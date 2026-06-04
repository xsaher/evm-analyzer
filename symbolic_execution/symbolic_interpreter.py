from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .symbolic_value import (
    SymbolicValue, ValueKind, TaintSource,
    concrete, symbolic, expression,
    ZERO, ONE, UNKNOWN, WORD_MASK,
)
from .symbolic_stack  import SymbolicStack
from .path_state      import PathState
from .symbolic_finding import SymbolicFinding


TAINT_SOURCE_MAP: dict[str, TaintSource] = {
    "CALLDATALOAD":  TaintSource.CALLDATALOAD,
    "CALLDATASIZE":  TaintSource.CALLDATASIZE,
    "CALLER":        TaintSource.CALLER,
    "CALLVALUE":     TaintSource.CALLVALUE,
    "ORIGIN":        TaintSource.ORIGIN,
    "RETURNDATASIZE": TaintSource.RETURNDATASIZE,
}

BINARY_ARITH = {"ADD", "MUL", "SUB", "DIV", "MOD", "EXP",
                "SDIV", "SMOD", "AND", "OR", "XOR",
                "SHL", "SHR", "SAR", "SIGNEXTEND"}

BINARY_COMPARE = {"LT", "GT", "SLT", "SGT", "EQ"}

UNARY_OPS = {"ISZERO", "NOT"}


@dataclass
class SymbolicInterpreter:
    block_offset: int  = 0
    stack:        SymbolicStack = field(default_factory=SymbolicStack)
    path:         PathState     = field(default_factory=PathState)
    findings:     list[SymbolicFinding] = field(default_factory=list)

    def copy(self) -> SymbolicInterpreter:
        return SymbolicInterpreter(
            block_offset = self.block_offset,
            stack        = self.stack.copy(),
            path         = self.path,
            findings     = list(self.findings),
        )

    def execute(self, instruction) -> None:
        op      = instruction.name
        operand = getattr(instruction, "operand", None)
        operand = int(operand, 16) if isinstance(operand, str) else operand
        self.block_offset = getattr(instruction, "offset", self.block_offset)

        if   op.startswith("PUSH"):   self._push(operand)
        elif op.startswith("DUP"):    self._dup(int(op[3:]))
        elif op.startswith("SWAP"):   self._swap(int(op[4:]))
        elif op in TAINT_SOURCE_MAP:  self._taint_source(op)
        elif op in BINARY_ARITH:      self._binary_arith(op)
        elif op in BINARY_COMPARE:    self._binary_compare(op)
        elif op in UNARY_OPS:         self._unary(op)
        elif op == "POP":             self.stack.pop()
        elif op == "MLOAD":           self._mload()
        elif op == "MSTORE":          self._mstore()
        elif op == "SLOAD":           self._sload()
        elif op == "SSTORE":          self._sstore()
        elif op == "CALL":            self._call()
        elif op == "DELEGATECALL":    self._delegatecall()
        elif op == "STATICCALL":      self._staticcall()
        elif op == "JUMPI":           self._jumpi()
        elif op == "JUMP":            self.stack.pop()
        elif op == "SELFDESTRUCT":    self._selfdestruct()
        elif op == "RETURN":          self._consume(2)
        elif op == "REVERT":          self._consume(2)
        elif op == "SHA3":            self._sha3()
        elif op in ("STOP", "INVALID"): pass
        else:                         self._unknown_op(op)

    def execute_block(self, instructions: list) -> None:
        for instr in instructions:
            self.execute(instr)

    def _push(self, value: Optional[int]) -> None:
        self.stack.push(concrete(value) if value is not None else UNKNOWN)

    def _dup(self, position: int) -> None:
        self.stack.dup(position)

    def _swap(self, position: int) -> None:
        self.stack.swap(position)

    def _taint_source(self, op: str) -> None:
        self.stack.push(symbolic(TAINT_SOURCE_MAP[op]))

    def _binary_arith(self, op: str) -> None:
        a = self.stack.pop()
        b = self.stack.pop()

        if a.kind == ValueKind.CONCRETE and b.kind == ValueKind.CONCRETE:
            result = self._eval_concrete(op, a.concrete, b.concrete)
            self.stack.push(concrete(result))
        elif a.is_tainted() or b.is_tainted():
            self.stack.push(expression(op, a, b))
        else:
            self.stack.push(expression(op, a, b))

    def _binary_compare(self, op: str) -> None:
        a = self.stack.pop()
        b = self.stack.pop()

        if a.kind == ValueKind.CONCRETE and b.kind == ValueKind.CONCRETE:
            result = self._eval_compare(op, a.concrete, b.concrete)
            self.stack.push(concrete(result))
        else:
            self.stack.push(expression(op, a, b))

    def _unary(self, op: str) -> None:
        a = self.stack.pop()

        if a.kind == ValueKind.CONCRETE:
            if op == "ISZERO":
                self.stack.push(concrete(1 if a.concrete == 0 else 0))
            else:
                self.stack.push(concrete((~a.concrete) & WORD_MASK))
        else:
            self.stack.push(expression(op, a))

    def _mload(self) -> None:
        self.stack.pop()
        self.stack.push(UNKNOWN)

    def _mstore(self) -> None:
        self._consume(2)

    def _sload(self) -> None:
        slot = self.stack.pop()
        self.stack.push(expression("SLOAD", slot))

    def _sstore(self) -> None:
        slot  = self.stack.pop()
        value = self.stack.pop()

        if value.is_tainted():
            self._report(
                vuln_type   = "user_controlled_storage_write",
                severity    = "HIGH",
                title       = "User-controlled storage write",
                description = (
                    "An attacker-influenced value flows directly into SSTORE. "
                    "Depending on the slot, this can corrupt balances, ownership, "
                    "or any other critical state variable."
                ),
                taint_source = value.taint_origin(),
            )

    def _call(self) -> None:
        _gas  = self.stack.pop()
        addr  = self.stack.pop()
        value = self.stack.pop()
        self._consume(4)

        if addr.is_tainted():
            self._report(
                vuln_type   = "user_controlled_call_target",
                severity    = "CRITICAL",
                title       = "User-controlled external call target",
                description = (
                    "The destination address of a CALL is derived from user input. "
                    "An attacker can redirect execution to an arbitrary contract."
                ),
                taint_source = addr.taint_origin(),
            )

        if value.is_tainted():
            self._report(
                vuln_type   = "user_controlled_eth_transfer",
                severity    = "HIGH",
                title       = "User-controlled ETH transfer amount",
                description = (
                    "The ETH value forwarded in a CALL is attacker-influenced. "
                    "This can be exploited to drain contract funds."
                ),
                taint_source = value.taint_origin(),
            )

        self.stack.push(concrete(1))

    def _delegatecall(self) -> None:
        _gas = self.stack.pop()
        addr = self.stack.pop()
        self._consume(4)

        if addr.is_tainted():
            self._report(
                vuln_type   = "user_controlled_delegatecall_target",
                severity    = "CRITICAL",
                title       = "User-controlled DELEGATECALL target",
                description = (
                    "The callee of DELEGATECALL is attacker-controlled. "
                    "Execution runs in the calling contract's storage context, "
                    "enabling complete state takeover."
                ),
                taint_source = addr.taint_origin(),
            )

        self.stack.push(concrete(1))

    def _staticcall(self) -> None:
        _gas = self.stack.pop()
        addr = self.stack.pop()
        self._consume(4)
        self.stack.push(concrete(1))

    def _selfdestruct(self) -> None:
        beneficiary = self.stack.pop()

        if beneficiary.is_tainted():
            self._report(
                vuln_type   = "user_controlled_selfdestruct_beneficiary",
                severity    = "HIGH",
                title       = "User-controlled SELFDESTRUCT beneficiary",
                description = (
                    "The ETH recipient of SELFDESTRUCT is derived from user input. "
                    "An attacker can drain all contract funds to an arbitrary address."
                ),
                taint_source = beneficiary.taint_origin(),
            )

    def _jumpi(self) -> None:
        dest      = self.stack.pop()
        condition = self.stack.pop()
        self.path = self.path.branch(condition, taken=True)

    def _sha3(self) -> None:
        offset = self.stack.pop()
        length = self.stack.pop()
        if offset.is_tainted() or length.is_tainted():
            self.stack.push(expression("SHA3", offset, length))
        else:
            self.stack.push(UNKNOWN)

    def _consume(self, n: int) -> None:
        for _ in range(n):
            self.stack.pop()

    def _unknown_op(self, op: str) -> None:
        self.stack.push(UNKNOWN)

    def _report(
        self,
        vuln_type:   str,
        severity:    str,
        title:       str,
        description: str,
        taint_source: Optional[TaintSource],
    ) -> None:
        finding = SymbolicFinding(
            vuln_type    = vuln_type,
            severity     = severity,
            title        = title,
            description  = description,
            block_offset = self.block_offset,
            taint_source = taint_source or TaintSource.UNKNOWN,
            path_summary = self.path.summary(),
            confirmed    = True,
        )
        self.findings.append(finding)

    @staticmethod
    def _eval_concrete(op: str, a: int, b: int) -> int:
        M = WORD_MASK
        match op:
            case "ADD":        return (a + b) & M
            case "MUL":        return (a * b) & M
            case "SUB":        return (a - b) & M
            case "DIV":        return (a // b) & M if b else 0
            case "MOD":        return (a % b)  & M if b else 0
            case "EXP":        return pow(a, b, M + 1)
            case "AND":        return a & b
            case "OR":         return a | b
            case "XOR":        return a ^ b
            case "SHL":        return (a << b) & M if b < 256 else 0
            case "SHR":        return (a >> b) if b < 256 else 0
            case _:            return 0

    @staticmethod
    def _eval_compare(op: str, a: int, b: int) -> int:
        match op:
            case "LT":  return int(a < b)
            case "GT":  return int(a > b)
            case "EQ":  return int(a == b)
            case _:     return 0