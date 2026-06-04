import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from decoder.opcode_decoder import decode
from analyzer.cfg_builder import build_cfg
from symbolic_execution import SymbolicEngine
from symbolic_execution.symbolic_value import (
    concrete, symbolic, expression,
    TaintSource, ValueKind,
)
from symbolic_execution.symbolic_stack import SymbolicStack
from symbolic_execution.symbolic_interpreter import SymbolicInterpreter
from tests.sample_bytecodes import (
    SYMBOLIC_TAINTED_SSTORE,
    SYMBOLIC_TAINTED_CALL_TARGET,
    SYMBOLIC_TAINTED_SELFDESTRUCT,
    SAFE_CONTRACT,
    REENTRANCY,
)


def run_engine(bytecode: str):
    instructions = decode(bytecode)
    graph = build_cfg(instructions)
    return SymbolicEngine(graph).run()


class TestSymbolicValue:
    def test_concrete_not_tainted(self):
        v = concrete(42)
        assert not v.is_tainted()
        assert v.taint_origin() is None

    def test_symbolic_is_tainted(self):
        v = symbolic(TaintSource.CALLDATALOAD)
        assert v.is_tainted()
        assert v.taint_origin() == TaintSource.CALLDATALOAD

    def test_expression_propagates_taint(self):
        a = symbolic(TaintSource.CALLER)
        b = concrete(100)
        result = expression("ADD", a, b)
        assert result.is_tainted()
        assert result.taint_origin() == TaintSource.CALLER

    def test_expression_no_taint_if_both_concrete(self):
        a = concrete(10)
        b = concrete(20)
        result = expression("ADD", a, b)
        assert not result.is_tainted()

    def test_concrete_repr(self):
        v = concrete(255)
        assert repr(v) == "0xff"

    def test_symbolic_repr(self):
        v = symbolic(TaintSource.CALLVALUE)
        assert "CALLVALUE" in repr(v)


class TestSymbolicStack:
    def test_push_pop(self):
        stack = SymbolicStack()
        stack.push(concrete(1))
        stack.push(concrete(2))
        assert stack.pop().concrete == 2
        assert stack.pop().concrete == 1

    def test_dup(self):
        stack = SymbolicStack()
        stack.push(concrete(42))
        stack.dup(1)
        assert len(stack) == 2
        assert stack.peek(0).concrete == 42
        assert stack.peek(1).concrete == 42

    def test_swap(self):
        stack = SymbolicStack()
        stack.push(concrete(1))
        stack.push(concrete(2))
        stack.swap(1)
        assert stack.peek(0).concrete == 1
        assert stack.peek(1).concrete == 2

    def test_underflow_returns_unknown(self):
        stack = SymbolicStack()
        result = stack.pop()
        assert result.kind == ValueKind.SYMBOLIC

    def test_peek_empty_returns_unknown(self):
        stack = SymbolicStack()
        result = stack.peek(5)
        assert result.kind == ValueKind.SYMBOLIC


class TestSymbolicInterpreter:
    def _instr(self, op, operand=None, offset=0):
        class I:
            pass
        i = I()
        i.name = op
        i.operand = f"{operand:02x}" if operand is not None else None
        i.offset = offset
        return i

    def test_push_concrete(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("PUSH1", 0x42))
        assert interp.stack.peek().concrete == 0x42

    def test_calldataload_is_tainted(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("CALLDATALOAD"))
        assert interp.stack.peek().is_tainted()
        assert interp.stack.peek().taint_origin() == TaintSource.CALLDATALOAD

    def test_add_concrete_values(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("PUSH1", 3))
        interp.execute(self._instr("PUSH1", 4))
        interp.execute(self._instr("ADD"))
        assert interp.stack.peek().concrete == 7

    def test_add_propagates_taint(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("CALLDATALOAD"))
        interp.execute(self._instr("PUSH1", 1))
        interp.execute(self._instr("ADD"))
        assert interp.stack.peek().is_tainted()

    def test_sstore_tainted_creates_finding(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("CALLDATALOAD"))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("SSTORE"))
        assert len(interp.findings) == 1
        assert interp.findings[0].vuln_type == "user_controlled_storage_write"

    def test_sstore_concrete_no_finding(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("PUSH1", 1))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("SSTORE"))
        assert interp.findings == []

    def test_call_tainted_target_creates_finding(self):
        interp = SymbolicInterpreter()
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("CALLDATALOAD"))
        interp.execute(self._instr("PUSH1", 0))
        interp.execute(self._instr("CALL"))
        call_findings = [f for f in interp.findings if f.vuln_type == "user_controlled_call_target"]
        assert len(call_findings) == 1


class TestSymbolicEngine:
    def test_tainted_sstore_detected(self):
        findings = run_engine(SYMBOLIC_TAINTED_SSTORE)
        types = [f.vuln_type for f in findings]
        assert "user_controlled_storage_write" in types

    def test_tainted_call_target_detected(self):
        findings = run_engine(SYMBOLIC_TAINTED_CALL_TARGET)
        types = [f.vuln_type for f in findings]
        assert "user_controlled_call_target" in types

    def test_tainted_selfdestruct_detected(self):
        findings = run_engine(SYMBOLIC_TAINTED_SELFDESTRUCT)
        types = [f.vuln_type for f in findings]
        assert "user_controlled_selfdestruct_beneficiary" in types

    def test_safe_contract_no_symbolic_findings(self):
        findings = run_engine(SAFE_CONTRACT)
        tainted = [f for f in findings if "user_controlled" in f.vuln_type]
        assert tainted == []

    def test_findings_sorted_by_severity(self):
        findings = run_engine(REENTRANCY)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [order.get(f.severity, 99) for f in findings]
        assert ranks == sorted(ranks)

    def test_no_duplicate_findings(self):
        findings = run_engine(SYMBOLIC_TAINTED_SSTORE)
        keys = [(f.vuln_type, f.block_offset) for f in findings]
        assert len(keys) == len(set(keys))
