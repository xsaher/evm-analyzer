from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class ValueKind(Enum):
    CONCRETE   = auto()
    SYMBOLIC   = auto()
    EXPRESSION = auto()


class TaintSource(Enum):
    CALLDATALOAD = "CALLDATALOAD"
    CALLDATASIZE = "CALLDATASIZE"
    CALLER       = "CALLER"
    CALLVALUE    = "CALLVALUE"
    ORIGIN       = "ORIGIN"
    RETURNDATASIZE = "RETURNDATASIZE"
    UNKNOWN      = "UNKNOWN"


WORD_MASK = (1 << 256) - 1


@dataclass(frozen=True)
class SymbolicValue:
    kind: ValueKind
    concrete: Optional[int]       = None
    taint: Optional[TaintSource]  = None
    op: Optional[str]             = None
    operands: tuple               = field(default_factory=tuple)

    def is_tainted(self) -> bool:
        if self.taint is not None:
            return True
        return any(
            isinstance(o, SymbolicValue) and o.is_tainted()
            for o in self.operands
        )

    def taint_origin(self) -> Optional[TaintSource]:
        if self.taint is not None:
            return self.taint
        for o in self.operands:
            if isinstance(o, SymbolicValue):
                origin = o.taint_origin()
                if origin:
                    return origin
        return None

    def __repr__(self) -> str:
        if self.kind == ValueKind.CONCRETE:
            return f"0x{self.concrete:x}"
        if self.kind == ValueKind.SYMBOLIC:
            return f"SYM[{self.taint.value}]"
        parts = ", ".join(repr(o) for o in self.operands)
        return f"{self.op}({parts})"


def concrete(value: int) -> SymbolicValue:
    return SymbolicValue(
        kind=ValueKind.CONCRETE,
        concrete=value & WORD_MASK,
    )


def symbolic(source: TaintSource) -> SymbolicValue:
    return SymbolicValue(
        kind=ValueKind.SYMBOLIC,
        taint=source,
    )


def expression(op: str, *operands: SymbolicValue) -> SymbolicValue:
    return SymbolicValue(
        kind=ValueKind.EXPRESSION,
        op=op,
        operands=tuple(operands),
    )


ZERO    = concrete(0)
ONE     = concrete(1)
UNKNOWN = symbolic(TaintSource.UNKNOWN)
