from __future__ import annotations
from dataclasses import dataclass, field
from .symbolic_value import SymbolicValue


@dataclass
class PathConstraint:
    condition: SymbolicValue
    taken: bool

    def __repr__(self) -> str:
        polarity = "IF" if self.taken else "IF NOT"
        return f"{polarity} {self.condition!r}"


@dataclass
class PathState:
    constraints: list[PathConstraint] = field(default_factory=list)

    def branch(self, condition: SymbolicValue, taken: bool) -> PathState:
        new_constraints = list(self.constraints)
        new_constraints.append(PathConstraint(condition, taken))
        return PathState(new_constraints)

    def has_symbolic_branch(self) -> bool:
        from .symbolic_value import ValueKind
        return any(
            c.condition.kind != ValueKind.CONCRETE
            for c in self.constraints
        )

    def summary(self) -> list[str]:
        return [repr(c) for c in self.constraints]

    def __repr__(self) -> str:
        return f"PathState(branches={len(self.constraints)})"
