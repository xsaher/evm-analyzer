from __future__ import annotations
from typing import Optional
from .symbolic_value import SymbolicValue, UNKNOWN

MAX_STACK_DEPTH = 1024


class StackUnderflowError(Exception):
    pass


class StackOverflowError(Exception):
    pass


class SymbolicStack:

    def __init__(self, initial: Optional[list[SymbolicValue]] = None):
        self._stack: list[SymbolicValue] = list(initial) if initial else []

    def push(self, value: SymbolicValue) -> None:
        if len(self._stack) >= MAX_STACK_DEPTH:
            raise StackOverflowError("EVM stack depth exceeded 1024")
        self._stack.append(value)

    def pop(self) -> SymbolicValue:
        if not self._stack:
            return UNKNOWN
        return self._stack.pop()

    def peek(self, depth: int = 0) -> SymbolicValue:
        idx = -(depth + 1)
        if abs(idx) > len(self._stack):
            return UNKNOWN
        return self._stack[idx]

    def dup(self, position: int) -> None:
        value = self.peek(position - 1)
        self.push(value)

    def swap(self, position: int) -> None:
        if len(self._stack) <= position:
            return
        top_idx  = -1
        swap_idx = -(position + 1)
        self._stack[top_idx], self._stack[swap_idx] = (
            self._stack[swap_idx],
            self._stack[top_idx],
        )

    def copy(self) -> SymbolicStack:
        return SymbolicStack(list(self._stack))

    def __len__(self) -> int:
        return len(self._stack)

    def __repr__(self) -> str:
        top = list(reversed(self._stack[-6:]))
        preview = ", ".join(repr(v) for v in top)
        return f"Stack(depth={len(self._stack)}, top=[{preview}])"
