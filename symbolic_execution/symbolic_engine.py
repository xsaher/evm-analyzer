from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from .symbolic_interpreter import SymbolicInterpreter
from .symbolic_finding      import SymbolicFinding
from .symbolic_value        import TaintSource


MAX_VISITS_PER_BLOCK = 3


@dataclass
class BlockState:
    interpreter: SymbolicInterpreter
    visits:      int = 0


class SymbolicEngine:

    def __init__(self, cfg: nx.DiGraph):
        self._cfg      = cfg
        self._findings: list[SymbolicFinding] = []

    def run(self) -> list[SymbolicFinding]:
        entry = self._find_entry()
        if entry is None:
            return []

        visited: dict[int, int] = {}
        worklist: deque[tuple[int, SymbolicInterpreter]] = deque()
        worklist.append((entry, SymbolicInterpreter()))

        while worklist:
            block_id, interp = worklist.popleft()

            visit_count = visited.get(block_id, 0)
            if visit_count >= MAX_VISITS_PER_BLOCK:
                continue
            visited[block_id] = visit_count + 1

            block_interp = interp.copy()
            block_interp.block_offset = block_id
            self._execute_block(block_id, block_interp)
            self._findings.extend(block_interp.findings)

            for successor in self._cfg.successors(block_id):
                worklist.append((successor, block_interp.copy()))

        return self._deduplicate(self._findings)

    def _find_entry(self) -> Optional[int]:
        roots = [n for n in self._cfg.nodes if self._cfg.in_degree(n) == 0]
        return min(roots) if roots else (min(self._cfg.nodes) if self._cfg.nodes else None)

    def _execute_block(self, block_id: int, interp: SymbolicInterpreter) -> None:
        block = self._cfg.nodes[block_id]
        instructions = block.get("instructions", [])
        interp.execute_block(instructions)

    @staticmethod
    def _deduplicate(findings: list[SymbolicFinding]) -> list[SymbolicFinding]:
        seen:   set[tuple]              = set()
        unique: list[SymbolicFinding]   = []

        for f in findings:
            key = (f.vuln_type, f.block_offset, f.taint_source)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        unique.sort(key=lambda f: f.severity_rank, reverse=True)
        return unique
