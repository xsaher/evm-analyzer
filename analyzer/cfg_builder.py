"""
analyzer/cfg_builder.py
------------------------
Builds a Control Flow Graph (CFG) from decoded instructions.

Each node in the graph = a "basic block" (sequence of instructions
with no jumps in the middle). Edges represent possible execution paths.
This is the same approach used by professional audit tools.
"""

import networkx as nx
from decoder.opcode_decoder import Instruction

# Opcodes that end a basic block (they change control flow)
BLOCK_ENDERS = {"JUMP", "JUMPI", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}


def build_cfg(instructions: list[Instruction]) -> nx.DiGraph:
    """
    Build a Control Flow Graph from a list of decoded instructions.

    Returns a directed graph where:
    - Nodes: basic block start offsets, with 'instructions' attribute
    - Edges: possible jumps between blocks
    """
    graph = nx.DiGraph()

    # --- Step 1: Find all basic block start points ---
    block_starts = {0}  # The contract always starts at offset 0

    for idx, inst in enumerate(instructions):
        # A JUMPDEST marks a valid jump target (new block start)
        if inst.name == "JUMPDEST":
            block_starts.add(inst.offset)
        # Instruction after a block-ending opcode starts a new block
        if inst.name in BLOCK_ENDERS and idx + 1 < len(instructions):
            block_starts.add(instructions[idx + 1].offset)

    block_starts = sorted(block_starts)

    # --- Step 2: Group instructions into basic blocks ---
    # O(1) lookup: offset -> index in instructions list
    offset_to_idx = {inst.offset: idx for idx, inst in enumerate(instructions)}
    block_starts_set = set(block_starts)

    def get_block_instructions(start_offset: int) -> list[Instruction]:
        """Collect all instructions belonging to this basic block."""
        block = []
        i = offset_to_idx.get(start_offset, -1)
        if i == -1:
            return block
        while i < len(instructions):
            inst = instructions[i]
            # Stop if we hit the next block's start (and it's not our first instruction)
            if inst.offset != start_offset and inst.offset in block_starts_set:
                break
            block.append(inst)
            if inst.name in BLOCK_ENDERS:
                break
            i += 1
        return block

    for start in block_starts:
        block_insts = get_block_instructions(start)
        if block_insts:
            graph.add_node(start, instructions=block_insts)

    # --- Step 3: Add edges between blocks ---
    block_starts_indexed = {start: idx for idx, start in enumerate(block_starts)}

    for start in block_starts:
        if start not in graph.nodes:
            continue
        block_insts = graph.nodes[start]["instructions"]
        if not block_insts:
            continue

        last_inst = block_insts[-1]
        idx = block_starts_indexed[start]

        if last_inst.name == "JUMP":
            # Unconditional jump — target is determined at runtime
            # We mark it as "dynamic" since we can't statically resolve all targets
            graph.nodes[start]["jump_type"] = "unconditional"

        elif last_inst.name == "JUMPI":
            # Conditional jump — two possible paths:
            # 1. Jump taken (target = JUMPDEST somewhere)
            # 2. Fall through to next instruction
            graph.nodes[start]["jump_type"] = "conditional"
            # Add fall-through edge to the next block
            if idx + 1 < len(block_starts):
                next_start = block_starts[idx + 1]
                graph.add_edge(start, next_start, edge_type="fall_through")

        elif last_inst.name not in {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}:
            # Normal fall-through — goes to next block sequentially
            if idx + 1 < len(block_starts):
                next_start = block_starts[idx + 1]
                graph.add_edge(start, next_start, edge_type="sequential")

    return graph


def cfg_summary(graph: nx.DiGraph) -> dict:
    """Return quick stats about the CFG."""
    return {
        "total_blocks": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "conditional_jumps": sum(
            1 for _, data in graph.nodes(data=True)
            if data.get("jump_type") == "conditional"
        ),
        "unreachable_blocks": len([
            n for n in graph.nodes
            if n != 0 and graph.in_degree(n) == 0
        ]),
    }