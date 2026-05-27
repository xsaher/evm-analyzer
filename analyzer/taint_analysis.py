from decoder.opcode_decoder import Instruction
from analyzer.vulnerability_patterns import Finding
import networkx as nx
 
 
TAINT_SOURCES = {
    "CALLER",
    "CALLVALUE",
    "CALLDATALOAD",
    "CALLDATASIZE",
    "ORIGIN",
}
 
OVERFLOW_OPS = {"ADD", "MUL", "SUB", "EXP"}
SINKS = {"SSTORE", "CALL", "DELEGATECALL", "SELFDESTRUCT"}
 
STACK_OPS = {
    "ADD": (2, 1), "SUB": (2, 1), "MUL": (2, 1), "DIV": (2, 1),
    "SDIV": (2, 1), "MOD": (2, 1), "SMOD": (2, 1), "EXP": (2, 1),
    "ADDMOD": (3, 1), "MULMOD": (3, 1), "SIGNEXTEND": (2, 1),
    "LT": (2, 1), "GT": (2, 1), "SLT": (2, 1), "SGT": (2, 1),
    "EQ": (2, 1), "ISZERO": (1, 1), "AND": (2, 1), "OR": (2, 1),
    "XOR": (2, 1), "NOT": (1, 1), "BYTE": (2, 1), "SHL": (2, 1),
    "SHR": (2, 1), "SAR": (2, 1), "SHA3": (2, 1),
    "BALANCE": (1, 1), "CALLDATACOPY": (3, 0), "CODECOPY": (3, 0),
    "EXTCODESIZE": (1, 1), "EXTCODECOPY": (4, 0), "RETURNDATASIZE": (0, 1),
    "RETURNDATACOPY": (3, 0), "EXTCODEHASH": (1, 1),
    "BLOCKHASH": (1, 1), "COINBASE": (0, 1), "TIMESTAMP": (0, 1),
    "NUMBER": (0, 1), "DIFFICULTY": (0, 1), "GASLIMIT": (0, 1),
    "CHAINID": (0, 1), "SELFBALANCE": (0, 1), "BASEFEE": (0, 1),
    "POP": (1, 0), "MLOAD": (1, 1), "MSTORE": (2, 0), "MSTORE8": (2, 0),
    "SLOAD": (1, 1), "SSTORE": (2, 0), "JUMP": (1, 0), "JUMPI": (2, 0),
    "MSIZE": (0, 1), "GAS": (0, 1), "ADDRESS": (0, 1), "GASPRICE": (0, 1),
    "CODESIZE": (0, 1), "PC": (0, 1),
    "CALL": (7, 1), "CALLCODE": (7, 1), "DELEGATECALL": (6, 1),
    "STATICCALL": (6, 1), "CREATE": (3, 1), "CREATE2": (4, 1),
    "RETURN": (2, 0), "REVERT": (2, 0), "SELFDESTRUCT": (1, 0),
    "LOG0": (2, 0), "LOG1": (3, 0), "LOG2": (4, 0), "LOG3": (5, 0), "LOG4": (6, 0),
}
 
 
def simulate_block(instructions: list[Instruction], initial_stack: list[bool] = None) -> list[bool]:
    stack = list(initial_stack) if initial_stack else []
 
    for inst in instructions:
        name = inst.name
 
        if name in TAINT_SOURCES:
            stack.append(True)
            continue
 
        if name.startswith("PUSH"):
            stack.append(False)
            continue
 
        if name.startswith("DUP"):
            n = int(name[3:])
            if len(stack) >= n:
                stack.append(stack[-n])
            continue
 
        if name.startswith("SWAP"):
            n = int(name[4:])
            if len(stack) > n:
                stack[-1], stack[-(n + 1)] = stack[-(n + 1)], stack[-1]
            continue
 
        if name == "JUMPDEST":
            continue
 
        if name in STACK_OPS:
            pop_count, push_count = STACK_OPS[name]
            popped = [stack.pop() for _ in range(min(pop_count, len(stack)))]
            tainted = any(popped)
            for _ in range(push_count):
                stack.append(tainted)
 
    return stack
 
 
def merge_stacks(stacks: list[list[bool]]) -> list[bool]:
    if not stacks:
        return []
    max_len = max(len(s) for s in stacks)
    merged = []
    for i in range(max_len):
        tainted = any(s[i] if i < len(s) else False for s in stacks)
        merged.append(tainted)
    return merged
 
 
def propagate_taint(graph: nx.DiGraph) -> dict[int, list[bool]]:
    output_states: dict[int, list[bool]] = {offset: [] for offset in graph.nodes()}
    visit_count: dict[int, int] = {offset: 0 for offset in graph.nodes()}
    worklist = list(graph.nodes())
 
    while worklist:
        offset = worklist.pop(0)
 
        if visit_count[offset] >= 10:
            continue
 
        visit_count[offset] += 1
        data = graph.nodes[offset]
        instructions = data.get("instructions", [])
 
        pred_outputs = [output_states[pred] for pred in graph.predecessors(offset)]
        input_stack = merge_stacks(pred_outputs)
        new_output = simulate_block(instructions, input_stack)
 
        if new_output != output_states[offset]:
            output_states[offset] = new_output
            for successor in graph.successors(offset):
                if successor not in worklist:
                    worklist.append(successor)
 
    return output_states
 
 
def has_bounds_check(instructions: list[Instruction], op_idx: int) -> bool:
    window = [inst.name for inst in instructions[max(0, op_idx - 5): op_idx + 6]]
    return any(n in {"LT", "GT", "SLT", "SGT", "ISZERO"} for n in window)
 
 
def check_block(instructions: list[Instruction], input_stack: list[bool], offset: int) -> list[Finding]:
    findings = []
    overflow_tainted = False
 
    for idx, inst in enumerate(instructions):
        name = inst.name
        pre_stack = simulate_block(instructions[:idx], list(input_stack))
 
        # track if an overflow-prone op produced a tainted result
        if name in OVERFLOW_OPS and len(pre_stack) >= 2:
            inputs_tainted = any(pre_stack[-2:])
            no_check = not has_bounds_check(instructions, idx)
            if inputs_tainted and no_check:
                overflow_tainted = True
 
        if name == "SSTORE":
            if len(pre_stack) >= 2 and any(pre_stack[-2:]):
                severity = "HIGH"
                title = "User-Controlled Storage Write"
                description = "SSTORE is called with a value or slot derived from user input. An attacker may be able to overwrite arbitrary storage slots."
 
                if overflow_tainted:
                    severity = "CRITICAL"
                    title = "Integer Overflow Leading to Storage Corruption"
                    description = "An unchecked arithmetic operation on user input flows directly into SSTORE. An attacker can cause an integer overflow to manipulate storage values, potentially stealing funds or taking ownership."
 
                findings.append(Finding(
                    severity=severity,
                    title=title,
                    description=description,
                    block_offset=offset,
                    recommendation="Validate and sanitize all user-supplied values before writing to storage. Use Solidity 0.8+ or SafeMath.",
                    opcodes=["SSTORE"],
                ))
                break
 
        elif name == "CALL":
            if len(pre_stack) >= 3:
                addr_tainted = len(pre_stack) >= 2 and pre_stack[-2]
                value_tainted = len(pre_stack) >= 3 and pre_stack[-3]
 
                if addr_tainted:
                    findings.append(Finding(
                        severity="HIGH",
                        title="User-Controlled Call Target",
                        description="The destination address of a CALL is derived from user input. An attacker can redirect ETH or execution to an arbitrary contract.",
                        block_offset=offset,
                        recommendation="Never use user-supplied addresses as call targets without strict validation.",
                        opcodes=["CALL"],
                    ))
                    break
 
                if value_tainted:
                    severity = "CRITICAL" if overflow_tainted else "MEDIUM"
                    title = "Integer Overflow Leading to ETH Theft" if overflow_tainted else "User-Controlled ETH Transfer Amount"
                    description = (
                        "An unchecked arithmetic overflow on user input flows into a CALL value. An attacker can wrap the value around to send more ETH than intended, draining the contract."
                        if overflow_tainted else
                        "The ETH value sent in a CALL is derived from user input. This may allow an attacker to drain the contract balance."
                    )
                    findings.append(Finding(
                        severity=severity,
                        title=title,
                        description=description,
                        block_offset=offset,
                        recommendation="Validate ETH amounts and use Solidity 0.8+ to prevent overflow.",
                        opcodes=["CALL"],
                    ))
                    break
 
        elif name == "DELEGATECALL":
            if len(pre_stack) >= 2 and pre_stack[-2]:
                findings.append(Finding(
                    severity="HIGH",
                    title="User-Controlled DELEGATECALL Target",
                    description="The target address of DELEGATECALL is derived from user input. An attacker can execute arbitrary code in this contract's storage context.",
                    block_offset=offset,
                    recommendation="DELEGATECALL targets must be hardcoded or set at deployment in an immutable variable.",
                    opcodes=["DELEGATECALL"],
                ))
                break
 
        elif name == "SELFDESTRUCT":
            if pre_stack and pre_stack[-1]:
                findings.append(Finding(
                    severity="HIGH",
                    title="User-Controlled SELFDESTRUCT Beneficiary",
                    description="The beneficiary address of SELFDESTRUCT is derived from user input. An attacker can destroy the contract and steal its ETH.",
                    block_offset=offset,
                    recommendation="Hardcode the beneficiary or restrict SELFDESTRUCT to the contract owner.",
                    opcodes=["SELFDESTRUCT"],
                ))
                break
 
    return findings
 
 
def run_taint_analysis(graph: nx.DiGraph) -> list[Finding]:
    output_states = propagate_taint(graph)
 
    findings = []
    seen = set()
 
    for offset in graph.nodes():
        data = graph.nodes[offset]
        instructions = data.get("instructions", [])
 
        pred_outputs = [output_states[pred] for pred in graph.predecessors(offset)]
        input_stack = merge_stacks(pred_outputs)
 
        for f in check_block(instructions, input_stack, offset):
            key = (f.title, f.block_offset)
            if key not in seen:
                seen.add(key)
                findings.append(f)
 
    return findings












































