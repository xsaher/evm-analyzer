"""
decoder/opcode_decoder.py
--------------------------
Converts raw EVM bytecode (hex) into a readable list of instructions.
This is the foundation — every other module depends on this output.
"""

from dataclasses import dataclass

# Full EVM opcode table: opcode -> (name, number_of_immediate_bytes)
EVM_OPCODES: dict[int, tuple[str, int]] = {
    # Arithmetic
    0x00: ("STOP",        0), 0x01: ("ADD",         0), 0x02: ("MUL",     0),
    0x03: ("SUB",         0), 0x04: ("DIV",         0), 0x05: ("SDIV",    0),
    0x06: ("MOD",         0), 0x07: ("SMOD",        0), 0x08: ("ADDMOD",  0),
    0x09: ("MULMOD",      0), 0x0A: ("EXP",         0), 0x0B: ("SIGNEXTEND", 0),
    # Comparison & bitwise
    0x10: ("LT",          0), 0x11: ("GT",          0), 0x12: ("SLT",     0),
    0x13: ("SGT",         0), 0x14: ("EQ",          0), 0x15: ("ISZERO",  0),
    0x16: ("AND",         0), 0x17: ("OR",          0), 0x18: ("XOR",     0),
    0x19: ("NOT",         0), 0x1A: ("BYTE",        0), 0x1B: ("SHL",     0),
    0x1C: ("SHR",         0), 0x1D: ("SAR",         0),
    # Hash
    0x20: ("SHA3",        0),
    # Environment
    0x30: ("ADDRESS",     0), 0x31: ("BALANCE",     0), 0x32: ("ORIGIN",  0),
    0x33: ("CALLER",      0), 0x34: ("CALLVALUE",   0), 0x35: ("CALLDATALOAD", 0),
    0x36: ("CALLDATASIZE",0), 0x37: ("CALLDATACOPY",0), 0x38: ("CODESIZE",0),
    0x39: ("CODECOPY",    0), 0x3A: ("GASPRICE",    0), 0x3B: ("EXTCODESIZE", 0),
    0x3C: ("EXTCODECOPY", 0), 0x3D: ("RETURNDATASIZE",0),0x3E:("RETURNDATACOPY",0),
    0x3F: ("EXTCODEHASH", 0),
    # Block
    0x40: ("BLOCKHASH",   0), 0x41: ("COINBASE",    0), 0x42: ("TIMESTAMP",0),
    0x43: ("NUMBER",      0), 0x44: ("DIFFICULTY",  0), 0x45: ("GASLIMIT", 0),
    0x46: ("CHAINID",     0), 0x47: ("SELFBALANCE", 0), 0x48: ("BASEFEE", 0),
    # Stack, memory, storage
    0x50: ("POP",         0), 0x51: ("MLOAD",       0), 0x52: ("MSTORE",  0),
    0x53: ("MSTORE8",     0), 0x54: ("SLOAD",       0), 0x55: ("SSTORE",  0),
    0x56: ("JUMP",        0), 0x57: ("JUMPI",       0), 0x58: ("PC",      0),
    0x59: ("MSIZE",       0), 0x5A: ("GAS",         0), 0x5B: ("JUMPDEST",0),
    # PUSH (1-32 bytes of immediate data)
    **{0x60 + i: (f"PUSH{i+1}", i+1) for i in range(32)},
    # DUP (1-16)
    **{0x80 + i: (f"DUP{i+1}",  0) for i in range(16)},
    # SWAP (1-16)
    **{0x90 + i: (f"SWAP{i+1}", 0) for i in range(16)},
    # Logging
    **{0xA0 + i: (f"LOG{i}", 0) for i in range(5)},
    # System
    0xF0: ("CREATE",      0), 0xF1: ("CALL",        0), 0xF2: ("CALLCODE",   0),
    0xF3: ("RETURN",      0), 0xF4: ("DELEGATECALL",0), 0xF5: ("CREATE2",    0),
    0xFA: ("STATICCALL",  0), 0xFD: ("REVERT",      0), 0xFE: ("INVALID",    0),
    0xFF: ("SELFDESTRUCT",0),
}


@dataclass
class Instruction:
    """Represents a single decoded EVM instruction."""
    offset: int          # Byte position in the bytecode
    opcode: int          # Raw opcode byte (e.g. 0x56)
    name: str            # Human-readable name (e.g. "JUMP")
    operand: str | None  # Immediate data for PUSH instructions, None otherwise

    def __repr__(self):
        op = f" 0x{self.operand}" if self.operand else ""
        return f"[{self.offset:04x}] {self.name}{op}"


def decode(bytecode_hex: str) -> list[Instruction]:
    """
    Decode a hex bytecode string into a list of Instructions.

    Args:
        bytecode_hex: hex string, with or without '0x' prefix

    Returns:
        List of Instruction objects in execution order
    """
    # Strip 0x prefix if present
    hex_str = bytecode_hex.removeprefix("0x").strip()
    hex_str = ''.join(hex_str.split())
    raw_bytes = bytes.fromhex(hex_str)

    instructions = []
    i = 0

    while i < len(raw_bytes):
        opcode = raw_bytes[i]
        name, immediate_size = EVM_OPCODES.get(opcode, (f"UNKNOWN(0x{opcode:02x})", 0))

        operand = None
        if immediate_size > 0:
            operand_bytes = raw_bytes[i + 1 : i + 1 + immediate_size]
            operand = operand_bytes.hex()

        instructions.append(Instruction(
            offset=i,
            opcode=opcode,
            name=name,
            operand=operand,
        ))

        i += 1 + immediate_size

    return instructions


def instructions_to_text(instructions: list[Instruction]) -> str:
    """Pretty-print decoded instructions for debugging."""
    return "\n".join(repr(inst) for inst in instructions)
