import sys
import os
 
STOP         = "00"
ADD          = "01"
MUL          = "02"
LT           = "10"
GT           = "11"
EQ           = "14"
ISZERO       = "15"
SHA3         = "20"
ORIGIN       = "32"
CALLER       = "33"
CALLVALUE    = "34"
CALLDATALOAD = "35"
TIMESTAMP    = "42"
NUMBER       = "43"
DIFFICULTY   = "44"
BLOCKHASH    = "40"
COINBASE     = "41"
POP          = "50"
MLOAD        = "51"
MSTORE       = "52"
SLOAD        = "54"
SSTORE       = "55"
JUMP         = "56"
JUMPI        = "57"
JUMPDEST     = "5b"
PUSH1        = "60"
PUSH2        = "61"
PUSH20       = "73"
DUP1         = "80"
DUP2         = "81"
SWAP1        = "90"
LOG0         = "a0"
CALL         = "f1"
DELEGATECALL = "f4"
STATICCALL   = "fa"
RETURN       = "f3"
REVERT       = "fd"
SELFDESTRUCT = "ff"
 
 
def push1(value):
    return f"{PUSH1}{value:02x}"
 
def push2(value):
    return f"{PUSH2}{value:04x}"
 
def build(*parts):
    return "0x" + "".join(parts)
 
 
REENTRANCY = build(
    push1(0), push1(0), push1(0), push1(0),
    push1(0), push1(0x10), push1(0),
    CALL, POP,
    push1(0), push1(0),
    SSTORE, STOP,
)
 
UNCHECKED_CALL = build(
    push1(0), push1(0), push1(0), push1(0),
    push1(0), push1(0x10), push1(0),
    CALL, POP, STOP,
)
 
TIMESTAMP_DEPENDENCE = build(
    TIMESTAMP, push1(100), LT, push1(0x10), JUMPI, STOP, JUMPDEST, STOP,
)
 
DELEGATECALL_UNTRUSTED = build(
    push1(0), push1(0), push1(0), push1(0),
    push1(0x20), push1(0),
    DELEGATECALL, POP, STOP,
)
 
SELFDESTRUCT_UNPROTECTED = build(
    push1(0x10), SELFDESTRUCT, STOP,
)
 
TX_ORIGIN_AUTH = build(
    ORIGIN, push1(0x10), EQ, push1(0x0e), JUMPI, REVERT, JUMPDEST, STOP,
)
 
WEAK_RANDOMNESS = build(
    BLOCKHASH, push1(0), MSTORE,
    push1(32), push1(0), SHA3,
    push1(0), SSTORE, STOP,
)
 
INTEGER_OVERFLOW = build(
    CALLDATALOAD, push1(0xff), ADD, push1(0), SSTORE, STOP,
)
 
UNPROTECTED_WITHDRAWAL = build(
    CALLVALUE, push1(0), MSTORE,
    push1(0), push1(0), push1(0), push1(0),
    push1(0), push1(0x20), push1(0),
    CALL, POP, STOP,
)
 
SAFE_CONTRACT = build(
    CALLER, push1(0x10), EQ, push1(0x10), JUMPI, REVERT,
    JUMPDEST, push1(1), push1(0), SSTORE, STOP,
)
 
SYMBOLIC_TAINTED_SSTORE = build(
    CALLDATALOAD, push1(0), SSTORE, STOP,
)
 
SYMBOLIC_TAINTED_CALL_TARGET = build(
    push1(0), push1(0), push1(0), push1(0),
    push1(0), CALLDATALOAD, push1(0),
    CALL, POP, STOP,
)
 
SYMBOLIC_TAINTED_SELFDESTRUCT = build(
    CALLDATALOAD, SELFDESTRUCT, STOP,
)
 
