from dataclasses import dataclass


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


def push1(value: int) -> str:
    return f"{PUSH1}{value:02x}"


def push2(value: int) -> str:
    return f"{PUSH2}{value:04x}"


def build(*parts: str) -> str:
    return "0x" + "".join(parts)
