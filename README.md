# EVM Bytecode Security Analyzer

A static security analysis tool for Ethereum smart contracts. Works directly on deployed bytecode — no source code needed.

Built as a personal project to understand EVM internals and smart contract security.

---

## What makes this different

Most tools like Slither and MythX require Solidity source code. This tool analyzes the compiled EVM bytecode of any deployed contract, even unverified ones. It goes beyond simple pattern matching with three independent analysis layers that run together on every contract.

---

## Tested on Real Exploited Contracts

| Contract | Stolen | Tool Result | Key Finding |
|---|---|---|---|
| The DAO (2016) | $60M | CRITICAL | Reentrancy + Integer Overflow → Storage Corruption |
| Rubixi (2014) | $2M | CRITICAL | Reentrancy + Integer Overflow → Storage Corruption |
| Bancor (2018) | $23M | HIGH | SELFDESTRUCT + User-Controlled Storage Write |

The tool detected the exact vulnerabilities that were exploited in each attack.

---

## Detected Vulnerabilities

**Via Pattern Analysis:**
- Reentrancy (CALL before SSTORE)
- DELEGATECALL to untrusted address
- SELFDESTRUCT without access control
- tx.origin authentication
- Timestamp dependence
- Weak randomness
- Unchecked external call return value
- Integer overflow

**Via Taint Analysis (inter-block):**
- User-controlled storage write
- User-controlled call target
- User-controlled ETH transfer amount
- User-controlled DELEGATECALL target
- User-controlled SELFDESTRUCT beneficiary

**Via Symbolic Execution:**
- Confirmed user-controlled SSTORE with full value trace
- Confirmed user-controlled CALL target with taint origin
- Confirmed user-controlled ETH transfer amount
- Confirmed user-controlled DELEGATECALL target
- Confirmed user-controlled SELFDESTRUCT beneficiary

**Severity Escalation:**
- Integer overflow that flows into SSTORE → escalates to **CRITICAL**
- Integer overflow that flows into CALL value → escalates to **CRITICAL**

---

## Installation

```bash
git clone https://github.com/xsaher/evm-analyzer
cd evm-analyzer
pip install -r requirements.txt
cp .env.example .env
```

Add your free Etherscan API key to `.env`. Get one at etherscan.io/myapikey

---

## Usage

```bash
# Single contract
python main.py 0xdAC17F958D2ee523a2206206994597C13D831ec7

# Multiple contracts
python main.py 0xdAC17F958D2ee523a2206206994597C13D831ec7 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# Save reports to a specific folder
python main.py 0xdAC17F958D2ee523a2206206994597C13D831ec7 -o ./reports

# Check version
python main.py --version
```

Each analysis produces:
- Terminal summary with color-coded severity levels
- `report_<address>.html` — visual audit report
- `report_<address>.json` — structured output for integration

---

## Architecture

```
evm-analyzer/
├── fetcher/
│   └── etherscan.py              # Bytecode, ABI, metadata from Etherscan API
├── decoder/
│   └── opcode_decoder.py         # Raw hex → decoded instruction list
├── analyzer/
│   ├── cfg_builder.py            # Basic block decomposition → Control Flow Graph
│   ├── vulnerability_patterns.py # Pattern-based checks on the CFG
│   └── taint_analysis.py         # Inter-block taint propagation + severity escalation
├── symbolic_execution/
│   ├── symbolic_value.py         # Concrete and symbolic value types
│   ├── symbolic_stack.py         # EVM stack operating on symbolic values
│   ├── symbolic_interpreter.py   # Opcode-level symbolic execution engine
│   ├── symbolic_engine.py        # CFG traversal with worklist algorithm
│   ├── symbolic_finding.py       # Finding dataclass with severity escalation
│   └── path_state.py             # Path constraint tracking across branches
├── reporter/
│   ├── html_report.py            # Self-contained HTML report
│   └── json_report.py            # JSON output
└── main.py                       # CLI entry point
```

---

## How It Works

```
Contract Address
      │
      ▼
Etherscan API  →  Raw Bytecode
      │
      ▼
Opcode Decoder  →  Instruction list
      │
      ▼
CFG Builder  →  Basic blocks + edges
      │
      ├──→  Pattern Matching     →  Reentrancy, SELFDESTRUCT, tx.origin...
      │
      ├──→  Taint Analysis       →  Tracks user input across all blocks
      │                              Escalates severity when overflow hits a sink
      │
      └──→  Symbolic Execution   →  Runs every opcode with symbolic values
                                     Confirms taint reaches dangerous sinks
      │
      ▼
HTML + JSON Reports
```

### Symbolic Execution

The symbolic engine assigns a symbolic value to every user-controlled input — `CALLDATALOAD`, `CALLER`, `CALLVALUE`, and others. These values carry a taint origin tag that propagates through every arithmetic and logical operation across the entire CFG.

When a tainted value reaches a dangerous sink (`SSTORE`, `CALL`, `DELEGATECALL`, `SELFDESTRUCT`), the engine records a confirmed finding with the full taint origin. This eliminates false positives from pattern matching alone: a finding is only reported when the data flow is proven, not just suspected.

The engine uses a worklist algorithm to traverse the CFG and supports branching through `JUMPI` by recording path constraints at each conditional jump.

---

## Tech Stack

- Python 3.9+
- NetworkX — CFG construction and traversal
- pycryptodome — keccak256 for function selector resolution
- Requests — Etherscan API
- Rich — terminal output

---

## References

- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
- [EVM Opcodes Reference](https://www.evm.codes/)
- [The DAO Hack Analysis](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/)
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)

---

*This tool performs automated static analysis. It does not replace a full manual security audit.*