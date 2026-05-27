# EVM Bytecode Security Analyzer 🔍

A static security analysis tool that detects vulnerabilities in deployed Ethereum smart contracts — **directly from bytecode**, even when the Solidity source code is unavailable.

> Built as part of a personal research project in smart contract security and EVM internals.

---

## Why Bytecode Analysis?

Most existing tools (Slither, MythX) analyze **Solidity source code**.  
This tool goes deeper — it analyzes the **compiled EVM bytecode** of deployed contracts.

This means:
- Works on **any deployed contract**, even unverified ones
- Catches vulnerabilities that only appear at the opcode level
- Mirrors the approach used by professional security auditors

---

## Features

| Feature | Description |
|---|---|
| **Bytecode Fetching** | Pulls deployed bytecode directly from Etherscan API |
| **Opcode Decoding** | Full EVM opcode set — decodes every instruction |
| **CFG Construction** | Builds a Control Flow Graph using basic block analysis |
| **Vulnerability Detection** | Pattern matching on opcodes and block structure |
| **HTML Report** | Clean, professional audit report with severity ratings |

### Detected Vulnerabilities

- 🔴 **Reentrancy** — CALL before SSTORE (The DAO pattern)
- 🔴 **DELEGATECALL Risk** — Unsafe external code execution
- 🔴 **SELFDESTRUCT** — Unprotected contract destruction
- 🟡 **Unchecked External Calls** — Silent failures
- 🟡 **Timestamp Dependence** — Miner-manipulable logic

---

## Installation

```bash
git clone https://github.com/yourusername/evm-analyzer
cd evm-analyzer
pip install -r requirements.txt
cp .env.example .env
# Add your Etherscan API key to .env
```

---

## Usage

```bash
python main.py <contract_address>
```

**Example — Analyzing USDT (Tether):**
```bash
python main.py 0xdAC17F958D2ee523a2206206994597C13D831ec7
```

Output:
- ✅ Colored console summary
- 📄 `report_0xdAC17F9.html` — full audit report

---

## Architecture

```
evm-analyzer/
├── fetcher/
│   └── etherscan.py          # Bytecode + metadata from Etherscan API
├── decoder/
│   └── opcode_decoder.py     # Hex → Instruction list (full EVM opcode table)
├── analyzer/
│   ├── cfg_builder.py        # Basic block analysis → Control Flow Graph
│   └── vulnerability_patterns.py  # Security checks on the CFG
├── reporter/
│   └── html_report.py        # Self-contained HTML audit report
└── main.py                   # CLI entry point
```

---

## How It Works

```
Contract Address
      │
      ▼
Etherscan API  ──→  Raw Bytecode (hex)
      │
      ▼
Opcode Decoder  ──→  [PUSH1 0x80, MSTORE, JUMPDEST, CALL, ...]
      │
      ▼
CFG Builder  ──→  Graph of basic blocks + edges
      │
      ▼
Vulnerability Patterns  ──→  Findings (severity, description, fix)
      │
      ▼
HTML Report  ──→  report.html
```

---

## Example Report

The generated report includes:
- Risk level (CLEAN / LOW / MEDIUM / HIGH / CRITICAL)
- Per-finding: severity badge, description, affected opcodes, recommendation
- CFG statistics (blocks, edges, unreachable blocks)
- Contract metadata (name, compiler, verification status)

---

## Tech Stack

- **Python** — Core analysis engine
- **NetworkX** — Control Flow Graph construction and analysis
- **Requests** — Etherscan API integration
- **Rich** — Terminal output formatting
- **Jinja2** — HTML report templating
- **Graph Theory** — Basic block decomposition, CFG traversal

---

## Roadmap

- [ ] Symbolic execution for deeper vulnerability detection
- [ ] Integer overflow/underflow detection
- [ ] Access control analysis (onlyOwner patterns)
- [ ] Batch analysis of multiple contracts
- [ ] Export to JSON for CI/CD integration

---

## References

- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) — EVM specification
- [EVM Opcodes Reference](https://www.evm.codes/)
- [The DAO Hack Analysis](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/)
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)

---

*This tool performs automated static analysis. It does not replace a full manual security audit.*
