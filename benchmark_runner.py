
import json
import time
import argparse
import os
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

from fetcher.etherscan import fetch_bytecode, fetch_source_info
from decoder.opcode_decoder import decode
from analyzer.cfg_builder import build_cfg
from analyzer.vulnerability_patterns import run_all_checks_with_taint as run_all_checks

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

CONTRACTS = [

    {
        "address": "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413",
        "name": "The DAO (2016)",
        "category": "exploited",
        "stolen_usd": 60_000_000,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "The original $60M reentrancy hack that split Ethereum",
    },
    {
        "address": "0xe82719202e5965Cf5D9B6673B7503a3b92DE20be",
        "name": "Rubixi (2014)",
        "category": "exploited",
        "stolen_usd": 2_000_000,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "Constructor name mismatch + reentrancy",
    },
    {
        "address": "0xA39105534BD08f96bE8fEBA0e0c9D8E9b4F7AfAa",
        "name": "SpankChain (2018)",
        "category": "exploited",
        "stolen_usd": 38_000,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "Payment channel reentrancy",
    },
    {
        "address": "0xbA2aE424d960c26247Dd6c32edC70B295c744C43",
        "name": "Fei Protocol Rari (2022)",
        "category": "exploited",
        "stolen_usd": 80_000_000,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "Cross-contract reentrancy via Compound fork",
    },

    {
        "address": "0xa74476443119A942dE498590Fe1f2454d7D4aC0d",
        "name": "Golem Token (overflow)",
        "category": "exploited",
        "stolen_usd": 0,
        "known_vulns": ["Possible Integer Overflow"],
        "notes": "ERC20 integer overflow in transfer",
    },
    {
        "address": "0xB3319f5D18Bc0D84dD1b4825Dcde5d5f7266d407",
        "name": "SMT / BEC Token (2018)",
        "category": "exploited",
        "stolen_usd": 900_000_000,
        "known_vulns": ["Possible Integer Overflow"],
        "notes": "batchTransfer overflow minted unlimited tokens",
    },
    {
        "address": "0xC5d105E63711398aF9bbff092d4B6769C82f793d",
        "name": "PoWH Coin (2018)",
        "category": "exploited",
        "stolen_usd": 800_000,
        "known_vulns": ["Possible Integer Overflow"],
        "notes": "Pyramid scheme with overflow in dividend tracking",
    },

    {
        "address": "0x9DA397b9e80755301a3b32173283a91C0ef6c87E",
        "name": "Bancor (2018)",
        "category": "exploited",
        "stolen_usd": 23_000_000,
        "known_vulns": ["SELFDESTRUCT Present"],
        "notes": "Unprotected SELFDESTRUCT allowed draining",
    },
    {
        "address": "0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4",
        "name": "Parity Multisig (2017)",
        "category": "exploited",
        "stolen_usd": 30_000_000,
        "known_vulns": ["DELEGATECALL to Potentially Untrusted Address"],
        "notes": "Unprotected initWallet via delegatecall",
    },
    {
        "address": "0x4a220E6096B25EADb88358cb44068A3248254675",
        "name": "0x Protocol v1",
        "category": "exploited",
        "stolen_usd": 0,
        "known_vulns": ["tx.origin Used for Authentication"],
        "notes": "tx.origin authentication bypass",
    },

    {
        "address": "0x1F573D6Fb3F13d689FF844B4cE37794d79a7FF1C",
        "name": "Bancor SmartToken",
        "category": "exploited",
        "stolen_usd": 0,
        "known_vulns": ["SELFDESTRUCT Present", "User-Controlled Storage Write"],
        "notes": "SmartToken with unprotected storage writes",
    },
    {
        "address": "0x3dFd23A6c5E8BbcFc9581d2E864a68feb6a076d3",
        "name": "Compound cToken (old)",
        "category": "exploited",
        "stolen_usd": 0,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "Early Compound with CEI pattern violation",
    },

    {
        "address": "0x5E7DA0a8F84E7e23f6f4EC92D4dE50A2eA8D7Ff5",
        "name": "PRNG Casino exploit",
        "category": "exploited",
        "stolen_usd": 400_000,
        "known_vulns": ["Weak Randomness Source"],
        "notes": "Block hash used as RNG in lottery",
    },

    {
        "address": "0xF1f4Ee610B2b491CA1B5e279EcB5392a9A44C590",
        "name": "GovernMental Ponzi",
        "category": "exploited",
        "stolen_usd": 1_100,
        "known_vulns": ["Timestamp Dependence"],
        "notes": "Ponzi used block.timestamp for payout timing",
    },

    {
        "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "name": "Uniswap V2 Router",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": ["Timestamp Dependence"],
        "notes": "Deadline parameter uses block.timestamp",
    },
    {
        "address": "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
        "name": "SushiSwap Router",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": ["Timestamp Dependence"],
        "notes": "Fork of Uniswap V2, same timestamp pattern",
    },
    {
        "address": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
        "name": "Uniswap V3 Router",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Modern router, expected to be clean",
    },
    {
        "address": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
        "name": "Uniswap V3 Router02",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Latest Uniswap router",
    },
    {
        "address": "0x1111111254EEB25477B68fb85Ed929f73A960582",
        "name": "1inch AggregationRouter V5",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Production DEX aggregator",
    },
    {
        "address": "0xDef1C0ded9bec7F1a1670819833240f027b25EfF",
        "name": "0x Exchange Proxy",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "0x protocol exchange proxy",
    },

    {
        "address": "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9",
        "name": "AAVE Token",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "AAVE governance token",
    },
    {
        "address": "0xc00e94Cb662C3520282E6f5717214004A7f26888",
        "name": "COMP Token",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Compound governance token",
    },
    {
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "name": "DAI Stablecoin",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "MakerDAO DAI",
    },
    {
        "address": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        "name": "WBTC Token",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Wrapped Bitcoin ERC20",
    },

    {
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "name": "USDT (Tether)",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": ["Possible Integer Overflow"],
        "notes": "Old Solidity 0.4 — integer overflow expected",
    },
    {
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "name": "USDC",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Circle USDC, well-audited",
    },
    {
        "address": "0x514910771AF9Ca656af840dff83E8264EcF986CA",
        "name": "LINK Token",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Chainlink ERC677 token",
    },
    {
        "address": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
        "name": "UNI Token",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Uniswap governance token",
    },
    {
        "address": "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2",
        "name": "MKR Token",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "MakerDAO governance token",
    },
    {
        "address": "0xD533a949740bb3306d119CC777fa900bA034cd52",
        "name": "CRV Token",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Curve DAO token",
    },

    {
        "address": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d",
        "name": "CryptoKitties (2017)",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": ["Timestamp Dependence"],
        "notes": "Uses block.timestamp for cat birth timing",
    },
    {
        "address": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
        "name": "BAYC NFT",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Bored Ape Yacht Club",
    },

    {
        "address": "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf",
        "name": "Polygon Bridge",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Polygon ERC20 bridge on mainnet",
    },
    {
        "address": "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1",
        "name": "Optimism Bridge",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Official Optimism L1 bridge",
    },

    {
        "address": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
        "name": "Chainlink ETH/USD Feed",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Chainlink price oracle",
    },
    {
        "address": "0x986b5E1e1755e3C2440e960477f25201B0a8bbD4",
        "name": "Uniswap V2 USDC/ETH Oracle",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": ["Weak Randomness Source"],
        "notes": "Uses block variables for TWAP",
    },

    {
        "address": "0x910Dfc18D6EA3D6a7124A6F8B5458F281060fA4c",
        "name": "King of Ether Throne",
        "category": "exploited",
        "stolen_usd": 200_000,
        "known_vulns": ["Unchecked Call Return Value"],
        "notes": "ETH sent to dethroned king via unchecked CALL",
    },
    {
        "address": "0x627306090abaB3A6e1400e9345bC60c78a8BEf57",
        "name": "CrowdSale vulnerable",
        "category": "exploited",
        "stolen_usd": 0,
        "known_vulns": ["Possible Integer Overflow"],
        "notes": "ICO crowdsale with overflow in token calculation",
    },

    {
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "name": "WETH9",
        "category": "token",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Wrapped Ether, extremely simple and safe",
    },
    {
        "address": "0x00000000219ab540356cBB839Cbe05303d7705Fa",
        "name": "ETH2 Deposit Contract",
        "category": "safe",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Ethereum 2.0 staking deposit, formally verified",
    },

    {
        "address": "0xA1d8d972560C2f8144AF871Db508F0B0B10a3fBf",
        "name": "Gnosis Safe Proxy",
        "category": "safe",
        "stolen_usd": 0,
        "known_vulns": ["DELEGATECALL to Potentially Untrusted Address"],
        "notes": "Proxy pattern — DELEGATECALL is intentional",
    },
    {
        "address": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E",
        "name": "Gnosis Safe L2",
        "category": "safe",
        "stolen_usd": 0,
        "known_vulns": ["DELEGATECALL to Potentially Untrusted Address"],
        "notes": "L2 version of Gnosis Safe",
    },

    {
        "address": "0x5f18C75AbDAe578b483E5F43f12a39cF75b973a9",
        "name": "Yearn USDC Vault",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Yearn v2 vault, multiple audits",
    },

    {
        "address": "0xdF1D6405e5a7D09F5e1D42b15Cf50B7b8e2F28B0",
        "name": "Lendf.Me (dForce, 2020)",
        "category": "exploited",
        "stolen_usd": 25_000_000,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "ERC777 reentrancy via transfer hook",
    },
    {
        "address": "0xd2CE719b5FE69F7Aa2f9b6E3E8Ffbc1c79e9fb6",
        "name": "Akropolis (2020)",
        "category": "exploited",
        "stolen_usd": 2_000_000,
        "known_vulns": ["Potential Reentrancy"],
        "notes": "Savings pool reentrancy via ERC777",
    },
    {
        "address": "0x9759A6Ac90977b93B58547b4A71c78317f391A28",
        "name": "MakerDAO MCD Vat",
        "category": "safe",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Core MakerDAO accounting module, formally verified",
    },
    {
        "address": "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
        "name": "SushiSwap Factory",
        "category": "defi",
        "stolen_usd": 0,
        "known_vulns": [],
        "notes": "Pair factory, minimal attack surface",
    },
]

@dataclass
class BenchmarkResult:
    address: str
    name: str
    category: str
    stolen_usd: int
    known_vulns: list
    notes: str

    status: str = "pending"
    error_msg: str = ""
    duration_sec: float = 0.0

    findings_titles: list = field(default_factory=list)
    findings_severities: list = field(default_factory=list)
    cfg_blocks: int = 0
    cfg_edges: int = 0
    bytecode_bytes: int = 0

    true_positives: list = field(default_factory=list)
    false_negatives: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)

def compute_metrics(results):
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for r in results:
        if r.status != "success":
            continue
        total_tp += len(r.true_positives)
        total_fp += len(r.false_positives)
        total_fn += len(r.false_negatives)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    successful = [r for r in results if r.status == "success"]
    errors     = [r for r in results if r.status == "error"]
    exploited  = [r for r in successful if r.category == "exploited"]
    safe       = [r for r in successful if r.category == "safe"]

    return {
        "total_contracts": len(results),
        "successful": len(successful),
        "errors": len(errors),
        "exploited_analyzed": len(exploited),
        "safe_analyzed": len(safe),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "detection_rate": round(total_tp / max(total_tp + total_fn, 1), 4),
    }

def analyze_contract(entry):
    result = BenchmarkResult(
        address=entry["address"],
        name=entry["name"],
        category=entry["category"],
        stolen_usd=entry["stolen_usd"],
        known_vulns=entry["known_vulns"],
        notes=entry["notes"],
    )

    start = time.time()
    try:
        bytecode = fetch_bytecode(entry["address"])
        result.bytecode_bytes = len(bytecode) // 2 - 1

        instructions = decode(bytecode)
        graph = build_cfg(instructions)
        result.cfg_blocks = graph.number_of_nodes()
        result.cfg_edges  = graph.number_of_edges()

        findings = run_all_checks(graph)
        result.findings_titles     = [f.title for f in findings]
        result.findings_severities = [f.severity for f in findings]

        detected_set = set(result.findings_titles)
        expected_set = set(result.known_vulns)

        result.true_positives  = list(expected_set & detected_set)
        result.false_negatives = list(expected_set - detected_set)

        if entry["category"] == "safe":
            critical_high = [
                t for t, s in zip(result.findings_titles, result.findings_severities)
                if s in ("CRITICAL", "HIGH") and t not in expected_set
            ]
            result.false_positives = critical_high
        else:
            result.false_positives = []

        result.status = "success"

    except Exception as e:
        result.status = "error"
        result.error_msg = str(e)[:120]

    result.duration_sec = round(time.time() - start, 2)
    return result

def print_summary(results, metrics):
    console.print()
    console.rule("[bold]Benchmark Summary")

    table = Table(box=box.ROUNDED, show_header=True, title=f"Results — {len(results)} contracts")
    table.add_column("#",        style="dim", width=4)
    table.add_column("Contract", width=28)
    table.add_column("Category", width=10)
    table.add_column("Status",   width=9)
    table.add_column("Findings", width=10)
    table.add_column("TP",       width=5)
    table.add_column("FN",       width=5)
    table.add_column("Time",     width=7)

    for i, r in enumerate(results, 1):
        if r.status == "success":
            status_str   = "[green]✓ OK[/green]"
            findings_str = str(len(r.findings_titles))
            tp_str = f"[green]{len(r.true_positives)}[/green]" if r.true_positives else "—"
            fn_str = f"[red]{len(r.false_negatives)}[/red]" if r.false_negatives else "[green]0[/green]"
        elif r.status == "error":
            status_str   = "[red]✗ ERR[/red]"
            findings_str = "—"
            tp_str = fn_str = "—"
        else:
            status_str   = "[yellow]SKIP[/yellow]"
            findings_str = fn_str = tp_str = "—"

        table.add_row(
            str(i), r.name[:27], r.category,
            status_str, findings_str, tp_str, fn_str,
            f"{r.duration_sec}s",
        )

    console.print(table)
    console.print()
    console.print(Panel(
        f"[bold]Contracts analyzed:[/bold]  {metrics['successful']} / {metrics['total_contracts']}\n"
        f"[bold]Errors:[/bold]              {metrics['errors']}\n"
        f"[bold]True Positives:[/bold]      {metrics['total_tp']}\n"
        f"[bold]False Negatives:[/bold]     {metrics['total_fn']}\n"
        f"[bold]False Positives:[/bold]     {metrics['total_fp']}\n"
        f"\n"
        f"[bold cyan]Precision:[/bold cyan]      {metrics['precision']:.1%}\n"
        f"[bold cyan]Recall:[/bold cyan]         {metrics['recall']:.1%}\n"
        f"[bold cyan]F1 Score:[/bold cyan]       {metrics['f1']:.1%}\n"
        f"[bold cyan]Detection Rate:[/bold cyan] {metrics['detection_rate']:.1%}",
        title="[bold]Metrics",
        border_style="cyan",
    ))

def save_results(results, metrics, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"benchmark_{timestamp}.json")

    report = {
        "meta": {
            "tool": "EVM Bytecode Security Analyzer — Benchmark",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_contracts": len(results),
        },
        "metrics": metrics,
        "results": [asdict(r) for r in results],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[green]✓[/green] Results saved to [cyan]{path}[/cyan]")
    return path

def main():
    parser = argparse.ArgumentParser(description="EVM Analyzer Benchmark Runner")
    parser.add_argument("--output",   "-o", default="benchmark_results", help="Output directory")
    parser.add_argument("--delay",    "-d", default=0.5, type=float,     help="Delay between requests (seconds)")
    parser.add_argument("--limit",    "-l", default=None, type=int,      help="Only run first N contracts")
    parser.add_argument("--category", "-c", default=None,                help="Filter: exploited/safe/defi/token")
    args = parser.parse_args()

    contracts = CONTRACTS
    if args.category:
        contracts = [c for c in contracts if c["category"] == args.category]
    if args.limit:
        contracts = contracts[:args.limit]

    console.print(Panel.fit(
        f"[bold]EVM Analyzer — Benchmark Runner[/bold]\n"
        f"[dim]Testing {len(contracts)} contracts · delay {args.delay}s between requests[/dim]",
        border_style="cyan",
    ))

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing contracts...", total=len(contracts))

        for i, entry in enumerate(contracts):
            progress.update(task, description=f"[cyan]{entry['name'][:35]}[/cyan]")
            result = analyze_contract(entry)
            results.append(result)

            if result.status == "error":
                console.print(f"  [red]✗[/red] {entry['name']}: {result.error_msg}")
            elif result.false_negatives:
                console.print(f"  [yellow]![/yellow] {entry['name']}: missed {result.false_negatives}")

            progress.advance(task)

            if i < len(contracts) - 1:
                time.sleep(args.delay)

    metrics = compute_metrics(results)
    print_summary(results, metrics)
    save_results(results, metrics, args.output)

if __name__ == "__main__":
    main()
