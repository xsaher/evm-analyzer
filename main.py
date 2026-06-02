import sys
import re
import os
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
 
from fetcher.etherscan import fetch_bytecode, fetch_source_info, fetch_function_signatures
from decoder.opcode_decoder import decode
from analyzer.cfg_builder import build_cfg, cfg_summary
from analyzer.vulnerability_patterns import run_all_checks_with_taint as run_all_checks
from reporter.html_report import generate_report as html_report
from reporter.json_report import generate_report as json_report
 
console = Console()
 
SEVERITY_STYLE = {
    "CRITICAL": "bold bright_red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "INFO":     "dim",
}
 
 
def is_valid_address(address: str) -> bool:
    return bool(re.match(r'^0x[0-9a-fA-F]{40}$', address))
 
 
def analyze(contract_address: str, output_dir: str = "."):
    if not is_valid_address(contract_address):
        console.print(f"[red]✗ Invalid address: {contract_address}[/red]")
        console.print("[dim]Address must be 42 characters starting with 0x, e.g. 0xdAC17F958D2ee523a2206206994597C13D831ec7[/dim]")
        return None
 
    os.makedirs(output_dir, exist_ok=True)
 
    console.print(Panel.fit(
        f"[bold]EVM Bytecode Security Analyzer[/bold]\n"
        f"[dim]Analyzing: {contract_address}[/dim]",
        border_style="cyan"
    ))
 
    console.print("\n[cyan]→[/cyan] Fetching bytecode from Etherscan...")
    try:
        bytecode = fetch_bytecode(contract_address)
        contract_info = fetch_source_info(contract_address)
    except Exception as e:
        console.print(f"[red]✗ Failed to fetch: {e}[/red]")
        return None
 
    console.print(f"  [green]✓[/green] Bytecode fetched ({len(bytecode) // 2 - 1} bytes)")
    if contract_info.get("is_verified"):
        console.print(f"  [green]✓[/green] Source verified: {contract_info['contract_name']}")
    else:
        console.print("  [yellow]![/yellow] Source not verified — analyzing bytecode only")
 
    console.print("\n[cyan]→[/cyan] Resolving function signatures...")
    signatures = fetch_function_signatures(contract_address)
    if signatures:
        console.print(f"  [green]✓[/green] {len(signatures)} functions found")
        sig_table = Table(box=box.SIMPLE, show_header=True, header_style="dim")
        sig_table.add_column("Selector", style="cyan", width=12)
        sig_table.add_column("Function", width=50)
        for selector, sig in list(signatures.items())[:10]:
            sig_table.add_row(f"0x{selector}", sig)
        if len(signatures) > 10:
            sig_table.add_row("...", f"and {len(signatures) - 10} more")
        console.print(sig_table)
    else:
        console.print("  [yellow]![/yellow] No ABI available — contract not verified")
 
    console.print("\n[cyan]→[/cyan] Decoding opcodes...")
    instructions = decode(bytecode)
    console.print(f"  [green]✓[/green] {len(instructions)} instructions decoded")
 
    console.print("\n[cyan]→[/cyan] Building Control Flow Graph...")
    graph = build_cfg(instructions)
    stats = cfg_summary(graph)
    console.print(f"  [green]✓[/green] {stats['total_blocks']} basic blocks, {stats['total_edges']} edges")
    console.print(f"  [green]✓[/green] {stats['conditional_jumps']} conditional jumps detected")
 
    console.print("\n[cyan]→[/cyan] Running vulnerability checks...")
    findings = run_all_checks(graph)
    console.print(f"  [green]✓[/green] {len(findings)} findings detected")
 
    console.print()
    if findings:
        table = Table(title="Security Findings", box=box.ROUNDED, show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Title", width=35)
        table.add_column("Block", width=8)
        table.add_column("Locations", width=12)
 
        for i, f in enumerate(findings, 1):
            style = SEVERITY_STYLE.get(f.severity, "")
            table.add_row(
                str(i),
                f"[{style}]{f.severity}[/{style}]",
                f.title,
                f"0x{f.block_offset:04x}",
                str(len(f.locations)) + " blocks" if f.locations else "",
            )
        console.print(table)
    else:
        console.print(Panel(
            "[bold green]✓ No vulnerabilities detected[/bold green]\n"
            "[dim]Manual review still recommended before deployment[/dim]",
            border_style="green"
        ))
 
    base = os.path.join(output_dir, f"report_{contract_address[:8]}")
    console.print(f"\n[cyan]→[/cyan] Generating reports...")
    html_report(contract_address, findings, graph, contract_info, f"{base}.html", signatures)
    json_report(contract_address, findings, graph, contract_info, f"{base}.json", signatures)
    console.print(f"  [green]✓[/green] {base}.html")
    console.print(f"  [green]✓[/green] {base}.json")
    console.print()
 
    return {"address": contract_address, "findings": len(findings), "base": base}
 
 
def batch_analyze(addresses: list[str], output_dir: str = "."):
    results = []
 
    for i, address in enumerate(addresses, 1):
        console.rule(f"[dim]Contract {i}/{len(addresses)}")
        result = analyze(address, output_dir)
        if result:
            results.append(result)
 
    console.rule("[bold]Batch Summary")
    summary_table = Table(box=box.ROUNDED, show_header=True)
    summary_table.add_column("#", style="dim", width=4)
    summary_table.add_column("Address", width=45)
    summary_table.add_column("Findings", width=10)
    summary_table.add_column("HTML", width=26)
    summary_table.add_column("JSON", width=26)
 
    for i, r in enumerate(results, 1):
        color = "red" if r["findings"] > 0 else "green"
        summary_table.add_row(
            str(i),
            r["address"],
            f"[{color}]{r['findings']}[/{color}]",
            f"{r['base']}.html",
            f"{r['base']}.json",
        )
 
    console.print(summary_table)
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="evm-analyzer",
        description="Static security analyzer for Ethereum smart contracts"
    )
    parser.add_argument("addresses", nargs="+", help="Contract address(es) to analyze")
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        help="Directory to save reports (default: current directory)"
    )
 
    args = parser.parse_args()
 
    if len(args.addresses) == 1:
        analyze(args.addresses[0], args.output_dir)
    else:
        batch_analyze(args.addresses, args.output_dir)





























