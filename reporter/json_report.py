import json
from datetime import datetime, timezone
from analyzer.vulnerability_patterns import Finding
from analyzer.cfg_builder import cfg_summary
import networkx as nx


def generate_report(
    contract_address: str,
    findings: list[Finding],
    graph: nx.DiGraph,
    contract_info: dict,
    output_path: str,
    signatures: dict = None,
) -> str:
    stats = cfg_summary(graph)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        severity_counts[f.severity] += 1

    risk_score = (
        severity_counts["CRITICAL"] * 100 +
        severity_counts["HIGH"] * 30 +
        severity_counts["MEDIUM"] * 15 +
        severity_counts["LOW"] * 5
    )

    if severity_counts["CRITICAL"] >= 1:
        risk_level = "CRITICAL"
    elif severity_counts["HIGH"] >= 2:
        risk_level = "CRITICAL"
    elif severity_counts["HIGH"] >= 1:
        risk_level = "HIGH"
    elif severity_counts["MEDIUM"] >= 1:
        risk_level = "MEDIUM"
    elif severity_counts["LOW"] >= 1:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    report = {
        "meta": {
            "tool": "EVM Bytecode Security Analyzer",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analyzer_version": "1.0.0",
        },
        "contract": {
            "address": contract_address,
            "name": contract_info.get("contract_name", "Unknown"),
            "compiler": contract_info.get("compiler_version", "Unknown"),
            "verified": contract_info.get("is_verified", False),
        },
        "analysis": {
            "cfg_blocks": stats["total_blocks"],
            "cfg_edges": stats["total_edges"],
            "conditional_jumps": stats["conditional_jumps"],
            "unreachable_blocks": stats["unreachable_blocks"],
            "functions_detected": len(signatures) if signatures else 0,
        },
        "summary": {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "by_severity": severity_counts,
        },
        "functions": [
            {"selector": f"0x{sel}", "signature": sig}
            for sel, sig in (signatures or {}).items()
        ],
        "findings": [
            {
                "id": i,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "block_offset": f"0x{f.block_offset:04x}",
                "locations": f.locations,
                "opcodes": f.opcodes,
            }
            for i, f in enumerate(findings, 1)
        ],
    }

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return output_path