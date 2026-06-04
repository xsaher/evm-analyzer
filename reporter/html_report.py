from analyzer.vulnerability_patterns import Finding
from analyzer.cfg_builder import cfg_summary
import networkx as nx
from datetime import datetime

SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#FDE8E8", "border": "#DC2626", "text": "#7F1D1D"},
    "HIGH":     {"bg": "#FEE2E2", "border": "#EF4444", "text": "#991B1B"},
    "MEDIUM":   {"bg": "#FEF3C7", "border": "#F59E0B", "text": "#92400E"},
    "LOW":      {"bg": "#DBEAFE", "border": "#3B82F6", "text": "#1E40AF"},
    "INFO":     {"bg": "#F3F4F6", "border": "#9CA3AF", "text": "#374151"},
}

RISK_COLORS = {
    "CRITICAL": "#DC2626",
    "HIGH": "#EF4444",
    "MEDIUM": "#F59E0B",
    "LOW": "#3B82F6",
    "CLEAN": "#10B981",
}


def generate_report(
    contract_address: str,
    findings: list[Finding],
    graph: nx.DiGraph,
    contract_info: dict,
    output_path: str = "report.html",
    signatures: dict = None,
) -> str:
    summary = cfg_summary(graph)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

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

    risk_color = RISK_COLORS.get(risk_level, "#10B981")
    source_verified = "✓ Yes" if contract_info.get("is_verified") else "✗ No (analyzed from bytecode only)"

    # build findings HTML
    findings_html = ""
    for idx, finding in enumerate(findings, 1):
        c = SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["INFO"])
        block_hex = "0x{:04x}".format(finding.block_offset)

        opcodes_html = " ".join(
            '<code style="background:#E5E7EB;padding:2px 6px;border-radius:4px;font-size:12px">' + op + '</code>'
            for op in finding.opcodes
        )

        locations_html = ""
        if finding.locations and len(finding.locations) > 1:
            locs = " ".join(
                '<code style="background:#F3F4F6;padding:2px 6px;border-radius:4px;font-size:11px">' + loc + '</code>'
                for loc in finding.locations
            )
            locations_html = (
                '<div style="margin-top:8px">'
                '<strong style="font-size:12px;color:#6B7280">ALL LOCATIONS (' + str(len(finding.locations)) + '): </strong>'
                + locs +
                '</div>'
            )

        findings_html += (
            '<div style="border:1px solid ' + c["border"] + ';border-radius:8px;margin-bottom:16px;overflow:hidden">'
            '<div style="background:' + c["bg"] + ';padding:12px 16px;display:flex;align-items:center;gap:10px">'
            '<span style="background:' + c["border"] + ';color:white;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600">' + finding.severity + '</span>'
            '<strong style="color:' + c["text"] + ';font-size:15px">#' + str(idx) + ' — ' + finding.title + '</strong>'
            '<span style="margin-left:auto;font-size:12px;color:#6B7280">Block offset: ' + block_hex + '</span>'
            '</div>'
            '<div style="padding:16px;background:white">'
            '<p style="margin:0 0 10px;color:#374151;line-height:1.6"><strong>What:</strong> ' + finding.description + '</p>'
            '<p style="margin:0 0 10px;color:#374151;line-height:1.6"><strong>Fix:</strong> ' + finding.recommendation + '</p>'
            '<div style="margin-top:8px"><strong style="font-size:12px;color:#6B7280">OPCODES INVOLVED: </strong>' + opcodes_html + '</div>'
            + locations_html +
            '</div></div>'
        )

    if not findings:
        findings_html = '<div style="background:#D1FAE5;border:1px solid #10B981;border-radius:8px;padding:20px;text-align:center;color:#065F46;font-size:16px">✓ No vulnerabilities detected by automated analysis.<br><small style="color:#047857">Manual review is still recommended before deployment.</small></div>'

    # build functions table
    functions_html = ""
    if signatures:
        rows = "".join(
            '<tr style="border-bottom:1px solid #F3F4F6">'
            '<td style="padding:6px 0;color:#60A5FA">0x' + sel + '</td>'
            '<td style="padding:6px 0">' + sig + '</td></tr>'
            for sel, sig in signatures.items()
        )
        functions_html = (
            '<div class="section">'
            '<h2>Functions (' + str(len(signatures)) + ' detected)</h2>'
            '<table style="width:100%;border-collapse:collapse;font-size:13px;font-family:monospace">'
            '<tr style="border-bottom:2px solid #E5E7EB">'
            '<th style="padding:8px 0;text-align:left;color:#6B7280;font-weight:500">Selector</th>'
            '<th style="padding:8px 0;text-align:left;color:#6B7280;font-weight:500">Signature</th>'
            '</tr>' + rows + '</table></div>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EVM Security Report — {contract_address[:10]}...</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #F9FAFB; color: #111827; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 32px 24px; }}
  .header {{ background: #111827; color: white; border-radius: 12px; padding: 28px 32px; margin-bottom: 24px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }}
  .stat-card {{ background: white; border: 1px solid #E5E7EB; border-radius: 8px; padding: 16px; text-align: center; }}
  .section {{ background: white; border: 1px solid #E5E7EB; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
  h2 {{ font-size: 18px; margin-bottom: 16px; color: #111827; }}
  code {{ font-family: 'SF Mono', monospace; }}
  .footer {{ text-align: center; color: #9CA3AF; font-size: 13px; padding-top: 16px; }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div style="display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:13px;color:#9CA3AF;margin-bottom:4px">EVM Bytecode Security Analyzer</div>
        <h1 style="font-size:22px;font-weight:600">Security Audit Report</h1>
        <div style="font-size:13px;color:#D1D5DB;margin-top:6px">
          Contract: <code style="color:#60A5FA">{contract_address}</code>
        </div>
      </div>
      <div style="text-align:right">
        <div style="font-size:13px;color:#9CA3AF">{now}</div>
        <div style="font-size:28px;font-weight:700;color:{risk_color};margin-top:4px">{risk_level}</div>
        <div style="font-size:12px;color:#9CA3AF">Risk Level</div>
      </div>
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat-card">
      <div style="font-size:28px;font-weight:700;color:#DC2626">{severity_counts['CRITICAL']}</div>
      <div style="font-size:13px;color:#6B7280;margin-top:4px">Critical</div>
    </div>
    <div class="stat-card">
      <div style="font-size:28px;font-weight:700;color:#EF4444">{severity_counts['HIGH']}</div>
      <div style="font-size:13px;color:#6B7280;margin-top:4px">High</div>
    </div>
    <div class="stat-card">
      <div style="font-size:28px;font-weight:700;color:#F59E0B">{severity_counts['MEDIUM']}</div>
      <div style="font-size:13px;color:#6B7280;margin-top:4px">Medium</div>
    </div>
    <div class="stat-card">
      <div style="font-size:28px;font-weight:700;color:#3B82F6">{severity_counts['LOW']}</div>
      <div style="font-size:13px;color:#6B7280;margin-top:4px">Low</div>
    </div>
    <div class="stat-card">
      <div style="font-size:28px;font-weight:700;color:#111827">{summary['total_blocks']}</div>
      <div style="font-size:13px;color:#6B7280;margin-top:4px">CFG Blocks</div>
    </div>
  </div>

  <div class="section">
    <h2>Contract Info</h2>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr style="border-bottom:1px solid #F3F4F6"><td style="padding:8px 0;color:#6B7280;width:200px">Contract Name</td><td style="font-weight:500">{contract_info.get('contract_name', 'Unknown')}</td></tr>
      <tr style="border-bottom:1px solid #F3F4F6"><td style="padding:8px 0;color:#6B7280">Compiler Version</td><td>{contract_info.get('compiler_version', 'Unknown')}</td></tr>
      <tr style="border-bottom:1px solid #F3F4F6"><td style="padding:8px 0;color:#6B7280">Source Verified</td><td>{source_verified}</td></tr>
      <tr style="border-bottom:1px solid #F3F4F6"><td style="padding:8px 0;color:#6B7280">CFG Blocks</td><td>{summary['total_blocks']}</td></tr>
      <tr style="border-bottom:1px solid #F3F4F6"><td style="padding:8px 0;color:#6B7280">Conditional Jumps</td><td>{summary['conditional_jumps']}</td></tr>
      <tr style="border-bottom:1px solid #F3F4F6"><td style="padding:8px 0;color:#6B7280">Unreachable Blocks</td><td>{summary['unreachable_blocks']}</td></tr>
      <tr><td style="padding:8px 0;color:#6B7280">Risk Score</td><td style="font-weight:600;color:{risk_color}">{risk_score}</td></tr>
    </table>
  </div>

  {functions_html}

  <div class="section">
    <h2>Findings ({len(findings)} total)</h2>
    {findings_html}
  </div>

  <div class="footer">
    Generated by EVM Bytecode Security Analyzer &nbsp;·&nbsp; Automated analysis only — manual review recommended
  </div>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html)

    return output_path