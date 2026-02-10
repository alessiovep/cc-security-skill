#!/usr/bin/env python3
"""
Generate formatted HTML security audit reports from JSON scan results.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {scan_date}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header .meta {{
            opacity: 0.9;
            font-size: 0.95em;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}

        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .summary-card.critical {{
            border-left: 4px solid #d32f2f;
        }}

        .summary-card.critical .number {{
            color: #d32f2f;
        }}

        .summary-card.high {{
            border-left: 4px solid #f57c00;
        }}

        .summary-card.high .number {{
            color: #f57c00;
        }}

        .summary-card.medium {{
            border-left: 4px solid #fbc02d;
        }}

        .summary-card.medium .number {{
            color: #fbc02d;
        }}

        .summary-card.low {{
            border-left: 4px solid #388e3c;
        }}

        .summary-card.low .number {{
            color: #388e3c;
        }}

        .summary-card.total {{
            border-left: 4px solid #667eea;
            background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
        }}

        .summary-card.total .number {{
            color: #667eea;
        }}

        .section {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }}

        .vulnerability {{
            border-left: 3px solid #e0e0e0;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
            border-radius: 5px;
        }}

        .vulnerability.critical {{
            border-left-color: #d32f2f;
            background: #ffebee;
        }}

        .vulnerability.high {{
            border-left-color: #f57c00;
            background: #fff3e0;
        }}

        .vulnerability.medium {{
            border-left-color: #fbc02d;
            background: #fffde7;
        }}

        .vulnerability.low {{
            border-left-color: #388e3c;
            background: #f1f8e9;
        }}

        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .vuln-title {{
            font-weight: bold;
            color: #333;
        }}

        .vuln-badges {{
            display: flex;
            gap: 8px;
        }}

        .badge {{
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge.severity-critical {{
            background: #d32f2f;
            color: white;
        }}

        .badge.severity-high {{
            background: #f57c00;
            color: white;
        }}

        .badge.severity-medium {{
            background: #fbc02d;
            color: #333;
        }}

        .badge.severity-low {{
            background: #388e3c;
            color: white;
        }}

        .badge.tool {{
            background: #667eea;
            color: white;
        }}

        .vuln-details {{
            color: #666;
            font-size: 0.9em;
            margin-top: 8px;
        }}

        .vuln-location {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.85em;
        }}

        .owasp-category {{
            color: #764ba2;
            font-weight: 500;
            margin-top: 5px;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}

        @media (max-width: 768px) {{
            .summary {{
                grid-template-columns: 1fr;
            }}

            .vuln-header {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .vuln-badges {{
                margin-top: 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Audit Report</h1>
            <div class="meta">
                <div>Target: <strong>{target}</strong></div>
                <div>Scan Date: <strong>{scan_date}</strong></div>
                <div>Generated: <strong>{generation_time}</strong></div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card total">
                <div class="number">{total}</div>
                <div class="label">Total Issues</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{high}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{medium}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{low}</div>
                <div class="label">Low</div>
            </div>
        </div>

        {vulnerabilities_html}

        <div class="footer">
            <p>Security Audit Report Generated by Claude Security Skills</p>
            <p>Automated scanning may produce false positives. Manual review is recommended.</p>
        </div>
    </div>
</body>
</html>"""


def group_vulnerabilities_by_category(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """Group vulnerabilities by OWASP category."""
    grouped = {}
    for vuln in vulnerabilities:
        category = vuln.get('owasp_category', 'Uncategorized')
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(vuln)

    return dict(sorted(grouped.items()))


def generate_vulnerability_html(vuln: Dict) -> str:
    """Generate HTML for a single vulnerability."""
    severity = vuln.get('severity', 'MEDIUM').lower()

    html = f'''
    <div class="vulnerability {severity}">
        <div class="vuln-header">
            <div class="vuln-title">{vuln.get('type', 'Unknown Issue')}</div>
            <div class="vuln-badges">
                <span class="badge severity-{severity}">{vuln.get('severity', 'MEDIUM')}</span>
                <span class="badge tool">{vuln.get('tool', 'Unknown')}</span>
            </div>
        </div>
        <div class="vuln-details">
            <div>Location: <span class="vuln-location">{vuln.get('file', 'unknown')}</span>'''

    if vuln.get('line', 0) > 0:
        html += f' (Line {vuln.get("line")})'

    html += f'''</div>
            <div>{vuln.get('message', 'No description available')}</div>'''

    if vuln.get('cve'):
        html += f'''
            <div>CVE: <strong>{vuln.get('cve')}</strong></div>'''

    html += f'''
            <div class="owasp-category">{vuln.get('owasp_category', 'Uncategorized')}</div>
        </div>
    </div>'''

    return html


def generate_html_report(json_report_path: str, output_path: str = None):
    """Generate HTML report from JSON scan results."""

    with open(json_report_path, 'r') as f:
        data = json.load(f)

    grouped_vulns = group_vulnerabilities_by_category(data.get('vulnerabilities', []))

    vulnerabilities_html = ""
    for category, vulns in grouped_vulns.items():
        vulnerabilities_html += f'''
        <div class="section">
            <h2>{category} ({len(vulns)} issues)</h2>'''

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get('severity', 'MEDIUM'), 2))

        for vuln in sorted_vulns:
            vulnerabilities_html += generate_vulnerability_html(vuln)

        vulnerabilities_html += '</div>'

    if not vulnerabilities_html:
        vulnerabilities_html = '''
        <div class="section">
            <h2>No Vulnerabilities Found</h2>
            <p>The security scan did not identify any vulnerabilities in the target codebase.</p>
            <p>Note: This does not guarantee the absence of all security issues. Manual security review is still recommended.</p>
        </div>'''

    summary = data.get('summary', {})
    html_content = HTML_TEMPLATE.format(
        target=data.get('target', 'Unknown'),
        scan_date=data.get('scan_date', 'Unknown'),
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=summary.get('total_vulnerabilities', 0),
        critical=summary.get('critical', 0),
        high=summary.get('high', 0),
        medium=summary.get('medium', 0),
        low=summary.get('low', 0),
        vulnerabilities_html=vulnerabilities_html
    )

    if not output_path:
        json_path = Path(json_report_path)
        output_path = json_path.with_suffix('.html')

    with open(output_path, 'w') as f:
        f.write(html_content)

    print(f"HTML report generated: {output_path}")
    return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <json_report_path> [output_html_path]")
        sys.exit(1)

    json_report = sys.argv[1]
    output_html = sys.argv[2] if len(sys.argv) > 2 else None

    generate_html_report(json_report, output_html)


if __name__ == "__main__":
    main()
