#!/usr/bin/env python3
"""
Generate formatted HTML security fix reports from JSON fix results.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Fix Rapport - {fix_date}</title>
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
            background: linear-gradient(135deg, #2e7d32 0%, #00897b 100%);
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

        .summary-card.fixed {{
            border-left: 4px solid #2e7d32;
        }}

        .summary-card.fixed .number {{
            color: #2e7d32;
        }}

        .summary-card.remaining {{
            border-left: 4px solid #f57c00;
        }}

        .summary-card.remaining .number {{
            color: #f57c00;
        }}

        .summary-card.manual {{
            border-left: 4px solid #1976d2;
        }}

        .summary-card.manual .number {{
            color: #1976d2;
        }}

        .summary-card.total {{
            border-left: 4px solid #00897b;
            background: linear-gradient(135deg, #2e7d3215 0%, #00897b15 100%);
        }}

        .summary-card.total .number {{
            color: #00897b;
        }}

        .section {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section h2 {{
            color: #2e7d32;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }}

        .section h2.remaining-title {{
            color: #f57c00;
        }}

        .section h2.manual-title {{
            color: #1976d2;
        }}

        .result-item {{
            border-left: 3px solid #e0e0e0;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
            border-radius: 5px;
        }}

        .result-item.fixed {{
            border-left-color: #2e7d32;
            background: #e8f5e9;
        }}

        .result-item.skipped {{
            border-left-color: #f57c00;
            background: #fff3e0;
        }}

        .result-item.manual_review {{
            border-left-color: #1976d2;
            background: #e3f2fd;
        }}

        .item-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .item-title {{
            font-weight: bold;
            color: #333;
        }}

        .item-badges {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
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

        .badge.status-fixed {{
            background: #2e7d32;
            color: white;
        }}

        .badge.status-skipped {{
            background: #f57c00;
            color: white;
        }}

        .badge.status-manual {{
            background: #1976d2;
            color: white;
        }}

        .badge.fix-auto {{
            background: #388e3c;
            color: white;
        }}

        .badge.fix-manual {{
            background: #f57c00;
            color: white;
        }}

        .badge.fix-dependency {{
            background: #1976d2;
            color: white;
        }}

        .item-details {{
            color: #666;
            font-size: 0.9em;
            margin-top: 8px;
        }}

        .item-location {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.85em;
        }}

        .action-taken {{
            margin-top: 10px;
            padding: 10px 14px;
            background: #e8f5e9;
            border: 1px solid #a5d6a7;
            border-radius: 6px;
            font-size: 0.88em;
            color: #2e7d32;
        }}

        .action-taken strong {{
            display: block;
            margin-bottom: 3px;
        }}

        .result-item.skipped .action-taken {{
            background: #fff3e0;
            border-color: #ffcc80;
            color: #e65100;
        }}

        .result-item.manual_review .action-taken {{
            background: #e3f2fd;
            border-color: #90caf9;
            color: #1565c0;
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

            .item-header {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .item-badges {{
                margin-top: 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Fix Rapport</h1>
            <div class="meta">
                <div>Doel: <strong>{target}</strong></div>
                <div>Fix datum: <strong>{fix_date}</strong></div>
                <div>Gegenereerd: <strong>{generation_time}</strong></div>
                <div>Bronrapport: <strong>{source_audit}</strong></div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card total">
                <div class="number">{total_processed}</div>
                <div class="label">Totaal verwerkt</div>
            </div>
            <div class="summary-card fixed">
                <div class="number">{fixed}</div>
                <div class="label">Gefixt</div>
            </div>
            <div class="summary-card remaining">
                <div class="number">{skipped}</div>
                <div class="label">Resterend</div>
            </div>
            <div class="summary-card manual">
                <div class="number">{manual_review}</div>
                <div class="label">Handmatige review</div>
            </div>
        </div>

        {results_html}

        <div class="footer">
            <p>Security Fix Rapport gegenereerd door Claude Security Skills</p>
            <p>Controleer alle wijzigingen voordat je ze naar productie deployt.</p>
        </div>
    </div>
</body>
</html>"""


STATUS_LABELS = {
    "fixed": ("Gefixt", "status-fixed"),
    "skipped": ("Overgeslagen", "status-skipped"),
    "manual_review": ("Handmatige review", "status-manual"),
}

FIX_TYPE_LABELS = {
    "auto": ("Auto-fix", "fix-auto"),
    "manual": ("Handmatig", "fix-manual"),
    "dependency": ("Dependency", "fix-dependency"),
}


def generate_result_item_html(item: Dict) -> str:
    """Generate HTML for a single fix result item."""
    status = item.get('status', 'skipped')
    severity = item.get('severity', 'MEDIUM').lower()

    html = f'''
    <div class="result-item {status}">
        <div class="item-header">
            <div class="item-title">{item.get('type', 'Onbekend')}</div>
            <div class="item-badges">
                <span class="badge severity-{severity}">{item.get('severity', 'MEDIUM')}</span>'''

    status_label, status_css = STATUS_LABELS.get(status, ("Onbekend", "status-skipped"))
    html += f'''
                <span class="badge {status_css}">{status_label}</span>'''

    fix_type = item.get('fix_type', '')
    if fix_type in FIX_TYPE_LABELS:
        label, css_class = FIX_TYPE_LABELS[fix_type]
        html += f'''
                <span class="badge {css_class}">{label}</span>'''

    html += '''
            </div>
        </div>
        <div class="item-details">'''

    html += f'''
            <div>Locatie: <span class="item-location">{item.get('file', 'onbekend')}</span>'''

    if item.get('line', 0) > 0:
        html += f' (Regel {item.get("line")})'

    html += '</div>'

    html += f'''
            <div>{item.get('message', 'Geen beschrijving beschikbaar')}</div>'''

    action = item.get('action_taken', '')
    if action:
        html += f'''
            <div class="action-taken"><strong>Actie:</strong> {action}</div>'''

    html += '''
        </div>
    </div>'''

    return html


def generate_fix_report(json_fix_path: str, output_path: str = None):
    """Generate HTML fix report from JSON fix results."""

    with open(json_fix_path, 'r') as f:
        data = json.load(f)

    results = data.get('results', [])
    fixed_items = [r for r in results if r.get('status') == 'fixed']
    skipped_items = [r for r in results if r.get('status') == 'skipped']
    manual_items = [r for r in results if r.get('status') == 'manual_review']

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    results_html = ""

    if fixed_items:
        sorted_fixed = sorted(fixed_items, key=lambda x: severity_order.get(x.get('severity', 'MEDIUM'), 2))
        count = len(sorted_fixed)
        label = "bevinding" if count == 1 else "bevindingen"
        results_html += f'''
        <div class="section">
            <h2>Opgeloste bevindingen ({count} {label})</h2>'''
        for item in sorted_fixed:
            results_html += generate_result_item_html(item)
        results_html += '</div>'

    if skipped_items:
        sorted_skipped = sorted(skipped_items, key=lambda x: severity_order.get(x.get('severity', 'MEDIUM'), 2))
        count = len(sorted_skipped)
        label = "bevinding" if count == 1 else "bevindingen"
        results_html += f'''
        <div class="section">
            <h2 class="remaining-title">Resterende bevindingen ({count} {label})</h2>'''
        for item in sorted_skipped:
            results_html += generate_result_item_html(item)
        results_html += '</div>'

    if manual_items:
        sorted_manual = sorted(manual_items, key=lambda x: severity_order.get(x.get('severity', 'MEDIUM'), 2))
        count = len(sorted_manual)
        label = "bevinding" if count == 1 else "bevindingen"
        results_html += f'''
        <div class="section">
            <h2 class="manual-title">Handmatige review vereist ({count} {label})</h2>'''
        for item in sorted_manual:
            results_html += generate_result_item_html(item)
        results_html += '</div>'

    if not results_html:
        results_html = '''
        <div class="section">
            <h2>Geen resultaten</h2>
            <p>Er zijn geen fix-resultaten om weer te geven.</p>
        </div>'''

    summary = data.get('summary', {})
    html_content = HTML_TEMPLATE.format(
        target=data.get('target', 'Onbekend'),
        fix_date=data.get('fix_date', 'Onbekend'),
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_audit=data.get('source_audit', 'Onbekend'),
        total_processed=summary.get('total_processed', 0),
        fixed=summary.get('fixed', 0),
        skipped=summary.get('skipped', 0),
        manual_review=summary.get('manual_review', 0),
        results_html=results_html
    )

    if not output_path:
        json_path = Path(json_fix_path)
        output_path = json_path.with_suffix('.html')

    with open(output_path, 'w') as f:
        f.write(html_content)

    print(f"HTML fix rapport gegenereerd: {output_path}")
    return output_path


def main():
    if len(sys.argv) < 2:
        print("Gebruik: python generate_fix_report.py <json_fix_pad> [output_html_pad]")
        sys.exit(1)

    json_fix = sys.argv[1]
    output_html = sys.argv[2] if len(sys.argv) > 2 else None

    generate_fix_report(json_fix, output_html)


if __name__ == "__main__":
    main()
