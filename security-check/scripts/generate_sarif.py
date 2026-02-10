#!/usr/bin/env python3
"""
Generate SARIF v2.1.0 output from security audit JSON reports.
Supports delta/diff reporting and false positive management.

Usage:
    python generate_sarif.py <audit_report.json> [options]

Options:
    --output, -o        Output SARIF file path (default: stdout)
    --baseline, -b      Baseline report for delta comparison
    --ignore-file, -i   Path to .security-ignore file (default: .security-ignore)
    --delta-only        Output only NEW findings (for PR reviews)
    --delta-report, -d  Output delta report as JSON to this path
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

TOOL_NAME = "security-audit"
TOOL_VERSION = "2.0"


def _finding_key(finding: Dict) -> Tuple[str, int, str]:
    """Generate a stable key for a finding based on file, line, and type."""
    return (
        finding.get("file", ""),
        finding.get("line", 0),
        finding.get("type", ""),
    )


def parse_security_ignore(ignore_path: str) -> Dict[Tuple[str, int, str], str]:
    """Parse a .security-ignore file.

    Format per line: file:line:rule-id # reason
    Returns a dict mapping (file, line, rule-id) -> reason.
    """
    ignores: Dict[Tuple[str, int, str], str] = {}
    path = Path(ignore_path)
    if not path.exists():
        return ignores

    for line_num, raw_line in enumerate(path.read_text().splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        reason = ""
        if "#" in line:
            line, reason = line.split("#", 1)
            line = line.strip()
            reason = reason.strip()

        parts = line.split(":")
        if len(parts) >= 3:
            file_path = parts[0].strip()
            try:
                line_no = int(parts[1].strip())
            except ValueError:
                print(f"[!] .security-ignore line {line_num}: invalid line number '{parts[1]}'", file=sys.stderr)
                continue
            rule_id = ":".join(parts[2:]).strip()
            ignores[(file_path, line_no, rule_id)] = reason or "No reason provided"
        else:
            print(f"[!] .security-ignore line {line_num}: invalid format '{raw_line}'", file=sys.stderr)

    return ignores


def filter_ignored(findings: List[Dict], ignores: Dict[Tuple[str, int, str], str]) -> Tuple[List[Dict], List[Dict]]:
    """Separate findings into active and ignored lists."""
    if not ignores:
        return findings, []

    active = []
    ignored = []
    for f in findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("type", ""))
        if key in ignores:
            f_copy = dict(f)
            f_copy["ignore_reason"] = ignores[key]
            ignored.append(f_copy)
        else:
            active.append(f)

    return active, ignored


def compute_delta(current: List[Dict], baseline: List[Dict]) -> Dict[str, List[Dict]]:
    """Compare current findings against a baseline.

    Returns dict with keys: new, fixed, existing.
    """
    current_keys = {_finding_key(f): f for f in current}
    baseline_keys = {_finding_key(f): f for f in baseline}

    current_set: Set[Tuple] = set(current_keys.keys())
    baseline_set: Set[Tuple] = set(baseline_keys.keys())

    new_keys = current_set - baseline_set
    fixed_keys = baseline_set - current_set
    existing_keys = current_set & baseline_set

    def _tag(findings_dict: Dict, keys: Set[Tuple], status: str) -> List[Dict]:
        result = []
        for k in sorted(keys):
            entry = dict(findings_dict[k])
            entry["delta_status"] = status
            result.append(entry)
        return result

    return {
        "new": _tag(current_keys, new_keys, "NEW"),
        "fixed": _tag(baseline_keys, fixed_keys, "FIXED"),
        "existing": _tag(current_keys, existing_keys, "EXISTING"),
    }


def build_sarif(report: Dict, findings: Optional[List[Dict]] = None) -> Dict:
    """Build a SARIF v2.1.0 document from an audit report.

    If findings is provided, use those instead of report['vulnerabilities'].
    """
    vulns = findings if findings is not None else report.get("vulnerabilities", [])

    rules: Dict[str, Dict] = {}
    results: List[Dict] = []

    for vuln in vulns:
        rule_id = vuln.get("type", "unknown")
        severity = vuln.get("severity", "MEDIUM")
        sarif_level = SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")

        if rule_id not in rules:
            tags = []
            owasp = vuln.get("owasp_category", "")
            if owasp:
                tags.append(owasp)
            tool_name = vuln.get("tool", "")
            if tool_name:
                tags.append(f"tool/{tool_name}")

            rule_entry = {
                "id": rule_id,
                "shortDescription": {"text": rule_id},
                "properties": {"tags": tags},
            }

            cwe_list = vuln.get("cwe", [])
            if cwe_list:
                if isinstance(cwe_list, str):
                    cwe_list = [cwe_list]
                rule_entry["relationships"] = []
                for cwe in cwe_list:
                    cwe_id = cwe
                    if "CWE-" in cwe:
                        cwe_id = cwe.split(":")[0].strip() if ":" in cwe else cwe
                    rule_entry["relationships"].append({
                        "target": {
                            "id": cwe_id,
                            "guid": "",
                            "toolComponent": {"name": "CWE", "index": 0},
                        },
                        "kinds": ["superset"],
                    })
            rules[rule_id] = rule_entry

        file_path = vuln.get("file", "unknown")
        line = vuln.get("line", 1)
        if line < 1:
            line = 1

        result_entry = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": vuln.get("message", "Security finding")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": line},
                    }
                }
            ],
        }

        fix_hint = vuln.get("fix_hint", "")
        if fix_hint:
            result_entry["fixes"] = [
                {
                    "description": {"text": fix_hint},
                    "artifactChanges": [],
                }
            ]

        finding_id = vuln.get("id", "")
        if finding_id:
            result_entry["properties"] = {"finding-id": finding_id}

        delta_status = vuln.get("delta_status")
        if delta_status:
            result_entry.setdefault("properties", {})["delta-status"] = delta_status

        results.append(result_entry)

    # Build CWE taxa list from all findings
    all_cwes: Dict[str, str] = {}
    for vuln in vulns:
        cwe_list = vuln.get("cwe", [])
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        for cwe in cwe_list:
            cwe_id = cwe.split(":")[0].strip() if ":" in cwe else cwe
            cwe_desc = cwe.split(":", 1)[1].strip() if ":" in cwe else cwe
            if cwe_id not in all_cwes:
                all_cwes[cwe_id] = cwe_desc

    taxonomies = []
    if all_cwes:
        taxa = []
        for cwe_id, cwe_desc in sorted(all_cwes.items()):
            taxa.append({
                "id": cwe_id,
                "shortDescription": {"text": cwe_desc},
            })
        taxonomies.append({
            "name": "CWE",
            "version": "4.13",
            "informationUri": "https://cwe.mitre.org/",
            "taxa": taxa,
        })

    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/alessio/claude-security-skill",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    if taxonomies:
        run["taxonomies"] = taxonomies

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }

    return sarif


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate SARIF output from security audit reports with delta and ignore support."
    )
    parser.add_argument("report", help="Path to the audit report JSON (v2.0)")
    parser.add_argument("-o", "--output", help="Output SARIF file path (default: stdout)")
    parser.add_argument("-b", "--baseline", help="Baseline report JSON for delta comparison")
    parser.add_argument("-i", "--ignore-file", default=".security-ignore",
                        help="Path to .security-ignore file (default: .security-ignore)")
    parser.add_argument("--delta-only", action="store_true",
                        help="Output only NEW findings in SARIF (for PR reviews)")
    parser.add_argument("-d", "--delta-report", help="Output delta report as JSON to this path")

    args = parser.parse_args()

    # Load audit report
    try:
        with open(args.report, "r") as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Failed to load report: {e}", file=sys.stderr)
        sys.exit(1)

    findings = report.get("vulnerabilities", [])

    # Apply .security-ignore filtering
    ignores = parse_security_ignore(args.ignore_file)
    findings, ignored_findings = filter_ignored(findings, ignores)

    if ignored_findings:
        print(f"[*] Filtered {len(ignored_findings)} ignored finding(s) via {args.ignore_file}", file=sys.stderr)

    # Delta reporting
    delta = None
    if args.baseline:
        try:
            with open(args.baseline, "r") as f:
                baseline_report = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Failed to load baseline: {e}", file=sys.stderr)
            sys.exit(1)

        baseline_findings = baseline_report.get("vulnerabilities", [])
        # Also filter baseline with ignores for consistent comparison
        baseline_findings, _ = filter_ignored(baseline_findings, ignores)

        delta = compute_delta(findings, baseline_findings)

        print(f"[*] Delta: {len(delta['new'])} new, {len(delta['fixed'])} fixed, {len(delta['existing'])} existing", file=sys.stderr)

        if args.delta_report:
            delta_output = {
                "version": "2.0",
                "delta_date": datetime.now().isoformat(),
                "current_report": args.report,
                "baseline_report": args.baseline,
                "new": delta["new"],
                "fixed": delta["fixed"],
                "existing": delta["existing"],
                "ignored_count": len(ignored_findings),
                "summary": {
                    "new_count": len(delta["new"]),
                    "fixed_count": len(delta["fixed"]),
                    "existing_count": len(delta["existing"]),
                },
            }
            with open(args.delta_report, "w") as f:
                json.dump(delta_output, f, indent=2)
            print(f"[*] Delta report saved to: {args.delta_report}", file=sys.stderr)

        if args.delta_only:
            findings = delta["new"]
        else:
            # Tag all findings with delta status
            tagged = delta["new"] + delta["existing"]
            findings = tagged

    # Generate SARIF
    sarif = build_sarif(report, findings)

    sarif_json = json.dumps(sarif, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(sarif_json)
        print(f"[+] SARIF report saved to: {args.output}", file=sys.stderr)
    else:
        print(sarif_json)


if __name__ == "__main__":
    main()
