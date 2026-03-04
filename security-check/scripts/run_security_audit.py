#!/usr/bin/env python3
"""
Main security audit orchestrator that runs all security scanning tools
and consolidates results into a comprehensive report.
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Severity normalization: maps tool-specific terms to unified schema
SEVERITY_MAP = {
    # Semgrep uses ERROR/WARNING/INFO
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    # Already normalized (Trivy, etc.)
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

SEVERITY_FALLBACK = "MEDIUM"


def normalize_severity(raw: str) -> str:
    """Normalize a tool-specific severity string to CRITICAL/HIGH/MEDIUM/LOW."""
    return SEVERITY_MAP.get(raw.upper(), SEVERITY_FALLBACK)


class SecurityAuditor:
    def __init__(self, target_path: str, output_dir: str = "./security_reports"):
        self.target_path = Path(target_path).resolve()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "version": "2.0",
            "scan_date": datetime.now().isoformat(),
            "target": str(self.target_path),
            "vulnerabilities": [],
            "summary": {}
        }
        self._finding_counter = 0

    def _next_finding_id(self) -> str:
        self._finding_counter += 1
        return f"finding-{self._finding_counter:03d}"

    def run_semgrep(self) -> Dict[str, Any]:
        """Run Semgrep for static code analysis."""
        print("[*] Running Semgrep static analysis...")
        try:
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--severity=ERROR",
                "--severity=WARNING",
                str(self.target_path)
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode in (0, 1):  # 1 = findings found
                return json.loads(result.stdout)
            else:
                print(f"[!] Semgrep error: {result.stderr}")
                return {"errors": [result.stderr]}
        except FileNotFoundError:
            print("[!] Semgrep not installed. Install with: pip install semgrep")
            return {"errors": ["Semgrep not installed"]}
        except subprocess.TimeoutExpired:
            print("[!] Semgrep timed out after 300s")
            return {"errors": ["Semgrep timed out"]}
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse Semgrep output: {e}")
            return {"errors": ["Failed to parse Semgrep output"]}

    def run_gitleaks(self) -> Dict[str, Any]:
        """Run Gitleaks for secret detection."""
        print("[*] Running Gitleaks secret detection...")
        try:
            report_file = self.output_dir / f"gitleaks_{self.timestamp}.json"
            cmd = [
                "gitleaks",
                "detect",
                "--source", str(self.target_path),
                "--report-format", "json",
                "--report-path", str(report_file),
                "--no-git"
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            if report_file.exists():
                with open(report_file, 'r') as f:
                    return json.load(f)
            return {"findings": []}
        except FileNotFoundError:
            print("[!] Gitleaks not installed. Install from: https://github.com/gitleaks/gitleaks")
            return {"errors": ["Gitleaks not installed"]}
        except subprocess.TimeoutExpired:
            print("[!] Gitleaks timed out after 120s")
            return {"errors": ["Gitleaks timed out"]}
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse Gitleaks output: {e}")
            return {"errors": ["Failed to parse Gitleaks output"]}

    def run_trivy(self) -> Dict[str, Any]:
        """Run Trivy for dependency and container scanning."""
        print("[*] Running Trivy dependency scanning...")
        try:
            cmd = [
                "trivy",
                "fs",
                "--format", "json",
                "--scanners", "vuln,secret,config",
                str(self.target_path)
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode in (0, 1):  # 1 = vulnerabilities found
                return json.loads(result.stdout)
            else:
                print(f"[!] Trivy error: {result.stderr}")
                return {"errors": [result.stderr]}
        except FileNotFoundError:
            print("[!] Trivy not installed. Install from: https://github.com/aquasecurity/trivy")
            return {"errors": ["Trivy not installed"]}
        except subprocess.TimeoutExpired:
            print("[!] Trivy timed out after 300s")
            return {"errors": ["Trivy timed out"]}
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse Trivy output: {e}")
            return {"errors": ["Failed to parse Trivy output"]}

    def categorize_by_owasp(self, vulnerability: Dict) -> str:
        """Map a vulnerability to an OWASP Top 10 2021 category.

        Strategy (in priority order):
        1. Use tool metadata (Semgrep extra.metadata.owasp)
        2. Direct mapping for tools with fixed categories (Gitleaks, Trivy deps)
        3. Pattern matching on check_id + message as fallback
        """
        # 1. Semgrep metadata -- most reliable source
        owasp_meta = (
            vulnerability.get("extra", {})
            .get("metadata", {})
            .get("owasp", "")
        )
        if owasp_meta and "A0" in owasp_meta:
            return owasp_meta

        # 2. Direct tool mapping
        tool = vulnerability.get("tool", "")
        if tool == "Gitleaks":
            return "A02:2021 - Cryptographic Failures"
        if tool == "Trivy":
            return "A06:2021 - Vulnerable and Outdated Components"

        # 3. Pattern matching on check_id + message (not full JSON dump)
        check_id = vulnerability.get("type", vulnerability.get("check_id", "")).lower()
        message = vulnerability.get("message", "").lower()
        text = f"{check_id} {message}"

        # Ordered from specific to generic
        patterns = [
            (["ssrf", "server-side request"], "A10:2021 - Server-Side Request Forgery"),
            (["sql-inject", "sql_inject", "sqli", "parameterized"], "A03:2021 - Injection"),
            (["xss", "cross-site scripting", "innerhtml"], "A03:2021 - Injection"),
            (["command-inject", "cmd-inject", "shell-inject"], "A03:2021 - Injection"),
            (["ssti", "template-inject", "server-side-template"], "A03:2021 - Injection"),
            (["redos", "regex-dos"], "A03:2021 - Injection"),
            (["inject", "ldap", "xpath"], "A03:2021 - Injection"),
            (["deseriali", "unsafe-load", "integrity"], "A08:2021 - Software and Data Integrity Failures"),
            (["jwt", "token", "bearer", "rate-limit", "brute-force", "throttle"], "A07:2021 - Identification and Authentication Failures"),
            (["authenticat", "password", "credential", "login", "session-fixat"], "A07:2021 - Identification and Authentication Failures"),
            (["mass-assign", "over-posting"], "A01:2021 - Broken Access Control"),
            (["postmessage", "websocket"], "A01:2021 - Broken Access Control"),
            (["authoriz", "access-control", "privilege", "idor", "broken-access"], "A01:2021 - Broken Access Control"),
            (["open-redirect", "redirect"], "A01:2021 - Broken Access Control"),
            (["path-traversal", "directory-traversal", "lfi"], "A01:2021 - Broken Access Control"),
            (["password-hash", "weak-hash", "bcrypt", "argon"], "A02:2021 - Cryptographic Failures"),
            (["crypto", "cipher", "weak-random", "md5", "sha1", "des", "secret", "api-key", "hardcoded"], "A02:2021 - Cryptographic Failures"),
            (["tls", "ssl", "certificate", "https"], "A02:2021 - Cryptographic Failures"),
            (["upload", "file-upload", "multipart", "race-condition", "toctou"], "A04:2021 - Insecure Design"),
            (["graphql", "introspection", "query-depth"], "A05:2021 - Security Misconfiguration"),
            (["security-header", "csp", "hsts", "x-frame"], "A05:2021 - Security Misconfiguration"),
            (["misconfig", "debug", "default", "cors", "header", "cookie", "csrf"], "A05:2021 - Security Misconfiguration"),
            (["dependency", "component", "outdated", "cve-"], "A06:2021 - Vulnerable and Outdated Components"),
            (["log", "monitor", "audit-trail"], "A09:2021 - Security Logging and Monitoring Failures"),
        ]

        for keywords, category in patterns:
            if any(kw in text for kw in keywords):
                return category

        return "A00:2021 - Uncategorized"

    def _determine_fix_type(self, vulnerability: Dict) -> str:
        """Determine whether a finding can be auto-fixed, needs manual review, or is a dependency issue."""
        tool = vulnerability.get("tool", "")
        if tool == "Trivy":
            return "dependency"
        check_id = vulnerability.get("type", "").lower()
        auto_patterns = [
            "misconfig", "cookie", "header", "debug", "csrf", "cors", "tls-verify",
            "security-header", "jwt", "password-hash", "target-blank", "yaml-load",
            "insecure-random", "weak-crypto", "insecure-cookie", "tls",
        ]
        if any(p in check_id for p in auto_patterns):
            return "auto"
        return "manual"

    def consolidate_results(self, semgrep_results: Dict, gitleaks_results: Dict, trivy_results: Dict):
        """Consolidate all scan results into a unified format."""
        vulnerabilities = []

        # Process Semgrep results
        if "results" in semgrep_results:
            for finding in semgrep_results["results"]:
                raw_severity = finding.get("extra", {}).get("severity", "MEDIUM")
                metadata = finding.get("extra", {}).get("metadata", {})
                cwe_data = metadata.get("cwe", [])
                if isinstance(cwe_data, str):
                    cwe_data = [cwe_data]
                vuln = {
                    "id": self._next_finding_id(),
                    "tool": "Semgrep",
                    "type": finding.get("check_id", "unknown"),
                    "severity": normalize_severity(raw_severity),
                    "file": finding.get("path", "unknown"),
                    "line": finding.get("start", {}).get("line", 0),
                    "message": finding.get("extra", {}).get("message", ""),
                    "cwe": cwe_data,
                    "owasp_category": self.categorize_by_owasp({
                        **finding,
                        "tool": "Semgrep",
                        "type": finding.get("check_id", "unknown"),
                        "message": finding.get("extra", {}).get("message", ""),
                    }),
                }
                vuln["fix_type"] = self._determine_fix_type(vuln)
                vuln["fix_hint"] = finding.get("extra", {}).get("fix", "")
                vulnerabilities.append(vuln)

        # Process Gitleaks results
        if isinstance(gitleaks_results, list):
            for finding in gitleaks_results:
                vuln = {
                    "id": self._next_finding_id(),
                    "tool": "Gitleaks",
                    "type": "Secret Exposure",
                    "severity": "HIGH",
                    "file": finding.get("File", "unknown"),
                    "line": finding.get("StartLine", 0),
                    "message": f"Potential secret found: {finding.get('Description', '')}",
                    "owasp_category": "A02:2021 - Cryptographic Failures",
                    "fix_type": "manual",
                    "fix_hint": "Remove the secret and rotate the credential",
                }
                vulnerabilities.append(vuln)

        # Process Trivy results
        if "Results" in trivy_results:
            for result in trivy_results["Results"]:
                if "Vulnerabilities" in result:
                    for vuln_detail in result["Vulnerabilities"]:
                        raw_severity = vuln_detail.get("Severity", "MEDIUM")
                        vuln = {
                            "id": self._next_finding_id(),
                            "tool": "Trivy",
                            "type": "Dependency Vulnerability",
                            "severity": normalize_severity(raw_severity),
                            "file": result.get("Target", "unknown"),
                            "line": 0,
                            "message": f"{vuln_detail.get('PkgName', '')} - {vuln_detail.get('Title', '')}",
                            "cve": vuln_detail.get("VulnerabilityID", ""),
                            "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                            "fix_type": "dependency",
                            "fix_hint": vuln_detail.get("FixedVersion", ""),
                        }
                        vulnerabilities.append(vuln)

        self.results["vulnerabilities"] = vulnerabilities
        self.results["summary"] = {
            "total_vulnerabilities": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v["severity"] == "CRITICAL"]),
            "high": len([v for v in vulnerabilities if v["severity"] == "HIGH"]),
            "medium": len([v for v in vulnerabilities if v["severity"] == "MEDIUM"]),
            "low": len([v for v in vulnerabilities if v["severity"] == "LOW"]),
        }

    def generate_report(self):
        """Generate the final security audit report."""
        json_report_path = self.output_dir / f"security_audit_{self.timestamp}.json"
        with open(json_report_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print("\n" + "=" * 60)
        print("SECURITY AUDIT SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target_path}")
        print(f"Scan Date: {self.results['scan_date']}")
        print(f"\nTotal Vulnerabilities: {self.results['summary']['total_vulnerabilities']}")
        print(f"  Critical: {self.results['summary']['critical']}")
        print(f"  High:     {self.results['summary']['high']}")
        print(f"  Medium:   {self.results['summary']['medium']}")
        print(f"  Low:      {self.results['summary']['low']}")
        print(f"\nDetailed report saved to: {json_report_path}")

        return json_report_path

    def run_audit(self):
        """Execute the complete security audit."""
        print(f"[*] Starting security audit of {self.target_path}")

        semgrep_results = self.run_semgrep()
        gitleaks_results = self.run_gitleaks()
        trivy_results = self.run_trivy()

        self.consolidate_results(semgrep_results, gitleaks_results, trivy_results)

        report_path = self.generate_report()
        return report_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_security_audit.py <target_path> [output_dir]")
        sys.exit(1)

    target_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./security_reports"

    auditor = SecurityAuditor(target_path, output_dir)
    report_path = auditor.run_audit()

    print(f"\n[+] Security audit complete! Report: {report_path}")


if __name__ == "__main__":
    main()
