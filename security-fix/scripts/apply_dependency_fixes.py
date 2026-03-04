#!/usr/bin/env python3
"""
Apply dependency fixes for common package managers.
Supports npm, pnpm, yarn, pip, pipenv, poetry, cargo, go, and maven ecosystems.
"""

import subprocess
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Optional


class DependencyFixer:
    def __init__(self, project_path: str, dry_run: bool = False):
        self.project_path = Path(project_path)
        self.dry_run = dry_run
        self.results = []

    def _has_poetry_config(self) -> bool:
        """Check if pyproject.toml contains a [tool.poetry] section."""
        pyproject = self.project_path / "pyproject.toml"
        if not pyproject.exists():
            return False
        try:
            content = pyproject.read_text()
            return "[tool.poetry]" in content
        except OSError:
            return False

    def detect_ecosystem(self) -> List[str]:
        """Detect which package managers are in use."""
        ecosystems = []

        # Node.js ecosystem - check specific lockfiles first
        if (self.project_path / "pnpm-lock.yaml").exists():
            ecosystems.append("pnpm")
        elif (self.project_path / "yarn.lock").exists():
            ecosystems.append("yarn")
        elif (self.project_path / "package.json").exists():
            ecosystems.append("npm")

        # Python ecosystem - check specific tools first
        if (self.project_path / "poetry.lock").exists() or self._has_poetry_config():
            ecosystems.append("poetry")
        elif (self.project_path / "Pipfile").exists():
            ecosystems.append("pipenv")
        elif (self.project_path / "requirements.txt").exists() or (self.project_path / "setup.py").exists():
            ecosystems.append("pip")

        if (self.project_path / "Cargo.toml").exists():
            ecosystems.append("cargo")
        if (self.project_path / "go.mod").exists():
            ecosystems.append("go")
        if (self.project_path / "pom.xml").exists():
            ecosystems.append("maven")

        return ecosystems

    def _run_cmd(self, cmd: List[str], timeout: int = 120, check: bool = False) -> subprocess.CompletedProcess:
        """Run a subprocess command with timeout."""
        return subprocess.run(
            cmd,
            cwd=self.project_path,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout
        )

    def fix_npm(self) -> Dict:
        """Fix npm vulnerabilities."""
        print("Checking npm vulnerabilities...")
        result = {"ecosystem": "npm", "success": False, "message": "", "fixes_applied": 0}

        try:
            audit_result = self._run_cmd(["npm", "audit", "--json"])

            if audit_result.returncode == 0 or audit_result.stdout:
                audit_data = json.loads(audit_result.stdout) if audit_result.stdout else {}
                vuln_count = audit_data.get("metadata", {}).get("vulnerabilities", {}).get("total", 0)

                if vuln_count == 0:
                    result["message"] = "No npm vulnerabilities found"
                    result["success"] = True
                    return result

                print(f"   Found {vuln_count} vulnerabilities")

                if self.dry_run:
                    result["message"] = f"Would fix {vuln_count} npm vulnerabilities"
                    result["success"] = True
                    return result

                fix_result = self._run_cmd(["npm", "audit", "fix"])

                if fix_result.returncode == 0:
                    result["success"] = True
                    result["message"] = "npm vulnerabilities fixed"
                    result["fixes_applied"] = vuln_count
                else:
                    result["message"] = f"npm audit fix failed: {fix_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "npm audit timed out after 120s"
        except json.JSONDecodeError:
            result["message"] = "Failed to parse npm audit output"
        except FileNotFoundError:
            result["message"] = "npm not found"

        return result

    def fix_pnpm(self) -> Dict:
        """Fix pnpm vulnerabilities."""
        print("Checking pnpm vulnerabilities...")
        result = {"ecosystem": "pnpm", "success": False, "message": "", "fixes_applied": 0}

        try:
            audit_result = self._run_cmd(["pnpm", "audit", "--json"])

            if audit_result.returncode == 0:
                result["message"] = "No pnpm vulnerabilities found"
                result["success"] = True
                return result

            if self.dry_run:
                result["message"] = "Would run pnpm audit --fix"
                result["success"] = True
                return result

            fix_result = self._run_cmd(["pnpm", "audit", "--fix"])
            if fix_result.returncode == 0:
                result["success"] = True
                result["message"] = "pnpm vulnerabilities fixed"
                result["fixes_applied"] = 1
            else:
                result["message"] = f"pnpm audit fix failed: {fix_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "pnpm audit timed out after 120s"
        except FileNotFoundError:
            result["message"] = "pnpm not found"

        return result

    def fix_yarn(self) -> Dict:
        """Fix yarn vulnerabilities."""
        print("Checking yarn vulnerabilities...")
        result = {"ecosystem": "yarn", "success": False, "message": "", "fixes_applied": 0}

        try:
            audit_result = self._run_cmd(["yarn", "audit", "--json"])

            if audit_result.returncode == 0:
                result["message"] = "No yarn vulnerabilities found"
                result["success"] = True
                return result

            if self.dry_run:
                result["message"] = "Would run yarn upgrade to fix vulnerabilities"
                result["success"] = True
                return result

            # yarn audit doesn't have --fix; use yarn upgrade instead
            fix_result = self._run_cmd(["yarn", "upgrade"], timeout=180)
            if fix_result.returncode == 0:
                result["success"] = True
                result["message"] = "yarn dependencies upgraded"
                result["fixes_applied"] = 1
            else:
                result["message"] = f"yarn upgrade failed: {fix_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "yarn audit timed out after 120s"
        except FileNotFoundError:
            result["message"] = "yarn not found"

        return result

    def fix_pip(self) -> Dict:
        """Fix pip vulnerabilities using pip-audit."""
        print("Checking pip vulnerabilities...")
        result = {"ecosystem": "pip", "success": False, "message": "", "fixes_applied": 0}

        try:
            check_install = self._run_cmd(["pip-audit", "--version"])

            if check_install.returncode != 0:
                result["message"] = "pip-audit not installed. Install with: pip install pip-audit"
                return result

            audit_result = self._run_cmd(["pip-audit", "--format", "json"])

            if audit_result.returncode == 0:
                result["message"] = "No pip vulnerabilities found"
                result["success"] = True
                return result

            if audit_result.stdout:
                try:
                    audit_data = json.loads(audit_result.stdout)
                    vuln_count = len(audit_data.get("dependencies", []))
                except json.JSONDecodeError:
                    vuln_count = 0
                print(f"   Found {vuln_count} vulnerable packages")

                if self.dry_run:
                    result["message"] = f"Would fix {vuln_count} pip vulnerabilities"
                    result["success"] = True
                    return result

                result["message"] = (
                    f"Found {vuln_count} pip vulnerabilities. "
                    "Run 'pip-audit --fix' to apply automatic fixes, or review manually."
                )
                result["success"] = True

        except subprocess.TimeoutExpired:
            result["message"] = "pip-audit timed out after 120s"
        except FileNotFoundError:
            result["message"] = "pip-audit not found"

        return result

    def fix_pipenv(self) -> Dict:
        """Fix pipenv vulnerabilities."""
        print("Checking pipenv vulnerabilities...")
        result = {"ecosystem": "pipenv", "success": False, "message": "", "fixes_applied": 0}

        try:
            audit_result = self._run_cmd(["pipenv", "check", "--output", "minimal"])

            if audit_result.returncode == 0:
                result["message"] = "No pipenv vulnerabilities found"
                result["success"] = True
                return result

            if self.dry_run:
                result["message"] = "Would run pipenv update"
                result["success"] = True
                return result

            fix_result = self._run_cmd(["pipenv", "update"], timeout=180)
            if fix_result.returncode == 0:
                result["success"] = True
                result["message"] = "pipenv dependencies updated"
                result["fixes_applied"] = 1
            else:
                result["message"] = f"pipenv update failed: {fix_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "pipenv check timed out after 120s"
        except FileNotFoundError:
            result["message"] = "pipenv not found"

        return result

    def fix_poetry(self) -> Dict:
        """Fix poetry vulnerabilities."""
        print("Checking poetry vulnerabilities...")
        result = {"ecosystem": "poetry", "success": False, "message": "", "fixes_applied": 0}

        try:
            if self.dry_run:
                result["message"] = "Would run poetry update"
                result["success"] = True
                return result

            fix_result = self._run_cmd(["poetry", "update"], timeout=180)
            if fix_result.returncode == 0:
                result["success"] = True
                result["message"] = "poetry dependencies updated"
                result["fixes_applied"] = 1
            else:
                result["message"] = f"poetry update failed: {fix_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "poetry update timed out after 180s"
        except FileNotFoundError:
            result["message"] = "poetry not found"

        return result

    def fix_cargo(self) -> Dict:
        """Fix cargo vulnerabilities."""
        print("Checking cargo vulnerabilities...")
        result = {"ecosystem": "cargo", "success": False, "message": "", "fixes_applied": 0}

        try:
            check_install = self._run_cmd(["cargo", "audit", "--version"])

            if check_install.returncode != 0:
                result["message"] = "cargo-audit not installed. Install with: cargo install cargo-audit"
                return result

            audit_result = self._run_cmd(["cargo", "audit", "--json"])

            if audit_result.returncode == 0:
                result["message"] = "No cargo vulnerabilities found"
                result["success"] = True
                return result

            if self.dry_run:
                result["message"] = "Would update cargo dependencies"
                result["success"] = True
                return result

            update_result = self._run_cmd(["cargo", "update"])

            if update_result.returncode == 0:
                result["success"] = True
                result["message"] = "Cargo dependencies updated"
                result["fixes_applied"] = 1
            else:
                result["message"] = f"Cargo update failed: {update_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "cargo audit timed out after 120s"
        except FileNotFoundError:
            result["message"] = "cargo not found"

        return result

    def fix_go(self) -> Dict:
        """Fix Go vulnerabilities using govulncheck and go get."""
        print("Checking Go vulnerabilities...")
        result = {"ecosystem": "go", "success": False, "message": "", "fixes_applied": 0}

        try:
            # Try govulncheck first
            vuln_result = self._run_cmd(["govulncheck", "./..."])

            if vuln_result.returncode == 0:
                result["message"] = "No Go vulnerabilities found"
                result["success"] = True
                return result

            if self.dry_run:
                result["message"] = "Would run go get -u to update dependencies"
                result["success"] = True
                return result

            # Update all dependencies
            update_result = self._run_cmd(["go", "get", "-u", "./..."], timeout=180)
            tidy_result = self._run_cmd(["go", "mod", "tidy"])

            if update_result.returncode == 0 and tidy_result.returncode == 0:
                result["success"] = True
                result["message"] = "Go dependencies updated and tidied"
                result["fixes_applied"] = 1
            else:
                result["message"] = f"Go update had issues: {update_result.stderr}"

        except subprocess.TimeoutExpired:
            result["message"] = "Go vulnerability check timed out"
        except FileNotFoundError:
            # govulncheck not installed, fall back to just updating
            try:
                if self.dry_run:
                    result["message"] = "Would run go get -u (govulncheck not installed)"
                    result["success"] = True
                    return result

                update_result = self._run_cmd(["go", "get", "-u", "./..."], timeout=180)
                tidy_result = self._run_cmd(["go", "mod", "tidy"])
                result["success"] = True
                result["message"] = "Go deps updated (install govulncheck for vulnerability scanning)"
                result["fixes_applied"] = 1
            except FileNotFoundError:
                result["message"] = "go not found"

        return result

    def fix_all(self) -> List[Dict]:
        """Fix vulnerabilities for all detected ecosystems."""
        ecosystems = self.detect_ecosystem()

        if not ecosystems:
            print("No supported package managers detected")
            return []

        print(f"Detected ecosystems: {', '.join(ecosystems)}")

        fix_methods = {
            "npm": self.fix_npm,
            "pnpm": self.fix_pnpm,
            "yarn": self.fix_yarn,
            "pip": self.fix_pip,
            "pipenv": self.fix_pipenv,
            "poetry": self.fix_poetry,
            "cargo": self.fix_cargo,
            "go": self.fix_go,
            "maven": lambda: {
                "ecosystem": "maven",
                "success": True,
                "message": "Maven: run 'mvn versions:use-latest-versions'",
                "fixes_applied": 0
            },
        }

        for ecosystem in ecosystems:
            if ecosystem in fix_methods:
                self.results.append(fix_methods[ecosystem]())

        return self.results

    def print_summary(self):
        """Print summary of fixes applied."""
        print("\n" + "=" * 60)
        print("DEPENDENCY FIX SUMMARY")
        print("=" * 60)

        for result in self.results:
            status = "OK" if result["success"] else "FAIL"
            print(f"[{status}] {result['ecosystem']}: {result['message']}")
            if result.get("fixes_applied", 0) > 0:
                print(f"   -> Fixed {result['fixes_applied']} issues")

        print("=" * 60)


SUPPORTED_ECOSYSTEMS = ["npm", "pnpm", "yarn", "pip", "pipenv", "poetry", "cargo", "go", "maven"]


def main():
    parser = argparse.ArgumentParser(description="Apply dependency fixes for security vulnerabilities")
    parser.add_argument("project_path", help="Path to the project directory")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be fixed without applying changes")
    parser.add_argument("--ecosystem", choices=SUPPORTED_ECOSYSTEMS, help="Fix specific ecosystem only")

    args = parser.parse_args()

    fixer = DependencyFixer(args.project_path, dry_run=args.dry_run)

    if args.dry_run:
        print("DRY RUN MODE - No changes will be applied\n")

    if args.ecosystem:
        print(f"Targeting {args.ecosystem} only\n")
        fix_methods = {
            "npm": fixer.fix_npm,
            "pnpm": fixer.fix_pnpm,
            "yarn": fixer.fix_yarn,
            "pip": fixer.fix_pip,
            "pipenv": fixer.fix_pipenv,
            "poetry": fixer.fix_poetry,
            "cargo": fixer.fix_cargo,
            "go": fixer.fix_go,
        }
        if args.ecosystem in fix_methods:
            fixer.results.append(fix_methods[args.ecosystem]())
        else:
            print(f"No automatic fixer for {args.ecosystem}")
    else:
        fixer.fix_all()

    fixer.print_summary()

    if any(not r["success"] for r in fixer.results):
        sys.exit(1)


if __name__ == "__main__":
    main()
