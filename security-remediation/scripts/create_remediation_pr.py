#!/usr/bin/env python3
"""
Create pull requests for security remediations.
Supports GitHub and GitLab workflows.
"""

import subprocess
import sys
import json
import argparse
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime


class RemediationPRCreator:
    def __init__(self, project_path: str, branch_name: Optional[str] = None):
        self.project_path = Path(project_path)
        self.branch_name = branch_name or f"security-remediation-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.base_branch = None
        self.changes = []

    def get_current_branch(self) -> str:
        """Get the current git branch name."""
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=self.project_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes."""
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=self.project_path,
            capture_output=True,
            text=True
        )
        return bool(result.stdout.strip())

    def create_branch(self) -> bool:
        """Create a new branch for the remediation."""
        try:
            self.base_branch = self.get_current_branch()
            print(f"Current branch: {self.base_branch}")

            subprocess.run(
                ["git", "checkout", "-b", self.branch_name],
                cwd=self.project_path,
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Created branch: {self.branch_name}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to create branch: {e.stderr}")
            return False

    def commit_changes(self, message: str, files: Optional[List[str]] = None) -> bool:
        """Commit changes with the provided message."""
        try:
            if not self.has_uncommitted_changes():
                print("No changes to commit")
                return False

            # Stage files
            if files:
                for file in files:
                    subprocess.run(
                        ["git", "add", file],
                        cwd=self.project_path,
                        check=True,
                        capture_output=True,
                        text=True
                    )
            else:
                # Use -u (tracked files only) instead of -A to avoid staging secrets
                subprocess.run(
                    ["git", "add", "-u"],
                    cwd=self.project_path,
                    check=True,
                    capture_output=True,
                    text=True
                )

            subprocess.run(
                ["git", "commit", "-m", message],
                cwd=self.project_path,
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Committed changes: {message}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to commit: {e.stderr}")
            return False

    def push_branch(self, force: bool = False) -> bool:
        """Push the branch to remote."""
        try:
            cmd = ["git", "push", "-u", "origin", self.branch_name]
            if force:
                cmd.insert(2, "--force")

            subprocess.run(
                cmd,
                cwd=self.project_path,
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Pushed branch to origin/{self.branch_name}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to push: {e.stderr}")
            return False

    def detect_git_platform(self) -> Optional[str]:
        """Detect if using GitHub or GitLab."""
        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            url = result.stdout.strip()

            if "github.com" in url:
                return "github"
            elif "gitlab.com" in url or "gitlab" in url:
                return "gitlab"
            else:
                return None

        except subprocess.CalledProcessError:
            return None

    def create_github_pr(self, title: str, body: str, labels: Optional[List[str]] = None) -> bool:
        """Create a GitHub pull request using gh CLI."""
        try:
            subprocess.run(
                ["gh", "--version"],
                capture_output=True,
                text=True,
                check=True
            )

            cmd = [
                "gh", "pr", "create",
                "--base", self.base_branch,
                "--head", self.branch_name,
                "--title", title,
                "--body", body
            ]

            if labels:
                cmd.extend(["--label", ",".join(labels)])

            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )

            pr_url = result.stdout.strip()
            print(f"Created GitHub PR: {pr_url}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to create GitHub PR: {e.stderr}")
            print("   Make sure 'gh' CLI is installed and authenticated")
            return False

    def create_gitlab_mr(self, title: str, body: str, labels: Optional[List[str]] = None) -> bool:
        """Create a GitLab merge request using glab CLI."""
        try:
            subprocess.run(
                ["glab", "--version"],
                capture_output=True,
                text=True,
                check=True
            )

            cmd = [
                "glab", "mr", "create",
                "--source-branch", self.branch_name,
                "--target-branch", self.base_branch,
                "--title", title,
                "--description", body
            ]

            if labels:
                cmd.extend(["--label", ",".join(labels)])

            subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )

            print("Created GitLab MR")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to create GitLab MR: {e.stderr}")
            print("   Make sure 'glab' CLI is installed and authenticated")
            return False

    def create_pr(self, title: str, body: str, labels: Optional[List[str]] = None) -> bool:
        """Create a pull request on the detected platform."""
        platform = self.detect_git_platform()

        if platform == "github":
            return self.create_github_pr(title, body, labels)
        elif platform == "gitlab":
            return self.create_gitlab_mr(title, body, labels)
        else:
            print("Could not detect GitHub or GitLab remote")
            print("   PR/MR creation skipped. Branch pushed successfully.")
            print(f"   Create PR manually from branch: {self.branch_name}")
            return False

    def rollback(self):
        """Rollback to the original branch."""
        try:
            subprocess.run(
                ["git", "checkout", self.base_branch],
                cwd=self.project_path,
                check=True,
                capture_output=True,
                text=True
            )
            subprocess.run(
                ["git", "branch", "-D", self.branch_name],
                cwd=self.project_path,
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Rolled back to {self.base_branch}")
        except subprocess.CalledProcessError:
            pass


def load_pr_template(template_path: Optional[str] = None) -> str:
    """Load PR body template."""
    if template_path and Path(template_path).exists():
        return Path(template_path).read_text()

    return """## Security Remediation

### Summary
This PR addresses security vulnerabilities identified in the latest security audit.

### Changes Made
{changes}

### Severity
{severity}

### Testing
- [ ] All tests pass
- [ ] No new vulnerabilities introduced
- [ ] Dependencies updated successfully

### References
- Security Audit Report: {audit_ref}
- OWASP Guidelines: https://owasp.org/

### Checklist
- [ ] Changes reviewed for side effects
- [ ] Documentation updated if needed
- [ ] CI/CD pipeline passes

---
*This PR was generated by the security-remediation skill*
"""


def main():
    parser = argparse.ArgumentParser(description="Create a pull request for security remediations")
    parser.add_argument("project_path", help="Path to the project directory")
    parser.add_argument("--title", default="Security Remediation", help="PR title")
    parser.add_argument("--branch", help="Branch name (auto-generated if not provided)")
    parser.add_argument("--commit-message", help="Commit message")
    parser.add_argument("--body", help="PR body text")
    parser.add_argument("--template", help="Path to PR body template file")
    parser.add_argument("--labels", nargs="+", default=["security", "automated"], help="PR labels")
    parser.add_argument("--files", nargs="+", help="Specific files to commit")
    parser.add_argument("--severity", default="high", choices=["critical", "high", "medium", "low"], help="Issue severity")
    parser.add_argument("--audit-ref", help="Reference to audit report")

    args = parser.parse_args()

    creator = RemediationPRCreator(args.project_path, args.branch)

    print("Starting PR creation workflow\n")

    if not creator.create_branch():
        sys.exit(1)

    commit_msg = args.commit_message or f"fix: security remediation - {args.severity} severity issues"
    if not creator.commit_changes(commit_msg, args.files):
        creator.rollback()
        print("No changes to commit. Exiting.")
        sys.exit(0)

    if not creator.push_branch():
        creator.rollback()
        sys.exit(1)

    if args.body:
        pr_body = args.body
    else:
        template = load_pr_template(args.template)
        pr_body = template.format(
            changes="See commit history for details",
            severity=args.severity.upper(),
            audit_ref=args.audit_ref or "N/A"
        )

    creator.create_pr(args.title, pr_body, args.labels)

    print("\nPR workflow completed successfully")


if __name__ == "__main__":
    main()
