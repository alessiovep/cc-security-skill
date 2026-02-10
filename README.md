# Claude Security Skills

> Security check and fix skills for Claude Code

## What do these skills do?

- **security-check**: Automated security scans using Semgrep, Trivy, and Gitleaks. Categorizes findings by OWASP Top 10, normalizes severity levels, and generates JSON/HTML reports. Includes framework-specific rules for React, Next.js, and Supabase.
- **security-fix**: Applies fixes based on check results. Automatic dependency updates, configuration patches, code fixes via Claude's Edit tool, and PR creation. Includes fix patterns for React XSS, Supabase service_role misuse, NEXT_PUBLIC_ secrets, and RLS configuration.

## Installation

```bash
# Clone the repository
git clone https://github.com/alessiovep/cc-security-skill.git

# Copy skills to Claude Code
cp -r cc-security-skill/security-check ~/.claude/skills/
cp -r cc-security-skill/security-fix ~/.claude/skills/
```

## Prerequisites

| Tool | Purpose | Installation |
|------|---------|--------------|
| Semgrep | Static analysis | `pip install semgrep` |
| Trivy | Dependency scanning | `brew install trivy` |
| Gitleaks | Secret detection | `brew install gitleaks` |
| gh CLI | PR creation (GitHub) | `brew install gh` |
| pip-audit | Python deps | `pip install pip-audit` |

> **Note:** None of the tools are required. The skills work with whatever is available and fall back to Claude's own analysis.

## Usage

Examples of commands and phrases you can use:

- "Run a security check on this project"
- "Scan this codebase for vulnerabilities"
- "Fix the critical findings from the last check"
- "Create a PR with the security fixes"
- `/security-check` and `/security-fix` as slash commands

## Architecture

The two skills communicate via a JSON contract:

- **Check** produces a JSON report with:
  - `version` -- report schema version
  - `vulnerabilities[]` -- list of findings, each with:
    - `id` -- unique identifier
    - `severity` -- normalized level (CRITICAL, HIGH, MEDIUM, LOW)
    - `fix_type` -- fix type (`auto`, `manual`, `dependency`)
    - `fix_hint` -- instruction or suggestion for the fix

- **Fix** consumes this report and applies fixes based on `fix_type`:
  - `auto` -- configuration patches
  - `dependency` -- dependency updates via package managers
  - `manual` -- code fixes via Claude's Edit tool

## Custom Semgrep Rules

| Ruleset | Language/Framework | Rules | Examples |
|---------|-------------------|-------|----------|
| `python_rules.yaml` | Python | 4 | SQL injection, eval, unsafe YAML, weak random |
| `javascript_rules.yaml` | JS/TS | 8 | XSS, command injection, prototype pollution, path traversal |
| `react_nextjs_rules.yaml` | React/Next.js/Supabase | 11 | Unsafe innerHTML, service_role exposure, RLS, hardcoded keys |
| `java_rules.yaml` | Java | 4 | SQL injection, XXE, insecure deserialization |
| `go_rules.yaml` | Go | 5 | SQL injection, insecure TLS, SSRF |

The React/Next.js/Supabase ruleset covers:
- **React**: Unsafe inner HTML injection, javascript: protocol URLs, target="_blank" without noopener
- **Next.js**: Secrets in NEXT_PUBLIC_ env vars, API routes without auth, unsanitized query params
- **Supabase**: service_role client-side exposure, RPC injection, admin auth misuse, hardcoded keys, mutations without RLS

## Structure

```
cc-security-skill/
├── README.md
├── LICENSE
├── .gitignore
├── security-check/
│   ├── SKILL.md
│   ├── scripts/
│   │   ├── run_security_audit.py
│   │   └── generate_report.py
│   ├── assets/semgrep_rules/
│   │   ├── python_rules.yaml
│   │   ├── javascript_rules.yaml
│   │   ├── react_nextjs_rules.yaml
│   │   ├── java_rules.yaml
│   │   └── go_rules.yaml
│   └── references/
│       ├── severity-mapping.md
│       └── tool-output-schemas.md
└── security-fix/
    ├── SKILL.md
    ├── scripts/
    │   ├── apply_dependency_fixes.py
    │   ├── apply_config_fix.py
    │   └── create_remediation_pr.py
    └── assets/
        ├── pr-template.md
        └── commit-message-template.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit with a clear description
4. Open a Pull Request
