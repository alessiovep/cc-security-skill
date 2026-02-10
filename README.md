# Claude Security Skills

> Security check and fix skills for Claude Code

## What do these skills do?

- **security-check**: Automated security scans using Semgrep, Trivy, and Gitleaks. Categorizes findings by OWASP Top 10 with CWE mapping, normalizes severity levels, and generates JSON/HTML/SARIF reports. Includes 137 custom Semgrep rules across 8 rulesets covering 20+ vulnerability categories and 10+ frameworks.
- **security-fix**: Applies fixes based on check results. Automatic dependency updates, configuration patches, code fixes via Claude's Edit tool, and PR creation. Includes fix patterns for 25+ vulnerability types with before/after code examples.

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

The two skills communicate via a JSON contract (v2.0):

- **Check** produces a JSON report with:
  - `version` -- report schema version
  - `vulnerabilities[]` -- list of findings, each with:
    - `id` -- unique identifier
    - `severity` -- normalized level (CRITICAL, HIGH, MEDIUM, LOW)
    - `cwe` -- CWE identifier (e.g. CWE-79)
    - `owasp_category` -- OWASP Top 10 mapping
    - `fix_type` -- fix type (`auto`, `manual`, `dependency`)
    - `fix_hint` -- instruction or suggestion for the fix

- **Fix** consumes this report and applies fixes based on `fix_type`:
  - `auto` -- configuration patches (security headers, cookies, TLS, JWT, password hashing, etc.)
  - `dependency` -- dependency updates via package managers
  - `manual` -- code fixes via Claude's Edit tool

## Custom Semgrep Rules

**137 rules across 8 rulesets:**

### Language-specific rules

| Ruleset | Language | Rules | Examples |
|---------|----------|-------|----------|
| `python_rules.yaml` | Python | 8 | SQL injection, eval/exec, unsafe YAML, weak random, hardcoded keys |
| `javascript_rules.yaml` | JS/TS | 8 | XSS, command injection, prototype pollution, path traversal |
| `java_rules.yaml` | Java | 20 | SQL injection, XXE, insecure deserialization, weak crypto |
| `go_rules.yaml` | Go | 19 | SQL injection, command injection, insecure TLS, SSRF |

### Framework-specific rules

| Ruleset | Framework | Rules | Examples |
|---------|-----------|-------|----------|
| `react_nextjs_rules.yaml` | React/Next.js/Supabase | 11 | Unsafe HTML rendering, NEXT_PUBLIC secrets, service_role exposure, RLS |
| `framework_rules.yaml` | Express/Django/Flask/Docker/GH Actions | 19 | helmet, csrf_exempt, ALLOWED_HOSTS, Dockerfile root user, expression injection |

### Web security & API rules

| Ruleset | Focus | Rules | Examples |
|---------|-------|-------|----------|
| `web_security_rules.yaml` | Web vulnerabilities | 28 | Security headers, JWT, file upload, mass assignment, SSTI, password hashing |
| `client_api_rules.yaml` | Client-side & API | 24 | postMessage, WebSocket, GraphQL, OAuth, Angular/Vue/Svelte XSS, ReDoS |

### Vulnerability coverage

| Category | OWASP | Category | OWASP |
|----------|-------|----------|-------|
| SQL/NoSQL Injection | A03 | Security Headers | A05 |
| XSS (all variants) | A03 | JWT Security | A07 |
| Command Injection | A03 | File Upload | A04 |
| SSTI | A03 | Mass Assignment | A01 |
| ReDoS | A03 | Password Hashing | A02 |
| Path Traversal | A01 | GraphQL Security | A05 |
| SSRF | A10 | OAuth/Auth | A07 |
| Weak Crypto | A02 | Rate Limiting | A07 |
| Insecure Deserialization | A08 | Misconfiguration | A05 |
| Secrets/Hardcoded Keys | A02 | Client-side (postMessage, WS) | A01 |

## Fix Patterns

The security-fix skill provides automated fix patterns for 25+ vulnerability types:

| Fix | Approach |
|-----|----------|
| Path Traversal | `path.resolve()` + prefix check |
| Open Redirect | URL allowlist validation |
| XXE (Java) | Disallow doctype declaration |
| Weak Crypto | Replace MD5/SHA1/DES with SHA-256/AES-GCM |
| Insecure Random | `secrets` (Python), `SecureRandom` (Java), `crypto.randomBytes` (Node) |
| Unsafe YAML | `yaml.safe_load()` |
| Insecure Cookies | Add secure, httpOnly, sameSite flags |
| SSRF | URL validation + private IP blocking |
| NoSQL Injection | Parameterized queries with `$eq` |
| Security Headers | Helmet (Express), Talisman (Flask), SecurityMiddleware (Django) |
| JWT | Explicit algorithm verification + expiry |
| Mass Assignment | Explicit field allowlists |
| SSTI | Template files instead of string rendering |
| File Upload | MIME validation + size limits + filename sanitization |
| Password Hashing | bcrypt/argon2 instead of MD5/SHA |

## Reporting

| Format | Command | Use case |
|--------|---------|----------|
| **Inline Markdown** | Built-in | Quick overview in terminal |
| **JSON** (v2.0) | `run_security_audit.py` | Machine-readable, input for fix skill |
| **HTML** | `generate_report.py` | Shareable visual report |
| **SARIF** (v2.1.0) | `generate_sarif.py` | GitHub Code Scanning integration |
| **Delta** | `generate_sarif.py --baseline` | PR reviews (NEW/FIXED/EXISTING) |

### False positive management

Create a `.security-ignore` file in the project root:

```
# Format: file:line:rule-id # reason
src/test/mock.py:15:python-eval-usage # Test mock, no user input
config/dev.py:3:python-debug-enabled # Dev config only
```

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
│   │   ├── generate_report.py
│   │   └── generate_sarif.py
│   ├── assets/semgrep_rules/
│   │   ├── python_rules.yaml
│   │   ├── javascript_rules.yaml
│   │   ├── react_nextjs_rules.yaml
│   │   ├── java_rules.yaml
│   │   ├── go_rules.yaml
│   │   ├── web_security_rules.yaml
│   │   ├── framework_rules.yaml
│   │   └── client_api_rules.yaml
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
