# Claude Security Skills

> Security check en fix skills voor Claude Code

## Wat doen deze skills?

- **security-check**: Geautomatiseerde security scans met Semgrep, Trivy en Gitleaks. Categoriseert findings per OWASP Top 10, normaliseert severity levels, en genereert JSON/HTML rapporten. Bevat framework-specifieke regels voor React, Next.js en Supabase.
- **security-fix**: Past fixes toe op basis van check-resultaten. Automatische dependency updates, configuratie-fixes, code-patches via Claude's Edit tool, en PR-creatie. Inclusief fix-patronen voor React XSS, Supabase service_role misuse, NEXT_PUBLIC_ secrets en RLS configuratie.

## Installatie

```bash
# Clone de repository
git clone https://github.com/alessiovep/cc-security-skill.git

# Kopieer skills naar Claude Code
cp -r cc-security-skill/security-check ~/.claude/skills/
cp -r cc-security-skill/security-fix ~/.claude/skills/
```

## Prerequisites

| Tool | Doel | Installatie |
|------|------|-------------|
| Semgrep | Static analysis | `pip install semgrep` |
| Trivy | Dependency scanning | `brew install trivy` |
| Gitleaks | Secret detection | `brew install gitleaks` |
| gh CLI | PR creatie (GitHub) | `brew install gh` |
| pip-audit | Python deps | `pip install pip-audit` |

> **Note:** Geen van de tools is verplicht. De skills werken met wat beschikbaar is en vallen terug op Claude's eigen analyse.

## Gebruik

Voorbeelden van commando's en zinnen die je kunt gebruiken:

- "Voer een security check uit op dit project"
- "Scan deze codebase op kwetsbaarheden"
- "Fix de kritieke bevindingen uit de laatste check"
- "Maak een PR met de security fixes"
- `/security-check` en `/security-fix` als slash commands

## Architectuur

De twee skills communiceren via een JSON-contract:

- **Check** produceert een JSON-rapport met:
  - `version` -- schemaversie van het rapport
  - `vulnerabilities[]` -- lijst van bevindingen, elk met:
    - `id` -- unieke identifier
    - `severity` -- genormaliseerd level (CRITICAL, HIGH, MEDIUM, LOW)
    - `fix_type` -- type fix (`auto`, `manual`, `dependency`)
    - `fix_hint` -- instructie of suggestie voor de fix

- **Fix** consumeert dit rapport en past fixes toe op basis van `fix_type`:
  - `auto` -- configuratie-patches
  - `dependency` -- dependency updates via package managers
  - `manual` -- code fixes via Claude's Edit tool

## Custom Semgrep Rules

| Regelset | Taal/Framework | Rules | Voorbeelden |
|----------|---------------|-------|-------------|
| `python_rules.yaml` | Python | 4 | SQL injection, eval, unsafe YAML, weak random |
| `javascript_rules.yaml` | JS/TS | 8 | XSS, command injection, prototype pollution, path traversal |
| `react_nextjs_rules.yaml` | React/Next.js/Supabase | 11 | Unsafe innerHTML, service_role exposure, RLS, hardcoded keys |
| `java_rules.yaml` | Java | 4 | SQL injection, XXE, insecure deserialization |
| `go_rules.yaml` | Go | 5 | SQL injection, insecure TLS, SSRF |

De React/Next.js/Supabase regelset dekt:
- **React**: Unsafe inner HTML injection, javascript: protocol URLs, target="_blank" zonder noopener
- **Next.js**: Secrets in NEXT_PUBLIC_ env vars, API routes zonder auth, unsanitized query params
- **Supabase**: service_role client-side exposure, RPC injection, admin auth misuse, hardcoded keys, mutaties zonder RLS

## Structuur

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

## Bijdragen

1. Fork de repository
2. Maak een feature branch (`git checkout -b feature/mijn-feature`)
3. Commit met een duidelijke beschrijving
4. Open een Pull Request
