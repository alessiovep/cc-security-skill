# Claude Security Skills

> Security audit en remediation skills voor Claude Code

## Wat doen deze skills?

- **security-audit**: Geautomatiseerde security scans met Semgrep, Trivy en Gitleaks. Categoriseert findings per OWASP Top 10, normaliseert severity levels, en genereert JSON/HTML rapporten.
- **security-remediation**: Past fixes toe op basis van audit-resultaten. Automatische dependency updates, configuratie-fixes, code-patches via Claude's Edit tool, en PR-creatie.

## Installatie

```bash
# Clone de repository
git clone https://github.com/YOUR-USERNAME/claude-security-skill.git

# Kopieer skills naar Claude Code
cp -r claude-security-skill/security-audit ~/.claude/skills/
cp -r claude-security-skill/security-remediation ~/.claude/skills/
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

- "Voer een security audit uit op dit project"
- "Scan deze codebase op kwetsbaarheden"
- "Fix de kritieke bevindingen uit de laatste audit"
- "Maak een PR met de security fixes"
- `/security-audit` en `/security-remediation` als slash commands

## Architectuur

De twee skills communiceren via een JSON-contract:

- **Audit** produceert een JSON-rapport met:
  - `version` -- schemaversie van het rapport
  - `findings[]` -- lijst van bevindingen, elk met:
    - `id` -- unieke identifier
    - `severity` -- genormaliseerd level (critical, high, medium, low)
    - `fix_type` -- type fix (`auto`, `manual`, `dependency`)
    - `fix_hint` -- instructie of suggestie voor de fix

- **Remediation** consumeert dit rapport en past fixes toe op basis van `fix_type`:
  - `auto` -- automatische code-patches via Claude's Edit tool
  - `dependency` -- dependency updates via package managers
  - `manual` -- handmatige instructies voor de ontwikkelaar

## Structuur

```
claude-security-skill/
├── .gitignore
├── LICENSE
├── README.md
├── security-audit/
│   ├── SKILLS.md
│   ├── scripts/
│   │   ├── run_semgrep.sh
│   │   ├── run_trivy.sh
│   │   ├── run_gitleaks.sh
│   │   └── normalize_findings.py
│   ├── assets/
│   │   └── semgrep_rules/
│   │       └── custom_rules.yaml
│   └── references/
│       └── owasp_mapping.json
└── security-remediation/
    └── SKILLS.md
```

## Bijdragen

1. Fork de repository
2. Maak een feature branch (`git checkout -b feature/mijn-feature`)
3. Commit met een duidelijke beschrijving (`git commit -m "Voeg feature X toe"`)
4. Push naar je branch (`git push origin feature/mijn-feature`)
5. Open een Pull Request
