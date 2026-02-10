---
name: security-check
description: Voer geautomatiseerde security checks uit op codebases. Scant broncode, configuraties en dependencies op kwetsbaarheden met Semgrep, Trivy en Gitleaks. Categoriseert findings per OWASP Top 10 met genormaliseerde severity levels. Gebruik bij security scans, PR reviews, of compliance checks.
---

# Security Check

Je bent een security auditor. Gebruik deze instructies om een codebase systematisch te scannen op kwetsbaarheden en een gestructureerd rapport te produceren.

## Wanneer activeren

Activeer deze skill wanneer de gebruiker:
- Vraagt om een "security audit", "security scan", of "vulnerability scan"
- Vraagt om een codebase te controleren op kwetsbaarheden
- Een PR wil reviewen op security issues
- Vraagt naar OWASP compliance of security posture
- `/security-check` gebruikt als commando

## Stap 1: Project verkennen

Gebruik Glob en Read om het project te begrijpen:

```
Glob: **/{package.json,requirements.txt,go.mod,Cargo.toml,pom.xml,Pipfile,pyproject.toml}
Glob: **/{Dockerfile,docker-compose.yml,.env,.env.example}
Glob: **/*.{py,js,ts,jsx,tsx,java,go,rs}
```

Bepaal op basis van gevonden bestanden:
- **Taal/ecosysteem**: Python, Node.js, Go, Java, Rust, etc.
- **Framework**: Django, Flask, Express, Spring, etc.
- **Beschikbare tools**: Welke scanners zijn geinstalleerd?

## Stap 2: Beschikbare tools checken

Controleer welke tools beschikbaar zijn:

```bash
which semgrep && semgrep --version
which trivy && trivy --version
which gitleaks && gitleaks --version
```

Ga verder met wat beschikbaar is. Geen tool is verplicht.

## Stap 3: Externe scanners draaien

### Semgrep (static analysis)
```bash
semgrep --config=auto --json --severity=ERROR --severity=WARNING <target_path> 2>/dev/null || true
```
Timeout: 300 seconden. Bij custom rules voeg toe: `--config=<skill_path>/assets/semgrep_rules/`

### Trivy (dependency scanning)
```bash
trivy fs --format json --scanners vuln,secret,config <target_path> 2>/dev/null || true
```
Timeout: 300 seconden.

### Gitleaks (secret detection)
```bash
gitleaks detect --source <target_path> --report-format json --report-path /tmp/gitleaks_report.json --no-git 2>/dev/null || true
```
Timeout: 120 seconden.

### Volledig script (alternatief)
```bash
python <skill_path>/scripts/run_security_audit.py <target_path> [output_dir]
```

## Stap 4: Claude-native analyse (altijd uitvoeren)

Ongeacht beschikbare tools, voer eigen analyse uit met Grep:

```
Grep: (eval|exec)\s*\(           -- Code injection
Grep: (SELECT|INSERT|UPDATE|DELETE).*\+\s*    -- SQL string concatenation
Grep: innerHTML\s*=              -- DOM XSS
Grep: password\s*=\s*['"]        -- Hardcoded credentials
Grep: (md5|sha1|DES|RC4)         -- Zwakke cryptografie
Grep: verify\s*=\s*False         -- Disabled TLS verification
Grep: debug\s*[:=]\s*[Tt]rue     -- Debug mode aan
Grep: 0\.0\.0\.0                 -- Luisteren op alle interfaces
Grep: Access-Control-Allow-Origin.*\*  -- CORS wildcard
Grep: CORS.*\*
```

### React / Next.js / Supabase patronen

Bij React/Next.js/Supabase projecten, voeg deze extra Grep patronen toe:

```
Grep: dangerouslySetInnerHTML       -- React unsafe HTML injection
Grep: href.*javascript:             -- JavaScript protocol in JSX links
Grep: service_role                  -- Supabase service_role key exposure
Grep: NEXT_PUBLIC_.*SERVICE\|NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY.*service  -- Secrets in publieke env vars
Grep: \.rpc\(                       -- Supabase RPC calls (controleer input validatie)
Grep: auth\.admin                   -- Supabase admin auth (moet server-side zijn)
Grep: \.from\(.*\)\.\(insert\|update\|delete\|upsert\)  -- Supabase mutaties (controleer RLS)
Grep: createClient.*supabase.*['"]ey  -- Hardcoded Supabase keys
```

Analyseer gevonden patronen in context (lees omringende code) om false positives te filteren.

## Stap 5: Resultaten consolideren

Combineer alle findings in een uniform format. Gebruik deze severity-normalisatie:

| Tool    | Tool Term | Genormaliseerd |
|---------|----------|----------------|
| Semgrep | ERROR    | HIGH           |
| Semgrep | WARNING  | MEDIUM         |
| Semgrep | INFO     | LOW            |
| Trivy   | CRITICAL | CRITICAL       |
| Trivy   | HIGH/MEDIUM/LOW | Directe mapping |
| Gitleaks| (altijd) | HIGH           |

### OWASP categorisatie (prioriteit):
1. Gebruik Semgrep's `extra.metadata.owasp` veld als beschikbaar
2. Gitleaks findings -> altijd A02 (Cryptographic Failures)
3. Trivy dependency findings -> altijd A06 (Vulnerable Components)
4. Fallback: pattern-match op check_id + message

## Stap 6: Rapport presenteren

Presenteer het rapport inline in dit format:

```
## Security Audit Rapport

**Target**: <pad>
**Datum**: <datum>

### Samenvatting
| Severity | Aantal |
|----------|--------|
| CRITICAL | X      |
| HIGH     | X      |
| MEDIUM   | X      |
| LOW      | X      |
| **Totaal** | **X** |

### Bevindingen per OWASP categorie

#### A03:2021 - Injection (X findings)
1. **[HIGH]** SQL injection in `app/models.py:45`
   - Tool: Semgrep
   - Beschrijving: User input direct in SQL query
   - Fix hint: Gebruik parameterized queries

(etc. per categorie)
```

### JSON rapport (optioneel)
Als de gebruiker een bestand wil, gebruik het script:
```bash
python <skill_path>/scripts/run_security_audit.py <target_path>
```
Dit produceert een JSON rapport met het v2.0 schema (zie references/tool-output-schemas.md).

### HTML rapport (optioneel)
```bash
python <skill_path>/scripts/generate_report.py <json_rapport_pad>
```

## Stap 7: Volgende stappen aanbevelen

Na het rapport, stel voor:
- **Bij CRITICAL/HIGH findings**: "Wil je dat ik de kritieke issues fix? Gebruik `/security-fix` of vraag me de fixes direct toe te passen."
- **Bij dependency issues**: "Er zijn X kwetsbare dependencies. Ik kan `npm audit fix` / `pip-audit --fix` draaien."
- **Bij secrets**: "Er zijn hardcoded secrets gevonden. Deze moeten handmatig verwijderd en geroteerd worden."

## JSON Contract (v2.0)

Het audit rapport dat de remediation skill consumeert:

```json
{
  "version": "2.0",
  "scan_date": "ISO8601",
  "target": "/pad",
  "vulnerabilities": [
    {
      "id": "finding-001",
      "tool": "Semgrep|Trivy|Gitleaks",
      "type": "check_id of categorie",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "pad/naar/bestand",
      "line": 45,
      "message": "beschrijving",
      "owasp_category": "A0X:2021 - Naam",
      "fix_type": "auto|manual|dependency",
      "fix_hint": "hoe te fixen"
    }
  ],
  "summary": {
    "total_vulnerabilities": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## Custom Semgrep Rules

Beschikbare regelsets in `assets/semgrep_rules/`:
- `python_rules.yaml` - Python-specifiek (SQL injection, eval, unsafe YAML, weak random)
- `javascript_rules.yaml` - JS/TS (XSS, command injection, prototype pollution)
- `react_nextjs_rules.yaml` - React/Next.js/Supabase (dangerouslySetInnerHTML, service_role exposure, RLS, hardcoded keys)
- `java_rules.yaml` - Java (SQL injection, XXE, insecure deserialization)
- `go_rules.yaml` - Go (SQL injection, insecure TLS, SSRF)

Gebruik met: `semgrep --config=<skill_path>/assets/semgrep_rules/ <target_path>`
