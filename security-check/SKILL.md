---
name: security-check
description: Security audit en vulnerability scan skill (SAST/SCA). Voert geautomatiseerde security checks en code reviews uit op codebases. Scant broncode, configuraties en dependencies op kwetsbaarheden met Semgrep, Trivy en Gitleaks. Categoriseert findings per OWASP Top 10 met genormaliseerde severity levels. Gebruik bij security scans, PR reviews, of compliance checks.
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

### Security Headers & Middleware patronen

```
Grep: helmet                     -- Express.js security headers (moet aanwezig zijn)
Grep: SecurityMiddleware         -- Django security middleware
Grep: Talisman                   -- Flask security headers
Grep: Content-Security-Policy    -- CSP header configuratie
Grep: Strict-Transport-Security  -- HSTS header
Grep: X-Frame-Options            -- Clickjacking bescherming
```

### JWT & Authenticatie patronen

```
Grep: jsonwebtoken|jose|PyJWT    -- JWT libraries in gebruik
Grep: algorithm.*none            -- JWT algorithm:none aanval
Grep: expiresIn|exp              -- JWT expiry (moet aanwezig zijn)
Grep: express-rate-limit|flask-limiter|ratelimit  -- Rate limiting (moet aanwezig zijn op auth endpoints)
```

### File Upload & Input patronen

```
Grep: multer|formidable|busboy   -- Node.js file upload libraries
Grep: FileStorage|werkzeug       -- Python file upload
Grep: MultipartFile              -- Java file upload
Grep: (zod|joi|yup|pydantic)     -- Input validatie schemas (moet aanwezig zijn)
```

### GraphQL patronen

```
Grep: introspection              -- GraphQL introspection (moet disabled zijn in productie)
Grep: depthLimit|complexityLimit -- GraphQL query depth limiet (moet aanwezig zijn)
Grep: graphql.*batch             -- GraphQL batching attacks
```

### Client-side Security patronen

```
Grep: addEventListener.*message  -- postMessage handler (controleer origin validatie)
Grep: postMessage\(.*\*          -- postMessage met wildcard target origin
Grep: localStorage.*token|sessionStorage.*token  -- Sensitive data in browser storage
Grep: new WebSocket\(.*ws://     -- Onveilige WebSocket (moet wss:// zijn)
```

### Framework-specifieke patronen

```
Grep: csrf_exempt                -- Django CSRF uitgeschakeld
Grep: ALLOWED_HOSTS.*\*          -- Django wildcard hosts
Grep: mark_safe                  -- Django XSS via mark_safe
Grep: render_template_string     -- Flask SSTI vector
Grep: v-html                     -- Vue.js XSS vector
Grep: bypassSecurityTrust        -- Angular security bypass
Grep: \{@html                    -- Svelte XSS vector
```

### React / Next.js / Supabase patronen

Bij React/Next.js/Supabase projecten, voeg deze extra Grep patronen toe:

```
Grep: dangerouslySetInner        -- React unsafe HTML injection
Grep: href.*javascript:          -- JavaScript protocol in JSX links
Grep: service_role               -- Supabase service_role key exposure
Grep: NEXT_PUBLIC_.*SERVICE\|NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY.*service  -- Secrets in publieke env vars
Grep: \.rpc\(                    -- Supabase RPC calls (controleer input validatie)
Grep: auth\.admin                -- Supabase admin auth (moet server-side zijn)
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

## Stap 6: Rapport genereren en openen

### 6a: JSON rapport genereren

Genereer altijd een JSON rapport. Bij gebruik van het volledige script:
```bash
python <skill_path>/scripts/run_security_audit.py <target_path> ./security_reports
```
Dit produceert een JSON rapport met het v2.0 schema (zie `references/tool-output-schemas.md`) in `./security_reports/`.

Bij alleen Claude-native analyse: schrijf het JSON rapport handmatig naar `./security_reports/security_audit_<datum>.json` volgens het v2.0 schema.

### 6b: HTML rapport genereren en openen

Genereer een visueel HTML rapport en open het in de browser:
```bash
python <skill_path>/scripts/generate_report.py <json_rapport_pad> ./security_reports/security_audit.html
open ./security_reports/security_audit.html
```

### 6c: Terminal samenvatting

Toon een beknopte samenvatting in de terminal (niet de volledige bevindingen lijst):

```
## Security Audit Samenvatting

| Severity | Aantal |
|----------|--------|
| CRITICAL | X      |
| HIGH     | X      |
| MEDIUM   | X      |
| LOW      | X      |
| **Totaal** | **X** |

Volledig rapport: `./security_reports/security_audit.html`

Gebruik `/security-fix` om gevonden kwetsbaarheden automatisch te fixen.
```

### SARIF rapport (voor CI/CD integratie)
```bash
python <skill_path>/scripts/generate_sarif.py <json_rapport_pad> [--output sarif_output.json]
```
Dit produceert een SARIF v2.1.0 rapport dat geupload kan worden naar GitHub Code Scanning:
```bash
gh api repos/{owner}/{repo}/code-scanning/sarifs -X POST -F "sarif=@sarif_output.json"
```

### Delta reporting (voor PR reviews)
```bash
python <skill_path>/scripts/generate_sarif.py <json_rapport_pad> --baseline <vorig_rapport.json> [--output delta.json]
```
Dit vergelijkt het huidige rapport met een baseline en markeert findings als NEW, FIXED, of EXISTING. Ideaal voor PR reviews waar alleen nieuwe issues relevant zijn.

### False positive management
Maak een `.security-ignore` bestand in de project root om bekende false positives te filteren:
```
# Formaat: file:line:rule-id # reden
src/test/mock.py:15:python-eval-usage # Test mock, geen user input
config/dev.py:3:python-debug-enabled # Alleen dev configuratie
```
Het script filtert deze findings automatisch uit het rapport en rapporteert het aantal genegeerde findings apart.

## Stap 7: Volgende stappen aanbevelen

Na het rapport, stel voor:
- **Bij CRITICAL/HIGH findings**: "Wil je dat ik de kritieke issues fix? Gebruik `/security-fix` of vraag me de fixes direct toe te passen."
- **Bij dependency issues**: "Er zijn X kwetsbare dependencies. Ik kan `npm audit fix` / `pip-audit --fix` draaien."
- **Bij secrets**: "Er zijn hardcoded secrets gevonden. Deze moeten handmatig verwijderd en geroteerd worden."

## Custom Semgrep Rules

137 regels over 8 bestanden in `assets/semgrep_rules/`. Dekken: SQL/NoSQL injection, XSS, command injection, SSTI, security headers, JWT, file upload, mass assignment, password hashing, GraphQL, client-side security, OAuth, weak crypto, insecure deserialization, SSRF, path traversal, rate limiting, ReDoS, secrets, en misconfiguratie.

Gebruik met: `semgrep --config=<skill_path>/assets/semgrep_rules/ <target_path>`
