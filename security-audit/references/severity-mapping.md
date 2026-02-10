# Severity Mapping

Normalisatie van severity-termen naar een uniform schema.

## Mapping Table

| Tool     | Tool Term  | Normalized | Notes                          |
|----------|-----------|------------|--------------------------------|
| Semgrep  | ERROR     | HIGH       | Semgrep's hoogste niveau       |
| Semgrep  | WARNING   | MEDIUM     |                                |
| Semgrep  | INFO      | LOW        |                                |
| Trivy    | CRITICAL  | CRITICAL   | Directe mapping                |
| Trivy    | HIGH      | HIGH       | Directe mapping                |
| Trivy    | MEDIUM    | MEDIUM     | Directe mapping                |
| Trivy    | LOW       | LOW        | Directe mapping                |
| Gitleaks | (geen)    | HIGH       | Secrets zijn altijd high        |

## Normalisatie Functie

Bij het consolideren van resultaten:
1. Check of de severity al in het genormaliseerde schema zit (CRITICAL/HIGH/MEDIUM/LOW)
2. Zo niet, map via bovenstaande tabel
3. Onbekende waarden -> MEDIUM als fallback
