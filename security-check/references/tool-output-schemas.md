# Tool Output Schemas

Referentie voor de JSON-structuur die elke scanner produceert.

## Semgrep

```json
{
  "results": [
    {
      "check_id": "rule-id",
      "path": "file.py",
      "start": {"line": 10, "col": 1},
      "end": {"line": 10, "col": 50},
      "extra": {
        "severity": "ERROR|WARNING|INFO",
        "message": "Description",
        "metadata": {
          "owasp": "A03:2021 - Injection",
          "category": "security"
        }
      }
    }
  ]
}
```

## Trivy

```json
{
  "Results": [
    {
      "Target": "package-lock.json",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-xxxx",
          "PkgName": "lodash",
          "Severity": "CRITICAL|HIGH|MEDIUM|LOW",
          "Title": "Description"
        }
      ]
    }
  ]
}
```

## Gitleaks

Array van findings (top-level is een JSON array):

```json
[
  {
    "Description": "Generic API Key",
    "File": "config.py",
    "StartLine": 15,
    "EndLine": 15,
    "Match": "sk-...",
    "Secret": "sk-...",
    "RuleID": "generic-api-key"
  }
]
```

## Geconsolideerd Audit Rapport (output van run_security_audit.py)

```json
{
  "version": "2.0",
  "scan_date": "ISO8601",
  "target": "/path",
  "vulnerabilities": [
    {
      "id": "finding-001",
      "tool": "Semgrep|Trivy|Gitleaks",
      "type": "check_id or category",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "path",
      "line": 0,
      "message": "description",
      "owasp_category": "A0X:2021 - Name",
      "fix_type": "auto|manual|dependency",
      "fix_hint": "description of how to fix"
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
