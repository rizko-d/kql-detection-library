# KQL Detection Library

**Azure Sentinel / Microsoft 365 Detection Rules Library** — curated KQL queries for threat detection, threat hunting, and security monitoring in Microsoft cloud environments.

[![GitHub stars](https://img.shields.io/github/stars/rizko-d/kql-detection-library?style=flat-square)](https://github.com/rizko-d/kql-detection-library/stargazers)
[![GitHub license](https://img.shields.io/github/license/rizko-d/kql-detection-library?style=flat-square)](https://github.com/rizko-d/kql-detection-library/blob/main/LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15.1-red?style=flat-square)](https://attack.mitre.org/)

---

## Overview

A standardized, production-ready library of KQL detection rules for **Microsoft Sentinel** and **Azure Log Analytics**. Every rule includes:

- **MITRE ATT&CK mapping** — technique ID, tactic, and severity
- **False positive guidance** — known noise sources and tuning tips
- **Incident response steps** — actionable triage and remediation
- **Test harness** — synthetic event data to validate detection logic

| Metric | Value |
|---|---|
| Current Rules | 20 |
| Tactics Covered | 6 of 14 |
| Techniques | 18 (v0.1, v0.2 complete + v0.3 partial) |
| Target Platform | Microsoft Sentinel / Log Analytics |
| Rule Format | Standardized KQL with MITRE ATT&CK frontmatter |

## Quick Start

```kql
// Copy any rule directly into Sentinel Log Analytics Workspace
// Example — paste and run:
```

```kql
// Brute Force RDP Detection
// https://github.com/rizko-d/kql-detection-library
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType in ("50053", "50057", "50126")
...
```

## Rules

### Credential Access

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Brute Force RDP](azure-sentinel/credential-access/brute-force-rdp.kql) | T1110 | High | SigninLogs |
| [Kerberoasting Detection](azure-sentinel/credential-access/kerberoasting-detection.kql) | T1558.003 | High | SecurityEvent 4769 |
| [DCSync Detection](azure-sentinel/credential-access/dcsync-detection.kql) | T1003.006 | Critical | DirectoryServiceAccess |

### Execution

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [PowerShell Obfuscation](azure-sentinel/execution/powershell-obfuscation.kql) | T1059.001 | Medium | DeviceProcessEvents (MDE) |

### Persistence

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Scheduled Task Creation](azure-sentinel/persistence/scheduled-task-creation.kql) | T1053.005 | Medium | SecurityEvent 4698 |

## Roadmap

Planned expansion to **~70 rules** across:
- **v0.2** — Execution & Defense Evasion (+10 rules)
- **v0.3** — Lateral Movement & Discovery (+10)
- **v0.4** — Exfiltration & C2 (+10)
- **v0.5** — Cloud & Kubernetes (+10)
- **v0.6** — Threat Hunting (+10 queries)
- **v0.7** — Tooling & CI (+8 tools)
- **v0.8** — Advanced Features (+8 features)

## Tools

[`tools/rule-validator.py`](tools/rule-validator.py) — zero-dependency Python validator that checks every rule for:
- MITRE ATT&CK header completeness (Technique, Tactic, Severity, Data Source, False Positives, Recommended Response)
- KQL bracket/quote pairing
- File naming conventions
- Query structure

```bash
python tools/rule-validator.py azure-sentinel/
```

## Deployment

### Manual
1. Open Azure Portal → Sentinel → Logs
2. Paste the KQL query
3. Click **+ New alert rule** → configure frequency / suppression

### Automated (coming in v0.7)
ARM templates and Terraform modules for deploying rules as Sentinel Analytic Rules.

## Contributing

Contributions welcome! See the [main repository](https://github.com/rizko-d/kql-detection-library) for details.

1. Follow the rule format with MITRE ATT&CK frontmatter
2. Add a test case with synthetic event data
3. Run `python tools/rule-validator.py`
4. Submit a PR

---

**Author:** Rizko Febri Rachmayadi

*Detection Engineering · Threat Hunting · Security Operations*
