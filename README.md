# KQL Detection Arsenal

**Azure Sentinel / Microsoft 365 Detection Rules Library** — curated KQL queries for threat detection, threat hunting, and security monitoring in Microsoft cloud environments.

## Overview

| Metric | Value |
|---|---|
| **Total Rules** | 5 (MVP) |
| **Tactics Covered** | 4 |
| **Techniques Covered** | 5 |
| **Target Platform** | Microsoft Sentinel (Log Analytics / KQL) |
| **Rule Format** | Standardized KQL with MITRE ATT&CK frontmatter |

## Quick Start

```kql
// Copy any rule directly into Sentinel Log Analytics Workspace
// or deploy as Scheduled Query Rule via ARM / CLI.
```

### Prerequisites

- **Microsoft Sentinel** workspace (or Azure Log Analytics)
- Required log tables per rule (see each rule's `Data Source` header)
- Minimum permissions: `Microsoft.OperationalInsights/workspaces/query/read`

## Rule Index

### Credential Access

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Brute Force RDP](azure-sentinel/credential-access/brute-force-rdp.kql) | T1110 | High | SigninLogs, AADNonInteractiveUserSignInLogs |
| [Kerberoasting Detection](azure-sentinel/credential-access/kerberoasting-detection.kql) | T1558.003 | High | SecurityEvent, IdentityLogonEvents |
| [DCSync Detection](azure-sentinel/credential-access/dcsync-detection.kql) | T1003.006 | Critical | DirectoryServiceAccess, BehaviorAnalytics |

### Execution

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [PowerShell Obfuscation](azure-sentinel/execution/powershell-obfuscation.kql) | T1059.001 | Medium | DeviceProcessEvents (MDE) |

### Persistence

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Scheduled Task Creation](azure-sentinel/persistence/scheduled-task-creation.kql) | T1053.005 | Medium | SecurityEvent, DeviceEvents |

## Rule Format

Every rule follows this structure:

```kql
// === MITRE ATT&CK ===
// Technique: TXXXX.XXX — Description
// Tactic: Tactic Name
// Severity: High / Medium / Low / Critical
// Data Source: TableName (Source)
// False Positives: Known noise sources
// Recommended Response: Step-by-step IR guidance
// === QUERY ===
<kql_query>
```

## Testing

See `mapping/test-cases/` for sample data + expected detection logic:

```bash
python tools/rule-validator.py azure-sentinel/
```

Each test case simulates the relevant table schema with realistic event data and validates query syntax. The test — not a live Sentinel deployment — catches structural errors and schema mismatches before deployment.

## MITRE ATT&CK Coverage

See [ATTACK_MATRIX.md](ATTACK_MATRIX.md) for full tactic/technique mapping.

## Roadmap

### v0.1 — MVP (Current)
- [x] Brute Force RDP Detection (T1110)
- [x] Kerberoasting Detection (T1558.003)
- [x] DCSync Detection (T1003.006)
- [x] PowerShell Obfuscation Detection (T1059.001)
- [x] Scheduled Task Persistence (T1053.005)
- [x] Rule validator tool
- [x] Test harness per rule
- [x] MITRE ATT&CK mapping

### v0.2 — Execution & Defense Evasion
- [ ] LSASS Access / Mimikatz Detection (T1003.001)
- [ ] Process Hollowing Detection (T1055.012)
- [ ] AMSI Bypass Detection (T1562.001)
- [ ] Log Clearing Detection (T1070.001)
- [ ] Registry Run Key Persistence (T1547.001)

### v0.3 — Lateral Movement & Discovery
- [ ] Pass-the-Hash Detection (T1550.002)
- [ ] Remote Service Creation (T1543.003)
- [ ] WMI Execution Detection (T1047)
- [ ] Network Share Discovery (T1135)
- [ ] PsExec Execution Detection (T1570)

### v0.4 — Exfiltration & C2
- [ ] Unusual Outbound Traffic (T1048)
- [ ] DNS Tunneling Anomaly (T1572)
- [ ] Beaconing Pattern Detection (T1071.001)
- [ ] Large File Upload Anomaly (T1030)
- [ ] Data Staging Detection (T1074)

### v0.5 — Cloud-Specific & Kubernetes
- [ ] Azure AD MFA Bypass / Legacy Auth (T1078.004)
- [ ] Suspicious OAuth Consent Grant (T1525.001)
- [ ] Anomalous Service Principal Usage (T1098)
- [ ] Kubernetes Container Escape (T1611)
- [ ] Azure Key Vault Access Anomaly (T1552.005)

### v0.6 — Hunting & Baseline
- [ ] Threat hunting queries module
- [ ] User behavior baseline KQL
- [ ] Unmanaged device access detection
- [ ] Anomalous logon hour analysis
- [ ] Cross-tenant access anomalies

### v0.7 — Tooling & CI
- [ ] `rule-scaffold.py` — generate new rule from template
- [ ] `coverage-report.py` — auto-generate ATT&CK matrix from rules dir
- [ ] `test-simulator.py` — synthetic event generator per table
- [ ] GitHub Actions CI — lint + validate on push
- [ ] ARM template exporter — deploy rules as Sentinel Analytic Rules

### v0.8 — Advanced Features
- [ ] Sentinel Workbook auto-generator (dashboard JSON)
- [ ] `tier-2` directory — correlation rules (multi-event chain detection)
- [ ] `tier-3` directory — fusion / ML anomaly rules
- [ ] Cross-workspace hunting queries
- [ ] Sentinel-as-code (Terraform / Bicep) module

## Deployment

### Manual (Log Analytics)
1. Open Azure Portal → Sentinel → Logs
2. Paste the KQL query
3. Tune time range and thresholds
4. Click **+ New alert rule** → configure frequency / suppression

### Automated (ARM / CLI) — coming in v0.7
```powershell
# Example using az CLI
az deployment group create --resource-group rg-sentinel --template-file deploy-rule.json
```

## Contributing

1. Fork the repository
2. Create a rule following the [format](#rule-format) above
3. Add MITRE mapping to `mapping/mitre-attack.yaml`
4. Add test case with sample data
5. Run `python tools/rule-validator.py`
6. Submit PR

## License

MIT — see [LICENSE](LICENSE).
