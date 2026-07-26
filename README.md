# KQL Detection Library

**Azure Sentinel / Microsoft 365 Detection Rules Library** — curated KQL queries for threat detection, threat hunting, and security monitoring in Microsoft cloud environments.

## Overview

| Metric | Value |
|---|---|
| **Total Rules** | 25 (current) — see [Roadmap](#roadmap) for planned additions up to ~70 |
| **Tactics Covered** | 6 of 14 |
| **Techniques Covered** | 25 of ~200 |
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
| [LSASS Memory Access](azure-sentinel/credential-access/lsass-memory-access.kql) | T1003.001 | Critical | DeviceEvents, SecurityEvent (4663/4656) |

### Execution

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [PowerShell Obfuscation](azure-sentinel/execution/powershell-obfuscation.kql) | T1059.001 | Medium | DeviceProcessEvents (MDE) |

### Defense Evasion

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [AMSI Bypass](azure-sentinel/defense-evasion/amsi-bypass.kql) | T1562.001 | High | DeviceProcessEvents, DeviceRegistryEvents |
| [Process Hollowing](azure-sentinel/defense-evasion/process-hollowing.kql) | T1055.012 | High | DeviceProcessEvents (MDE) |
| [Log Clearing](azure-sentinel/defense-evasion/log-clearing.kql) | T1070.001 | High | SecurityEvent (1102), DeviceProcessEvents |
| [DLL Search Order Hijacking](azure-sentinel/defense-evasion/dll-search-order-hijacking.kql) | T1574.001 | Medium/High | DeviceImageLoadEvents (MDE) |

### Persistence

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Scheduled Task Creation](azure-sentinel/persistence/scheduled-task-creation.kql) | T1053.005 | Medium | SecurityEvent, DeviceEvents |
| [Registry Run Key](azure-sentinel/persistence/registry-run-key.kql) | T1547.001 | Medium/High | DeviceRegistryEvents (MDE) |
| [WMI Event Subscription](azure-sentinel/persistence/wmi-event-subscription.kql) | T1546.003 | Medium/High | SecurityEvent (5861), DeviceEvents |
| [Startup Folder](azure-sentinel/persistence/startup-folder.kql) | T1547.001 | Medium/High | DeviceFileEvents (MDE) |
| [BITS Jobs](azure-sentinel/persistence/bits-jobs.kql) | T1197 | Medium/High | DeviceProcessEvents (MDE) |
| [Service Installation](azure-sentinel/persistence/service-installation.kql) | T1543.003 | Medium/High | SecurityEvent (7045/4697), DeviceProcessEvents |

### Lateral Movement

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Pass-the-Hash](azure-sentinel/lateral-movement/pass-the-hash.kql) | T1550.002 | High | SecurityEvent (4624), DeviceLogonEvents |
| [WMI Execution](azure-sentinel/lateral-movement/wmi-execution.kql) | T1047 | Medium/High | DeviceProcessEvents (MDE) |
| [PsExec / SMB Execution](azure-sentinel/lateral-movement/psexec-smb-execution.kql) | T1570 | High | SecurityEvent (7045/5145), DeviceProcessEvents |
| [RDP Lateral Movement](azure-sentinel/lateral-movement/rdp-lateral-movement.kql) | T1021.001 | Medium | SecurityEvent (4624), DeviceLogonEvents |
| [Remote Service Creation](azure-sentinel/lateral-movement/remote-service-creation.kql) | T1543.003 | High | SecurityEvent (4697/7045), DeviceProcessEvents |
| [DCOM Lateral Movement](azure-sentinel/lateral-movement/dcom-lateral-movement.kql) | T1021.003 | High | DeviceProcessEvents (MDE) |
| [WinRM / PowerShell Remoting](azure-sentinel/lateral-movement/winrm-powershell-remoting.kql) | T1021.006 | High | DeviceProcessEvents (MDE) |
| [SMB Named Pipe Impersonation](azure-sentinel/lateral-movement/smb-named-pipe-impersonation.kql) | T1550.003 | High | SecurityEvent (5145) |

### Discovery

| Rule | Technique | Severity | Data Source |
|---|---|---|---|
| [Network Share Discovery](azure-sentinel/discovery/network-share-discovery.kql) | T1135 | Low/Medium | DeviceProcessEvents (MDE) |
| [Active Directory Discovery](azure-sentinel/discovery/active-directory-discovery.kql) | T1087.002 | Medium/High | DeviceProcessEvents (MDE) |

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

### v0.2 — Execution & Defense Evasion (+10 rules) ✅ COMPLETE
- [x] **LSASS Access / Mimikatz Detection** (T1003.001) — ProcessAccess via lsass.exe, Event 4663
- [x] **AMSI Bypass Detection** (T1562.001) — AmsiScanBuffer patching, registry disable
- [x] **Process Hollowing Detection** (T1055.012) — Unbacked memory + suspended thread in trusted binaries
- [x] **Log Clearing Detection** (T1070.001) — Event 1102 (Security log cleared), wevtutil /auditpol
- [x] **Registry Run Key Persistence** (T1547.001) — CurrentVersion\Run modifications (Event 4657)
- [x] **WMI Event Subscription Persistence** (T1546.003) — \_\_EventFilter / \_\_FilterToConsumerBinding (Event 5861)
- [x] **Startup Folder Persistence** (T1547.001) — LNK creation in StartUp folders
- [x] **DLL Search Order Hijacking** (T1574.001) — DLL loads from user-writable paths
- [x] **BITS Jobs Persistence** (T1197) — Background Intelligent Transfer Service job creation
- [x] **Service Installation Detection** (T1543.003) — New service creation (Event 4697) from non-admin

### v0.3 — Lateral Movement & Discovery (+10 rules) ✅ COMPLETE
- [x] **Pass-the-Hash Detection** (T1550.002) — NTLM logon type 3 anomalies
- [x] **Remote Service Creation** (T1543.003) — sc.exe / PowerShell New-Service from remote
- [x] **WMI Execution Detection** (T1047) — wmic process call create, Invoke-CimMethod
- [x] **PsExec / SMB Execution** (T1570) — PSEXESVC service + named pipe \psexecsvc
- [x] **Network Share Discovery** (T1135) — net view / net share enumeration bursts
- [x] **DCOM Lateral Movement** (T1021.003) — MMC20.Application, ShellWindows, Excel DCOM
- [x] **WinRM / PowerShell Remoting** (T1021.006) — WinRM service access, PS session creation
- [x] **RDP Lateral Movement** (T1021.001) — Successful RDP logon from non-admin workstation
- [x] **SMB Named Pipe Impersonation** (T1550.003) — \\pipe\\\* access after SMB session
- [x] **Active Directory Discovery** (T1087.002) — BloodHound / AD enumeration tools (adfind, sharphound)

### v0.4 — Exfiltration & C2 (+10 rules)
- [ ] **Unusual Outbound Traffic** (T1048) — Egress volume anomaly from non-web servers
- [ ] **DNS Tunneling Anomaly** (T1572) — High-entropy subdomains, TXT query bursts
- [ ] **Beaconing Pattern Detection** (T1071.001) — Periodic HTTP/HTTPS connection interval analysis
- [ ] **Large File Upload Anomaly** (T1030) — File uploads > 100MB via web / cloud storage
- [ ] **Data Staging Detection** (T1074) — Archive creation (zip/rar/7z) on sensitive shares
- [ ] **C2 Over WebSocket** (T1071.001) — Long-lived WebSocket connections to rare domains
- [ ] **C2 Over HTTPS (JA3/S)** — JA3 hash clustering for known C2 frameworks
- [ ] **Cloud Storage Exfiltration** (T1567.002) — Files uploaded to personal cloud (Dropbox, GDrive)
- [ ] **Email Forwarding Exfiltration** (T1114.003) — Auto-forwarding rule creation to external domain
- [ ] **ICMP / Custom Protocol Tunneling** (T1571) — Non-DNS/HTTP outbound protocol anomalies

### v0.5 — Cloud-Specific & Kubernetes (+10 rules)
- [ ] **Azure AD MFA Bypass / Legacy Auth** (T1078.004) — Legacy protocol auth, no MFA conditional access
- [ ] **Suspicious OAuth Consent Grant** (T1525.001) — Third-party app consent with high permissions
- [ ] **Anomalous Service Principal Usage** (T1098) — New SPN / client secret outside business hours
- [ ] **Container Escape Detection** (T1611) — --privileged flag, host mount, --pid=host
- [ ] **Azure Key Vault Access Anomaly** (T1552.005) — Secret access from unexpected IP / region
- [ ] **Kubernetes RBAC Abuse** (T1087.004) — ClusterRole escalation, secret enumeration via API
- [ ] **Azure VM Run Command Abuse** (T1059.009) — RunCommand / Invoke-AzVMRunCommand
- [ ] **Blob Storage Public Access** (T1530) — Anonymous blob enumeration, storage account misconfig
- [ ] **Azure Resource Deletion** (T1485) — Bulk resource group / NSG deletion within minutes
- [ ] **Azure Logic App / Automation Account Abuse** (T1053.006) — Suspicious runbook/job creation

### v0.6 — Hunting & Baseline (+10 queries)
- [ ] **Threat Hunting Queries Module** — `hunting-queries/` directory
- [ ] **User Behavior Baseline KQL** — Historical logon hours, geolocation, device count
- [ ] **Unmanaged Device Access Detection** — Device compliance check + Conditional Access bypass
- [ ] **Anomalous Logon Hour Analysis** — First-time logon at 3 AM for a given user
- [ ] **Cross-Tenant Access Anomalies** — B2B guest account enumeration
- [ ] **Service Account Interactive Logon** — Service accounts should never have interactive sessions
- [ ] **Pass-the-Hash Hunting** — RC4 NTLM logon across non-DC hosts
- [ ] **Golden Ticket Hunting** — Kerberos ticket lifetime > 10 hours (Event 4768/4769 anomalies)
- [ ] **Mailbox Access Anomalies** — Mailbox accessed via EWS/Graph API from unknown IP
- [ ] **Identity Protection Insights** — Azure AD Identity Protection risk detections aggregated

### v0.7 — Tooling & CI
- [ ] **`rule-scaffold.py`** — Generate new rule from template with auto-frontmatter
- [ ] **`coverage-report.py`** — Auto-generate ATT&CK matrix markdown from rules directory
- [ ] **`test-simulator.py`** — Synthetic event generator per table schema
- [ ] **GitHub Actions CI** — Run `rule-validator.py` on every push + PR
- [ ] **ARM Template Exporter** — Deploy rules as Sentinel Analytic Rules via ARM/Bicep
- [ ] **Sentinel-as-code (Terraform)** — Terraform module for `azurerm_sentinel_alert_rule`
- [ ] **Rule Dependency Checker** — Cross-ref table references between rules and available data connectors
- [ ] **False-Positive Test Dashboard** — KQL that quantifies FP rate per rule on historical data

### v0.8 — Advanced Features
- [ ] **Sentinel Workbook Generator** — Auto-create Azure Workbook JSON from ruleset
- [ ] **Tier-2: Correlation Rules** — Multi-event chain detection (e.g., user gets RDP → creates task → dumps LSASS)
- [ ] **Tier-3: ML / Fusion Anomalies** — Time-series anomaly detection rules
- [ ] **Cross-Workspace Hunting** — KQL queries spanning multiple Sentinel workspaces
- [ ] **Watchlist Integration** — Dynamic allowlisting via Sentinel watchlists (corporate IP ranges, known-good hashes)
- [ ] **KQL Unit Test Framework** — Automated `datatable`-based tests that assert expected results
- [ ] **MITRE ATT&CK Navigator Layer** — Export rules as ATT&CK Navigator heatmap JSON
- [ ] **Multi-Language Rule Converter** — Sigma → KQL translation mapper

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
