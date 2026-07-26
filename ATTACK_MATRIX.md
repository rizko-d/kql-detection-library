# MITRE ATT&CK Coverage Matrix

**Last Updated:** 2025-07-26 | **Current Rules:** 10 | **Roadmap Scope:** ~70 rules across v0.1–v0.8

## Legend

| Status | Meaning |
|---|---|
| ✅ | Implemented |
| 🟡 | Planned (roadmap) |
| ❌ | Not covered |

## Reconnaissance

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Resource Development

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Initial Access

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Execution

| Technique | ID | Rule | Status |
|---|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | [powershell-obfuscation.kql](azure-sentinel/execution/powershell-obfuscation.kql) | ✅ |
| Windows Management Instrumentation | T1047 | — | 🟡 v0.3 |
| Scheduled Task / Job | T1053.005 | [scheduled-task-creation.kql](azure-sentinel/persistence/scheduled-task-creation.kql) | ✅ |
| Azure VM Run Command | T1059.009 | — | 🟡 v0.5 |
| Azure Logic App / Automation Account | T1053.006 | — | 🟡 v0.5 |

## Persistence

| Technique | ID | Rule | Status |
|---|---|---|---|
| Scheduled Task / Job | T1053.005 | [scheduled-task-creation.kql](azure-sentinel/persistence/scheduled-task-creation.kql) | ✅ |
| Registry Run Keys / Startup Folder | T1547.001 | [registry-run-key.kql](azure-sentinel/persistence/registry-run-key.kql) | ✅ |
| WMI Event Subscription | T1546.003 | — | 🟡 v0.2 |
| DLL Search Order Hijacking | T1574.001 | — | 🟡 v0.2 |
| BITS Jobs | T1197 | — | 🟡 v0.2 |
| Create or Modify System Process: Windows Service | T1543.003 | — | 🟡 v0.3 |
| Account Manipulation | T1098 | — | 🟡 v0.5 |

## Privilege Escalation

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Defense Evasion

| Technique | ID | Rule | Status |
|---|---|---|---|
| Impair Defenses: AMSI Bypass | T1562.001 | [amsi-bypass.kql](azure-sentinel/defense-evasion/amsi-bypass.kql) | ✅ |
| Process Hollowing | T1055.012 | [process-hollowing.kql](azure-sentinel/defense-evasion/process-hollowing.kql) | ✅ |
| Indicator Removal: Log Clearing | T1070.001 | [log-clearing.kql](azure-sentinel/defense-evasion/log-clearing.kql) | ✅ |
| Valid Accounts: Cloud Accounts | T1078.004 | — | 🟡 v0.5 |
| Service Installation (Masquerading) | T1543.003 | — | 🟡 v0.2 |

## Credential Access

| Technique | ID | Rule | Status |
|---|---|---|---|
| Brute Force | T1110 | [brute-force-rdp.kql](azure-sentinel/credential-access/brute-force-rdp.kql) | ✅ |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | [kerberoasting-detection.kql](azure-sentinel/credential-access/kerberoasting-detection.kql) | ✅ |
| OS Credential Dumping: DCSync | T1003.006 | [dcsync-detection.kql](azure-sentinel/credential-access/dcsync-detection.kql) | ✅ |
| OS Credential Dumping: LSASS | T1003.001 | [lsass-memory-access.kql](azure-sentinel/credential-access/lsass-memory-access.kql) | ✅ |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | — | 🟡 v0.6 |
| Unsecured Credentials: Key Vault | T1552.005 | — | 🟡 v0.5 |

## Discovery

| Technique | ID | Rule | Status |
|---|---|---|---|
| Network Share Discovery | T1135 | — | 🟡 v0.3 |
| Account Discovery: AD | T1087.002 | — | 🟡 v0.3 |
| Kubernetes RBAC Discovery | T1087.004 | — | 🟡 v0.5 |

## Lateral Movement

| Technique | ID | Rule | Status |
|---|---|---|---|
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | — | 🟡 v0.3 |
| Remote Services: SMB/WinRM | T1021.006 | — | 🟡 v0.3 |
| Remote Services: DCOM | T1021.003 | — | 🟡 v0.3 |
| Remote Services: RDP | T1021.001 | — | 🟡 v0.3 |
| Lateral Tool Transfer | T1570 | — | 🟡 v0.3 |
| Use Alternate Authentication Material: SMB/Named Pipe | T1550.003 | — | 🟡 v0.3 |

## Collection

| Technique | ID | Rule | Status |
|---|---|---|---|
| Email Collection: Auto-Forwarding | T1114.003 | — | 🟡 v0.4 |
| Data Staging | T1074 | — | 🟡 v0.4 |

## Command and Control

| Technique | ID | Rule | Status |
|---|---|---|---|
| DNS Tunneling | T1572 | — | 🟡 v0.4 |
| Web Service: Beaconing | T1071.001 | — | 🟡 v0.4 |
| Web Service: WebSocket | T1071.001 | — | 🟡 v0.4 |
| Non-Application Layer Protocol | T1571 | — | 🟡 v0.4 |

## Exfiltration

| Technique | ID | Rule | Status |
|---|---|---|---|
| Exfiltration Over C2 Channel | T1048 | — | 🟡 v0.4 |
| Exfiltration to Cloud Storage | T1567.002 | — | 🟡 v0.4 |
| Automated Exfiltration: Large Upload | T1030 | — | 🟡 v0.4 |

## Impact

| Technique | ID | Rule | Status |
|---|---|---|---|
| Data Destruction | T1485 | — | 🟡 v0.5 |

---

**Tactics covered (current):** 4 / 14
**Techniques covered (current):** 10  
**Techniques planned (roadmap):** ~45+  
**Rule count target:** ~70 across all versions
