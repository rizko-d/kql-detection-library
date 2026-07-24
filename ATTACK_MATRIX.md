# MITRE ATT&CK Coverage Matrix

**Last Updated:** 2025-07-24 | **Total Rules:** 5

## Legend

| Status | Meaning |
|---|---|
| ✅ | Implemented |
| 🟡 | Planned |
| ❌ | Not covered |

## Initial Access

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Execution

| Technique | ID | Rule | Status |
|---|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | [powershell-obfuscation.kql](azure-sentinel/execution/powershell-obfuscation.kql) | ✅ |
| Scheduled Task / Job | T1053.005 | [scheduled-task-creation.kql](azure-sentinel/persistence/scheduled-task-creation.kql) | ✅ |

## Persistence

| Technique | ID | Rule | Status |
|---|---|---|---|
| Scheduled Task / Job | T1053.005 | [scheduled-task-creation.kql](azure-sentinel/persistence/scheduled-task-creation.kql) | ✅ |

## Privilege Escalation

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Defense Evasion

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Credential Access

| Technique | ID | Rule | Status |
|---|---|---|---|
| Brute Force | T1110 | [brute-force-rdp.kql](azure-sentinel/credential-access/brute-force-rdp.kql) | ✅ |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | [kerberoasting-detection.kql](azure-sentinel/credential-access/kerberoasting-detection.kql) | ✅ |
| OS Credential Dumping: DCSync | T1003.006 | [dcsync-detection.kql](azure-sentinel/credential-access/dcsync-detection.kql) | ✅ |

## Discovery

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Lateral Movement

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Collection

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Command and Control

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Exfiltration

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

## Impact

| Technique | ID | Rule | Status |
|---|---|---|---|
| — | — | — | ❌ |

---

**Tactics covered:** 3 / 14 | **Techniques covered:** 5
