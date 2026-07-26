# MITRE ATT&CK Coverage Matrix

**Last Updated:** 2025-07-26 | **Current Rules:** 45 | **Roadmap Scope:** ~70 rules across v0.1–v0.8

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
| Valid Accounts: Cloud Accounts (Legacy Auth) | T1078.004 | [azure-ad-mfa-bypass.kql](azure-sentinel/cloud/azure-ad-mfa-bypass.kql) | ✅ |

## Execution

| Technique | ID | Rule | Status |
|---|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | [powershell-obfuscation.kql](azure-sentinel/execution/powershell-obfuscation.kql) | ✅ |
| Windows Management Instrumentation | T1047 | [wmi-execution.kql](azure-sentinel/lateral-movement/wmi-execution.kql) | ✅ |
| Scheduled Task / Job | T1053.005 | [scheduled-task-creation.kql](azure-sentinel/persistence/scheduled-task-creation.kql) | ✅ |
| Cloud API: Azure VM Run Command | T1059.009 | [azure-vm-run-command-abuse.kql](azure-sentinel/cloud/azure-vm-run-command-abuse.kql) | ✅ |
| Scheduled Task/Job: Cloud (Automation/Logic App) | T1053.006 | [logic-app-automation-abuse.kql](azure-sentinel/cloud/logic-app-automation-abuse.kql) | ✅ |

## Persistence

| Technique | ID | Rule | Status |
|---|---|---|---|
| Scheduled Task / Job | T1053.005 | [scheduled-task-creation.kql](azure-sentinel/persistence/scheduled-task-creation.kql) | ✅ |
| Registry Run Keys / Startup Folder | T1547.001 | [registry-run-key.kql](azure-sentinel/persistence/registry-run-key.kql), [startup-folder.kql](azure-sentinel/persistence/startup-folder.kql) | ✅ |
| WMI Event Subscription | T1546.003 | [wmi-event-subscription.kql](azure-sentinel/persistence/wmi-event-subscription.kql) | ✅ |
| DLL Search Order Hijacking | T1574.001 | [dll-search-order-hijacking.kql](azure-sentinel/defense-evasion/dll-search-order-hijacking.kql) | ✅ |
| BITS Jobs | T1197 | [bits-jobs.kql](azure-sentinel/persistence/bits-jobs.kql) | ✅ |
| Create or Modify System Process: Windows Service | T1543.003 | [service-installation.kql](azure-sentinel/persistence/service-installation.kql) | ✅ |
| Account Manipulation: Service Principal | T1098 | [service-principal-abuse.kql](azure-sentinel/cloud/service-principal-abuse.kql) | ✅ |
| Scheduled Task/Job: Cloud (Automation/Logic App) | T1053.006 | [logic-app-automation-abuse.kql](azure-sentinel/cloud/logic-app-automation-abuse.kql) | ✅ |

## Privilege Escalation

| Technique | ID | Rule | Status |
|---|---|---|---|
| Escape to Host (Kubernetes Container Escape) | T1611 | [kubernetes-container-escape.kql](azure-sentinel/cloud/kubernetes-container-escape.kql) | ✅ |
| Account Discovery: Cloud (K8s RBAC Abuse) | T1087.004 | [kubernetes-rbac-abuse.kql](azure-sentinel/cloud/kubernetes-rbac-abuse.kql) | ✅ |

## Defense Evasion

| Technique | ID | Rule | Status |
|---|---|---|---|
| Impair Defenses: AMSI Bypass | T1562.001 | [amsi-bypass.kql](azure-sentinel/defense-evasion/amsi-bypass.kql) | ✅ |
| Process Hollowing | T1055.012 | [process-hollowing.kql](azure-sentinel/defense-evasion/process-hollowing.kql) | ✅ |
| Indicator Removal: Log Clearing | T1070.001 | [log-clearing.kql](azure-sentinel/defense-evasion/log-clearing.kql) | ✅ |
| Hijack Execution Flow: DLL Search Order Hijacking | T1574.001 | [dll-search-order-hijacking.kql](azure-sentinel/defense-evasion/dll-search-order-hijacking.kql) | ✅ |
| BITS Jobs | T1197 | [bits-jobs.kql](azure-sentinel/persistence/bits-jobs.kql) | ✅ |
| Create or Modify System Process: Windows Service | T1543.003 | [service-installation.kql](azure-sentinel/persistence/service-installation.kql) | ✅ |
| Valid Accounts: Cloud Accounts (Legacy Auth) | T1078.004 | [azure-ad-mfa-bypass.kql](azure-sentinel/cloud/azure-ad-mfa-bypass.kql) | ✅ |

## Credential Access

| Technique | ID | Rule | Status |
|---|---|---|---|
| Brute Force | T1110 | [brute-force-rdp.kql](azure-sentinel/credential-access/brute-force-rdp.kql) | ✅ |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | [kerberoasting-detection.kql](azure-sentinel/credential-access/kerberoasting-detection.kql) | ✅ |
| OS Credential Dumping: DCSync | T1003.006 | [dcsync-detection.kql](azure-sentinel/credential-access/dcsync-detection.kql) | ✅ |
| OS Credential Dumping: LSASS | T1003.001 | [lsass-memory-access.kql](azure-sentinel/credential-access/lsass-memory-access.kql) | ✅ |
| Steal Application Access Token (OAuth Consent) | T1528 | [oauth-consent-grant.kql](azure-sentinel/cloud/oauth-consent-grant.kql) | ✅ |
| Unsecured Credentials: Key Vault | T1552.005 | [key-vault-access-anomaly.kql](azure-sentinel/cloud/key-vault-access-anomaly.kql) | ✅ |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | — | 🟡 v0.6 |

## Discovery

| Technique | ID | Rule | Status |
|---|---|---|---|
| Network Share Discovery | T1135 | [network-share-discovery.kql](azure-sentinel/discovery/network-share-discovery.kql) | ✅ |
| Account Discovery: AD | T1087.002 | [active-directory-discovery.kql](azure-sentinel/discovery/active-directory-discovery.kql) | ✅ |
| Account Discovery: Cloud (K8s RBAC) | T1087.004 | [kubernetes-rbac-abuse.kql](azure-sentinel/cloud/kubernetes-rbac-abuse.kql) | ✅ |

## Lateral Movement

| Technique | ID | Rule | Status |
|---|---|---|---|
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | [pass-the-hash.kql](azure-sentinel/lateral-movement/pass-the-hash.kql) | ✅ |
| Windows Management Instrumentation | T1047 | [wmi-execution.kql](azure-sentinel/lateral-movement/wmi-execution.kql) | ✅ |
| Lateral Tool Transfer (PsExec / SMB) | T1570 | [psexec-smb-execution.kql](azure-sentinel/lateral-movement/psexec-smb-execution.kql) | ✅ |
| Remote Services: RDP | T1021.001 | [rdp-lateral-movement.kql](azure-sentinel/lateral-movement/rdp-lateral-movement.kql) | ✅ |
| Create/Modify Service (Remote) | T1543.003 | [remote-service-creation.kql](azure-sentinel/lateral-movement/remote-service-creation.kql) | ✅ |
| Remote Services: DCOM | T1021.003 | [dcom-lateral-movement.kql](azure-sentinel/lateral-movement/dcom-lateral-movement.kql) | ✅ |
| Remote Services: WinRM | T1021.006 | [winrm-powershell-remoting.kql](azure-sentinel/lateral-movement/winrm-powershell-remoting.kql) | ✅ |
| Use Alternate Authentication Material: SMB/Named Pipe | T1550.003 | [smb-named-pipe-impersonation.kql](azure-sentinel/lateral-movement/smb-named-pipe-impersonation.kql) | ✅ |

## Collection

| Technique | ID | Rule | Status |
|---|---|---|---|
| Email Collection: Auto-Forwarding | T1114.003 | [email-forwarding-exfiltration.kql](azure-sentinel/collection/email-forwarding-exfiltration.kql) | ✅ |
| Data Staging | T1074 | [data-staging.kql](azure-sentinel/collection/data-staging.kql) | ✅ |
| Data from Cloud Storage (Blob Public Access) | T1530 | [blob-storage-public-access.kql](azure-sentinel/cloud/blob-storage-public-access.kql) | ✅ |

## Command and Control

| Technique | ID | Rule | Status |
|---|---|---|---|
| DNS Tunneling | T1572 | [dns-tunneling.kql](azure-sentinel/command-and-control/dns-tunneling.kql) | ✅ |
| Web Service: Beaconing | T1071.001 | [beaconing-pattern.kql](azure-sentinel/command-and-control/beaconing-pattern.kql) | ✅ |
| Web Service: WebSocket | T1071.001 | [c2-over-websocket.kql](azure-sentinel/command-and-control/c2-over-websocket.kql) | ✅ |
| Web Service: TLS Fingerprint (JA3/JA3S) | T1071.001 | [c2-ja3-fingerprint.kql](azure-sentinel/command-and-control/c2-ja3-fingerprint.kql) | ✅ |
| Non-Standard Port / Protocol Tunneling | T1571 | [icmp-protocol-tunneling.kql](azure-sentinel/command-and-control/icmp-protocol-tunneling.kql) | ✅ |

## Exfiltration

| Technique | ID | Rule | Status |
|---|---|---|---|
| Exfiltration Over Alternative Protocol | T1048 | [unusual-outbound-traffic.kql](azure-sentinel/exfiltration/unusual-outbound-traffic.kql) | ✅ |
| Exfiltration to Cloud Storage | T1567.002 | [cloud-storage-exfiltration.kql](azure-sentinel/exfiltration/cloud-storage-exfiltration.kql) | ✅ |
| Data Transfer Size Limits: Large Upload | T1030 | [large-file-upload.kql](azure-sentinel/exfiltration/large-file-upload.kql) | ✅ |

## Impact

| Technique | ID | Rule | Status |
|---|---|---|---|
| Data Destruction (Azure Bulk Deletion) | T1485 | [azure-resource-deletion.kql](azure-sentinel/cloud/azure-resource-deletion.kql) | ✅ |

---

**Tactics covered (current):** 12 / 14
**Techniques covered (current):** 43 (45 rules)  
**Techniques planned (roadmap):** ~25+  
**Rule count target:** ~70 across all versions
