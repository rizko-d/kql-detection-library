# Data Connector Requirements

Every rule in this library depends on specific Sentinel data connectors. Before
deploying a rule, ensure the corresponding connector is enabled and ingesting
data into your workspace.

## Legend

| Status | Meaning |
|---|---|
| 🔵 Required | Rule will produce zero results without this |
| 🟢 Recommended | Enhances detection quality (additional signals) |

---

## Prerequisites (Workspace-Level)

Enable these before deploying any rules:

| Connector | Coverage | Rules using it |
|---|---|---|
| **Microsoft Defender for Endpoint** (MDE) | 22 rules | All DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents rules |
| **Microsoft Sentinel for Microsoft 365** (Office 365) | 11 rules | All SigninLogs, AuditLogs, OfficeActivity rules |
| **Security Events via AMA / Legacy Agent** | 11 rules | All SecurityEvent (4624/4625/4768/4769/5145/7045/4698) rules |
| **Azure Activity** | 5 rules | All AzureActivity rules (Key Vault, Automation, Logic Apps, Resource Deletion) |

---

## Per-Rule Connector Map

### Credential Access (5 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| brute-force-rdp | SigninLogs | Microsoft 365 (Azure AD) | 🔵 Enable Azure AD sign-in logs |
| kerberoasting-detection | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 4769 |
| dcsync-detection | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 4662 & Directory Service Access auditing enabled |
| lsass-memory-access | SecurityEvent + DeviceProcessEvents | Security Events + MDE | 🔵 Enable Object Access auditing for LSASS (GPO: Computer Config → Windows Settings → Security Settings → Advanced Audit Policy → Object Access → Audit Kernel Object) |
| key-vault-access-anomaly | AzureDiagnostics | Key Vault diagnostics → Log Analytics | 🔵 Enable Key Vault diagnostic settings (AuditEvent → Log Analytics workspace) |

### Execution + Persistence (13 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| powershell-obfuscation | DeviceProcessEvents | MDE | 🟢 Enable PowerShell script block logging for richer context |
| scheduled-task-creation | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 4698 |
| registry-run-key | DeviceRegistryEvents | MDE | 🔵 MDE must have registry monitoring enabled |
| wmi-event-subscription | SecurityEvent + DeviceEvents | Security Events + MDE | 🔵 Needs EventID 5861 |
| startup-folder | DeviceFileEvents | MDE | 🔵 |
| dll-search-order-hijacking | DeviceImageLoadEvents | MDE | 🟢 Image load events must be enabled in MDE |
| bits-jobs | DeviceProcessEvents | MDE | 🔵 |
| service-installation | SecurityEvent + DeviceProcessEvents | Security Events + MDE | 🔵 Needs EventID 7045/4697 |
| azure-vm-run-command-abuse | AzureActivity | Azure Activity | 🔵 Enable Azure Activity logs |
| logic-app-automation-abuse | AzureActivity | Azure Activity | 🔵 |

### Defense Evasion (4 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| amsi-bypass | DeviceProcessEvents + DeviceRegistryEvents | MDE | 🔵 |
| process-hollowing | DeviceProcessEvents | MDE | 🔵 |
| log-clearing | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 1102 |

### Lateral Movement (8 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| pass-the-hash | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 4624 (type 3) |
| wmi-execution | DeviceProcessEvents | MDE | 🔵 |
| psexec-smb-execution | SecurityEvent + DeviceProcessEvents | Security Events + MDE | 🔵 Needs EventID 7045/5145 |
| rdp-lateral-movement | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 4624 (type 10) |
| remote-service-creation | SecurityEvent + DeviceProcessEvents | Security Events + MDE | 🔵 Needs EventID 7045/4697 |
| dcom-lateral-movement | DeviceProcessEvents | MDE | 🔵 |
| winrm-powershell-remoting | DeviceProcessEvents | MDE | 🔵 |
| smb-named-pipe-impersonation | SecurityEvent | Security Events (AMA/Legacy) | 🔵 Needs EventID 5145 |

### Command and Control (5 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| dns-tunneling | DnsEvents | Azure Firewall / DNS | 🔵 or DNS forwarder → Log Analytics |
| beaconing-pattern | DeviceNetworkEvents | MDE | 🔵 |
| c2-over-websocket | DeviceNetworkEvents | MDE | 🔵 |
| c2-ja3-fingerprint | DeviceNetworkEvents (JA3-enriched) | MDE + Zeek/Suricata TLS enrichment | 🟢 JA3 requires network-data enrichment pipeline |
| icmp-protocol-tunneling | DeviceNetworkEvents | MDE | 🔵 |

### Exfiltration + Collection (5 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| unusual-outbound-traffic | DeviceNetworkEvents | MDE | 🔵 |
| large-file-upload | DeviceNetworkEvents | MDE | 🔵 |
| cloud-storage-exfiltration | DeviceNetworkEvents | MDE | 🔵 |
| email-forwarding-exfiltration | OfficeActivity | Microsoft 365 (Exchange) | 🔵 Enable Exchange mailbox auditing |
| data-staging | DeviceProcessEvents | MDE | 🔵 |

### Cloud & Kubernetes (10 rules)

| Rule | Primary Table | Required Connector | Notes |
|---|---|---|---|
| azure-ad-mfa-bypass | SigninLogs | Microsoft 365 (Azure AD) | 🔵 |
| oauth-consent-grant | AuditLogs | Microsoft 365 (Azure AD) | 🔵 Enable Azure AD audit logs |
| service-principal-abuse | AuditLogs + AADServicePrincipalSignInLogs | Microsoft 365 (Azure AD) | 🔵 |
| kubernetes-container-escape | AzureDiagnostics | Kubernetes audit logs → Log Analytics | 🔵 Enable AKS diagnostic settings (kube-audit) |
| kubernetes-rbac-abuse | AzureDiagnostics | Kubernetes audit logs → Log Analytics | 🔵 |
| blob-storage-public-access | StorageBlobLogs | Azure Storage | 🔵 Enable Storage diagnostic settings (blob logs) |
| azure-resource-deletion | AzureActivity | Azure Activity | 🔵 |

---

## Quick Check: Which Connectors Do I Need?

Run this in Sentinel Logs to see which tables have data:

```kql
union withsource=TableName
    SigninLogs, AuditLogs, SecurityEvent, DeviceProcessEvents,
    DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents,
    OfficeActivity, AzureActivity, AzureDiagnostics,
    StorageBlobLogs, DnsEvents, AADServicePrincipalSignInLogs,
    AADNonInteractiveUserSignInLogs
| summarize IngestionCount = count() by TableName
| order by IngestionCount desc
```

If a table shows 0 rows, you need to enable its connector.

---

## Enabling Connectors

1. Open **Microsoft Sentinel** → **Data connectors**
2. Find the connector listed above (e.g., "Microsoft Defender for Endpoint")
3. Click **Open connector page** → follow the setup wizard
4. Wait 15-30 minutes for data to begin flowing
5. Re-run the check query above to confirm ingestion
