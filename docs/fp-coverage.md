# False-Positive Tuning Coverage

**Rules analyzed:** 45 | **Avg FP-hardening score:** 2.91 / 3

Score = has_FP_section + has_response + test_has_benign_row (0-3).

| Rule | FP entries | Response | Benign test row | Score |
|---|---|---|---|---|
| azure-sentinel/credential-access/brute-force-rdp.kql | 3 | ✅ | ❌ | 2/3 |
| azure-sentinel/credential-access/dcsync-detection.kql | 3 | ✅ | ❌ | 2/3 |
| azure-sentinel/credential-access/kerberoasting-detection.kql | 3 | ✅ | ❌ | 2/3 |
| azure-sentinel/persistence/service-installation.kql | 2 | ✅ | ❌ | 2/3 |
| azure-sentinel/cloud/azure-ad-mfa-bypass.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/azure-resource-deletion.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/azure-vm-run-command-abuse.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/blob-storage-public-access.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/key-vault-access-anomaly.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/kubernetes-container-escape.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/kubernetes-rbac-abuse.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/logic-app-automation-abuse.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/oauth-consent-grant.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/cloud/service-principal-abuse.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/collection/data-staging.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/collection/email-forwarding-exfiltration.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/command-and-control/beaconing-pattern.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/command-and-control/c2-ja3-fingerprint.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/command-and-control/c2-over-websocket.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/command-and-control/dns-tunneling.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/command-and-control/icmp-protocol-tunneling.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/credential-access/lsass-memory-access.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/defense-evasion/amsi-bypass.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/defense-evasion/dll-search-order-hijacking.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/defense-evasion/log-clearing.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/defense-evasion/process-hollowing.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/discovery/active-directory-discovery.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/discovery/network-share-discovery.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/execution/powershell-obfuscation.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/exfiltration/cloud-storage-exfiltration.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/exfiltration/large-file-upload.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/exfiltration/unusual-outbound-traffic.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/dcom-lateral-movement.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/pass-the-hash.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/psexec-smb-execution.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/rdp-lateral-movement.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/remote-service-creation.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/smb-named-pipe-impersonation.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/winrm-powershell-remoting.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/lateral-movement/wmi-execution.kql | 2 | ✅ | ✅ | 3/3 |
| azure-sentinel/persistence/bits-jobs.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/persistence/registry-run-key.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/persistence/scheduled-task-creation.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/persistence/startup-folder.kql | 3 | ✅ | ✅ | 3/3 |
| azure-sentinel/persistence/wmi-event-subscription.kql | 2 | ✅ | ✅ | 3/3 |
