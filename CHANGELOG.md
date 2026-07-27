# Changelog

## v0.8 — 2025-07-26
### Added — Advanced Features (COMPLETE, final roadmap version)
- **`workbook-generator.py`** — generate Sentinel Workbook JSON (rule inventory + tactic pie chart)
- **`navigator-export.py`** — export rules as ATT&CK Navigator heatmap layer JSON (41 techniques)
- **`test-simulator.py`** — synthetic event generator (deferred from v0.7, 9 table schemas)
- **`sigma-to-kql.py`** — basic Sigma rule → KQL converter (field mapping, modifier support)
- **`kql-test-framework.py`** — unit test framework (expected-result checking, coverage reporting)
- **Tier-2 Correlation Rule** — LSASS dump → RDP lateral → scheduled task kill-chain hunting query
- **Tier-3 ML Anomaly** — z-score time-series sign-in failure spike detection
- **Cross-Workspace Hunting** — workspace()-based cross-tenant queries (3 hunt patterns)
- **Watchlist Integration Guide** — docs/watchlist-integration.kql with 4 working examples
### Changed
- v0.7 `test-simulator.py` item moved from deferred to complete in v0.8
- Updated README stats: 12 tools + CI, 13 hunting queries
- **Roadmap fully complete — all v0.1–v0.8 delivered**

## v0.7 — 2025-07-26
### Added — Tooling & CI (7 of 8 items; test-simulator deferred to v0.8)
- **`rule-scaffold.py`** — generate a rule/hunt from template + matching test case
- **`coverage-report.py`** — auto-generate ATTACK_MATRIX.md from rule headers (`--write`/`--check`)
- **`rule-dependency-checker.py`** — verify rules ↔ test cases ↔ mitre-attack.yaml ↔ matrix integrity
- **`fp-report.py`** — false-positive hardening score per rule (avg 2.91/3 at v0.7)
- **`arm-exporter.py`** — export rules as a Sentinel ARM template (Microsoft.SecurityInsights/alertRules)
- **`terraform-exporter.py`** — export rules as Terraform (azurerm_sentinel_alert_rule_scheduled)
- **GitHub Actions CI** (`.github/workflows/validate.yml`) — validator + dependency + coverage-check on push/PR
### Changed
- `ATTACK_MATRIX.md` is now **auto-generated** by `coverage-report.py` (no more manual edits)
- Renamed 4 v0.1 test cases to the `test-<rule-stem>.kql` convention so the dependency
  checker can pair them 1:1 (test-brute-force→test-brute-force-rdp, etc.)
- Added `docs/fp-coverage.md` — generated FP-tuning coverage report

## v0.6 — 2025-07-26
### Added — Hunting & Baseline (COMPLETE, 10 hunting queries)
- New `hunting-queries/` module with a hunt-specific metadata format
  (Hunt Hypothesis / Investigation Steps / Pivots instead of Severity / Response)
- **User Behavior Baseline** (T1078) — 30d per-user baseline vs recent deviation
- **Unmanaged Device Access** (T1078.004) — non-compliant device → sensitive apps
- **Anomalous Logon Hour** (T1078) — first-ever logon at an odd/off-hours time
- **Cross-Tenant Access Anomalies** (T1078.004) — B2B guest sign-ins + invitations
- **Service Account Interactive Logon** (T1078) — svc accounts with type 2/10 logons
- **Pass-the-Hash Hunting** (T1550.002) — NTLM type-3 fan-out across hosts
- **Golden Ticket Hunting** (T1558.001) — TGS without TGT, RC4 ticket anomalies
- **Mailbox Access Anomalies** (T1114) — non-owner mailbox access via EWS/Graph
- **Identity Protection Insights** (T1078) — aggregated AAD risk detections per user
- **Data Staging → Exfil Correlation** (T1074/T1048) — archive-then-egress chain
### Changed
- `rule-validator.py` extended to support two file types: detection rules
  (6 MITRE headers) and hunting queries (6 hunt headers, `// === HUNT ===` marker).
  Backward compatible — all 45 detection rules still validate unchanged.

## v0.5 — 2025-07-26
### Added — Cloud-Specific & Kubernetes (COMPLETE, 10 of 10 rules)
- **Azure AD MFA Bypass / Legacy Auth** (T1078.004) — legacy protocol sign-ins that evade MFA
- **OAuth Consent Grant** (T1528) — illicit consent to apps requesting high-risk Graph scopes
- **Service Principal Abuse** (T1098) — app credential adds / anomalous SP sign-ins
- **Kubernetes Container Escape** (T1611) — privileged pods, hostPath, docker.sock, capabilities
- **Key Vault Access Anomaly** (T1552.005) — bulk secret dumping / unexpected identity
- **Kubernetes RBAC Abuse** (T1087.004) — cluster-admin bindings, secret enumeration, self-review
- **Azure VM Run Command Abuse** (T1059.009) — control-plane RCE via Run Command / custom script
- **Blob Storage Public Access** (T1530) — anonymous enumeration / public blob access
- **Azure Resource Deletion** (T1485) — destructive bulk delete of RGs / vaults / NSGs
- **Logic App / Automation Abuse** (T1053.006) — runbook / workflow persistence
- New `cloud/` rule category; test cases for all 10 rules

## v0.4 — 2025-07-26
### Added — Exfiltration & C2 (COMPLETE, 10 of 10 rules)
- **Unusual Outbound Traffic** (T1048) — per-device egress baseline + z-score anomaly detection
- **DNS Tunneling** (T1572) — high unique-subdomain count, long/high-entropy queries, TXT-heavy
- **Beaconing Pattern** (T1071.001) — regular inter-connection interval (low jitter) C2 detection
- **Large File Upload** (T1030) — single large outbound transfer to external endpoints
- **Data Staging** (T1074) — rar/7z/Compress-Archive with password/staging-path/sensitive-source
- **C2 over WebSocket** (T1071.001) — long-lived / non-browser WebSocket channels
- **C2 JA3/JA3S Fingerprint** (T1071.001) — TLS fingerprint match against known C2 frameworks
- **Cloud Storage Exfiltration** (T1567.002) — uploads to consumer cloud (Dropbox/GDrive/Mega)
- **Email Forwarding Exfiltration** (T1114.003) — external inbox forwarding rules (BEC)
- **ICMP / Protocol Tunneling** (T1571) — covert channels over ICMP / non-standard protocols
- New `exfiltration/`, `command-and-control/`, and `collection/` rule categories
- Test cases for all 10 rules
- Updated MITRE ATT&CK matrix (12 tactics, 45 rules)

## v0.3 — 2025-07-26
### Added — Lateral Movement & Discovery (COMPLETE, 10 of 10 rules)
- **Pass-the-Hash** (T1550.002) — NTLM type-3 logon fan-out across hosts
- **WMI Execution** (T1047) — wmic process call create, Invoke-WmiMethod, WmiPrvSE children
- **PsExec / SMB Execution** (T1570) — PSEXESVC service, named pipes, ADMIN$ writes
- **RDP Lateral Movement** (T1021.001) — internal RDP (type 10) fan-out detection
- **Network Share Discovery** (T1135) — net view/share, PowerView ShareFinder, recon tools
- **Remote Service Creation** (T1543.003) — sc.exe \\host, New-Service -ComputerName, Impacket smbexec
- **DCOM Lateral Movement** (T1021.003) — MMC20.Application, DCOM server spawning shells
- **WinRM / PowerShell Remoting** (T1021.006) — winrs, Invoke-Command, wsmprovhost children
- **SMB Named Pipe Impersonation** (T1550.003) — svcctl/atsvc/psexesvc pipe access over IPC$
- **Active Directory Discovery** (T1087.002) — SharpHound, PowerView, dsquery, nltest, net /domain
- New `lateral-movement/` and `discovery/` rule categories
- Test cases for all 10 new rules
- Updated MITRE ATT&CK matrix (6 tactics, 25 rules)

## v0.2 — 2025-07-26
### Added — Execution & Defense Evasion (COMPLETE, 10 of 10 rules)
- **LSASS Memory Access** (T1003.001) — credential dumping via lsass.exe handle access, ProcDump, comsvcs MiniDump
- **AMSI Bypass** (T1562.001) — AmsiScanBuffer patching, reflection-based bypass, registry disable
- **Process Hollowing** (T1055.012) — trusted system binaries running from user-writable paths
- **Log Clearing** (T1070.001) — Event 1102 + wevtutil/auditpol/Clear-EventLog
- **Registry Run Key Persistence** (T1547.001) — autostart Run/RunOnce key modifications
- **WMI Event Subscription Persistence** (T1546.003) — __EventFilter / __FilterToConsumerBinding (Event 5861)
- **Startup Folder Persistence** (T1547.001) — LNK/script/EXE dropped into Startup folders
- **DLL Search Order Hijacking** (T1574.001) — commonly-abused DLLs loaded from user-writable paths
- **BITS Jobs Abuse** (T1197) — bitsadmin download + SetNotifyCmdLine persistence
- **Service Installation** (T1543.003) — new service creation (7045/4697) with suspicious binaries
- New `defense-evasion/` rule category
- Test cases for all 10 new rules
- Fixed `rule-validator.py` bracket checker: `//` inside string literals (e.g. URLs) no longer misread as comments
- Updated MITRE ATT&CK matrix (4 tactics, 15 rules across 13 techniques)

## v0.1 — 2025-07-24
### Added
- Initial 5 detection rules (Brute Force RDP, Kerberoasting, DCSync, PowerShell Obfuscation, Scheduled Task)
- Standardized KQL rule format with MITRE ATT&CK frontmatter
- Test harness per rule with synthetic event data
- `rule-validator.py` — KQL syntax and structure validator
- MITRE ATT&CK matrix mapping
- Project README with detailed roadmap to v0.8 (~70 rules planned)
- Expanded roadmap: v0.2 (+10 rules), v0.3 (+10), v0.4 (+10), v0.5 (+10), v0.6 (+10 queries), v0.7 (+8 tooling), v0.8 (+8 advanced)
