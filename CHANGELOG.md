# Changelog

## v0.3 — 2025-07-26
### Added — Lateral Movement & Discovery (partial, 5 of 10 rules)
- **Pass-the-Hash** (T1550.002) — NTLM type-3 logon fan-out across hosts
- **WMI Execution** (T1047) — wmic process call create, Invoke-WmiMethod, WmiPrvSE children
- **PsExec / SMB Execution** (T1570) — PSEXESVC service, named pipes, ADMIN$ writes
- **RDP Lateral Movement** (T1021.001) — internal RDP (type 10) fan-out detection
- **Network Share Discovery** (T1135) — net view/share, PowerView ShareFinder, recon tools
- New `lateral-movement/` and `discovery/` rule categories
- Test cases for all 5 new rules
- Updated MITRE ATT&CK matrix (6 tactics, 20 rules)

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
