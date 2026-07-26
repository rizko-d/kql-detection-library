# Changelog

## v0.2 — 2025-07-26
### Added — Execution & Defense Evasion (partial, 5 of 10 rules)
- **LSASS Memory Access** (T1003.001) — credential dumping via lsass.exe handle access, ProcDump, comsvcs MiniDump
- **AMSI Bypass** (T1562.001) — AmsiScanBuffer patching, reflection-based bypass, registry disable
- **Process Hollowing** (T1055.012) — trusted system binaries running from user-writable paths
- **Log Clearing** (T1070.001) — Event 1102 + wevtutil/auditpol/Clear-EventLog
- **Registry Run Key Persistence** (T1547.001) — autostart Run/RunOnce key modifications
- New `defense-evasion/` rule category
- Test cases for all 5 new rules
- Updated MITRE ATT&CK matrix (4 tactics, 10 techniques)

## v0.1 — 2025-07-24
### Added
- Initial 5 detection rules (Brute Force RDP, Kerberoasting, DCSync, PowerShell Obfuscation, Scheduled Task)
- Standardized KQL rule format with MITRE ATT&CK frontmatter
- Test harness per rule with synthetic event data
- `rule-validator.py` — KQL syntax and structure validator
- MITRE ATT&CK matrix mapping
- Project README with detailed roadmap to v0.8 (~70 rules planned)
- Expanded roadmap: v0.2 (+10 rules), v0.3 (+10), v0.4 (+10), v0.5 (+10), v0.6 (+10 queries), v0.7 (+8 tooling), v0.8 (+8 advanced)
