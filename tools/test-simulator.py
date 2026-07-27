#!/usr/bin/env python3
"""
test-simulator.py — Generate synthetic KQL datatable fixtures from rule headers.

Zero-dependency (stdlib only).

Reads a .kql rule file, extracts the expressed or implied table schema from the
// Data Source: header, and generates a minimal datatable with enough rows to
exercise the detection logic. Output is a valid KQL datatable block that can be
appended to the rule (after // === QUERY ===) for local testing.

Supports commonly-used Sentinel tables with pre-defined column sets:
  - SigninLogs, SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents,
    AuditLogs, AzureActivity, OfficeActivity, DnsEvents

Usage:
    python tools/test-simulator.py azure-sentinel/credential-access/brute-force-rdp.kql
    python tools/test-simulator.py --all   # regenerate every test case
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "mapping" / "test-cases"
RULES_DIR = ROOT / "azure-sentinel"

TABLE_SCHEMAS = {
    "signinlogs": {
        "columns": "TimeGenerated:datetime, ResultType:string, UserPrincipalName:string, IPAddress:string, "
                   "Location:string, AppDisplayName:string, ClientAppUsed:string, DeviceDetail:dynamic, "
                   "RiskLevelDuringSignIn:string, AuthenticationRequirement:string",
        "header": "SigninLogs",
        "comment": "SigninLogs (Azure AD)",
    },
    "securityevent": {
        "columns": "TimeGenerated:datetime, EventID:int, Computer:string, TargetUserName:string, "
                   "SubjectUserName:string, IpAddress:string, LogonType:int, AuthenticationPackageName:string, "
                   "LogonProcessName:string, ServiceName:string, ServiceFileName:string, ShareName:string, "
                   "RelativeTargetName:string, TicketEncryptionType:string",
        "header": "SecurityEvent",
        "comment": "SecurityEvent (Windows Event Logs via AMA/Legacy)",
    },
    "deviceprocessevents": {
        "columns": "TimeGenerated:datetime, DeviceName:string, FileName:string, ProcessCommandLine:string, "
                   "AccountName:string, InitiatingProcessFileName:string",
        "header": "DeviceProcessEvents (MDE)",
        "comment": "DeviceProcessEvents (Microsoft Defender for Endpoint)",
    },
    "devicenetworkevents": {
        "columns": "TimeGenerated:datetime, ActionType:string, RemoteIPType:string, RemoteIP:string, "
                   "RemotePort:int, RemoteUrl:string, SentBytes:long, ReceivedBytes:long, "
                   "InitiatingProcessFileName:string, DeviceName:string",
        "header": "DeviceNetworkEvents (MDE)",
        "comment": "DeviceNetworkEvents (Microsoft Defender for Endpoint)",
    },
    "auditlogs": {
        "columns": "TimeGenerated:datetime, OperationName:string, TargetResources:dynamic, InitiatedBy:string, "
                   "Result:string",
        "header": "AuditLogs",
        "comment": "AuditLogs (Azure AD)",
    },
    "azureactivity": {
        "columns": "TimeGenerated:datetime, OperationNameValue:string, ActivityStatusValue:string, "
                   "Caller:string, HTTPRequest:string, Resource:string, ResourceGroup:string",
        "header": "AzureActivity",
        "comment": "AzureActivity (Azure Resource Manager audit)",
    },
    "officeactivity": {
        "columns": "TimeGenerated:datetime, OperationName:string, UserId:string, ClientIP:string, "
                   "Parameters:string, MailboxOwnerUPN:string, ClientInfoString:string, LogonType:string",
        "header": "OfficeActivity",
        "comment": "OfficeActivity (Exchange / SharePoint / Teams)",
    },
    "dnsevents": {
        "columns": "TimeGenerated:datetime, Name:string, QueryType:string, ClientIP:string",
        "header": "DnsEvents",
        "comment": "DnsEvents (Azure DNS / Firewall)",
    },
    "storagelogs": {
        "columns": "TimeGenerated:datetime, AuthenticationType:string, OperationName:string, "
                   "CallerIpAddress:string, AccountName:string, StatusText:string, StatusCode:int, Uri:string",
        "header": "StorageBlobLogs",
        "comment": "StorageBlobLogs (Azure Storage)",
    },
    "azurediagnostics": {
        "columns": "TimeGenerated:datetime, ResourceType:string, OperationName:string, Resource:string, "
                   "CallerIPAddress:string, identity_claim_upn_s:string, id_s:string, log_s:string, Category:string",
        "header": "AzureDiagnostics",
        "comment": "AzureDiagnostics (generic — covers Key Vault, kube-audit, etc.)",
    },
}

DS_RE = re.compile(r'^//\s*Data Source:\s*(.+)$')


def detect_table(text: str) -> str:
    """Guess which Sentinel table this rule queries from its header."""
    for line in text.splitlines():
        m = DS_RE.match(line.strip())
        if m:
            ds_raw = m.group(1).strip().lower()
            for key, schema in TABLE_SCHEMAS.items():
                if key in ds_raw or key.replace(" ", "") in ds_raw:
                    return key
            # heuristic: common column names
            if "signinlogs" in ds_raw: return "signinlogs"
            if "securityevent" in ds_raw: return "securityevent"
            if "deviceprocessevents" in ds_raw: return "deviceprocessevents"
            if "devicenetworkevents" in ds_raw: return "devicenetworkevents"
            if "auditlogs" in ds_raw: return "auditlogs"
            if "azureactivity" in ds_raw: return "azureactivity"
            if "officeactivity" in ds_raw: return "officeactivity"
            if "dnsevents" in ds_raw: return "dnsevents"
            if "storage" in ds_raw: return "storagelogs"
            if "azurediagnostics" in ds_raw: return "azurediagnostics"
    return "devicenetworkevents"  # default fallback


def generate_test(rule_path: Path) -> tuple[str, str]:
    """Return (test_text, suggested_filename) for a rule."""
    text = rule_path.read_text(encoding="utf-8")
    table = detect_table(text)
    schema = TABLE_SCHEMAS.get(table, TABLE_SCHEMAS["devicenetworkevents"])
    stem = rule_path.stem

    # Check if the rule uses union or a specific test table
    if "let Test" in text:
        table_name = "TestTable"
    else:
        table_name = schema["header"].split(" ")[0]  # first token = table name

    lines = [f"// === Test Case: {stem} ===",
             f"// Auto-generated by test-simulator.py — review the rows before deploying.",
             f"// Simulates: TODO — malicious row(s) + benign row(s)",
             f"// Expected: TODO — which rows should fire",
             f"// Query expects: {schema['comment']}",
             "",
             f"let {table_name} = datatable(",
             f"    {schema['columns']}",
             ")",
             "[",
             f"    // TODO: replace with realistic test data",
             f"    datetime(2025-01-01 00:00:00), \"TODO-malicious\",",
             f"    datetime(2025-01-01 01:00:00), \"TODO-benign (should NOT fire)\",",
             "];",
             "",
             f"{table_name}"]
    return "\n".join(lines), f"test-{stem}.kql"


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic KQL test datatables")
    ap.add_argument("rule", nargs="?", default="",
                    help="path to a single .kql rule (or --all to regenerate everything)")
    ap.add_argument("--all", action="store_true",
                    help="regenerate test fixtures for every rule")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be generated, do not write")
    args = ap.parse_args()

    if args.all:
        targets = sorted(RULES_DIR.rglob("*.kql"))
    elif args.rule:
        targets = [Path(args.rule)]
    else:
        print("Provide a rule path or use --all.", file=sys.stderr)
        sys.exit(1)

    generated = 0
    for rule in targets:
        test_content, filename = generate_test(rule)
        target = TESTS_DIR / filename

        if args.dry_run:
            print(f"\n[DRY RUN] Would write {target}")
            print(test_content)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)

        # Only generate if test doesn't already exist (don't overwrite user-crafted tests)
        if target.exists():
            print(f"  SKIP (already exists): {target.name}")
            continue

        target.write_text(test_content, encoding="utf-8")
        print(f"  GENERATED: {target.name} (table: {detect_table(rule.read_text(encoding='utf-8'))})")
        generated += 1

    print(f"\nGenerated {generated} test fixtures. "
          f"Review and replace the TODO rows with real event data.")


if __name__ == "__main__":
    main()
