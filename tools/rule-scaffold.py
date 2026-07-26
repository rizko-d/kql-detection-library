#!/usr/bin/env python3
"""
rule-scaffold.py — Generate a new KQL detection rule or hunting query from a
template, pre-filled with the correct header block.

Zero-dependency (stdlib only).

Usage:
    # Detection rule
    python tools/rule-scaffold.py rule \
        --name lsass-clone-access \
        --category credential-access \
        --technique T1003.001 \
        --tactic "Credential Access" \
        --severity High \
        --data-source "DeviceProcessEvents (MDE)"

    # Hunting query
    python tools/rule-scaffold.py hunt \
        --name odd-service-creation \
        --technique T1543.003 \
        --tactic Persistence \
        --data-source "SecurityEvent (7045)"

Creates the .kql file under the right directory and prints the path.
Also scaffolds a matching test case under mapping/test-cases/.
"""
import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "azure-sentinel"
HUNTS_DIR = ROOT / "hunting-queries"
TESTS_DIR = ROOT / "mapping" / "test-cases"

VALID_SEVERITIES = {"High", "Medium", "Low", "Critical", "Informational"}
NAME_RE = re.compile(r'^[a-z][a-z0-9-]*[a-z0-9]$')


def validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        sys.exit(f"ERROR: name must match ^[a-z][a-z0-9-]*[a-z0-9]$ : got '{name}'")


def rule_template(args) -> str:
    return f"""// === MITRE ATT&CK ===
// Technique: {args.technique} — {args.title or 'DESCRIBE THE TECHNIQUE'}
// Tactic: {args.tactic}
// Severity: {args.severity}
// Data Source: {args.data_source}
//
// Detects: TODO — one-paragraph description of what this rule detects and why.
//
// Key indicators:
// - TODO
//
// False Positives:
// - TODO
//
// Recommended Response:
// 1. TODO
// === QUERY ===

let lookback = 1d;

// TODO: implement detection logic
TableName
| where TimeGenerated > ago(lookback)
| extend
    AlertName = "{(args.title or args.name).title()}",
    Severity = "{args.severity}",
    TechniqueId = "{args.technique}",
    TechniqueName = "{args.title or 'TODO'}",
    Description = "TODO"
| project TimeGenerated, AlertName, Severity, TechniqueId, TechniqueName, Description"""


def hunt_template(args) -> str:
    return f"""// === HUNT ===
// Technique: {args.technique} — {args.title or 'DESCRIBE THE TECHNIQUE'}
// Tactic: {args.tactic}
// Hunt Hypothesis: TODO — the hypothesis this hunt tests.
// Data Source: {args.data_source}
// Investigation Steps:
//   1. TODO
//   2. TODO
// Pivots:
//   - TODO
// === QUERY ===

let lookback = 7d;

// TODO: implement hunt logic
TableName
| where TimeGenerated > ago(lookback)"""


def test_template(name: str, kind: str) -> str:
    return f"""// === Test Case: {name} ===
// Simulates: TODO — describe the malicious + benign rows.
// Expected: TODO — which row(s) should fire.
// Query expects: TODO (table schema)

let TestTable = datatable(
    TimeGenerated: datetime,
    ExampleColumn: string
)
[
    datetime(2025-01-01 00:00:00), "TODO-malicious",
    datetime(2025-01-01 01:00:00), "TODO-benign",
];

TestTable"""


def write_file(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        sys.exit(f"ERROR: {path} already exists (use --force to overwrite)")
    path.parent.mkdir(parents=True, exist_ok=True)
    # No trailing newline (repo convention)
    path.write_text(content, encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description="Scaffold a KQL rule or hunting query")
    sub = p.add_subparsers(dest="kind", required=True)

    rp = sub.add_parser("rule", help="scaffold a detection rule")
    rp.add_argument("--name", required=True)
    rp.add_argument("--category", required=True,
                    help="subdir under azure-sentinel/ (e.g. credential-access)")
    rp.add_argument("--technique", required=True)
    rp.add_argument("--tactic", required=True)
    rp.add_argument("--severity", required=True, choices=sorted(VALID_SEVERITIES))
    rp.add_argument("--data-source", required=True)
    rp.add_argument("--title", default="")
    rp.add_argument("--force", action="store_true")

    hp = sub.add_parser("hunt", help="scaffold a hunting query")
    hp.add_argument("--name", required=True)
    hp.add_argument("--technique", required=True)
    hp.add_argument("--tactic", required=True)
    hp.add_argument("--data-source", required=True)
    hp.add_argument("--title", default="")
    hp.add_argument("--force", action="store_true")

    args = p.parse_args()
    validate_name(args.name)

    if args.kind == "rule":
        target = RULES_DIR / args.category / f"{args.name}.kql"
        write_file(target, rule_template(args), args.force)
    else:
        target = HUNTS_DIR / f"{args.name}.kql"
        write_file(target, hunt_template(args), args.force)

    test_path = TESTS_DIR / f"test-{args.name}.kql"
    write_file(test_path, test_template(args.name, args.kind), args.force)

    print(f"Created rule:      {target.relative_to(ROOT)}")
    print(f"Created test case: {test_path.relative_to(ROOT)}")
    print("Next: fill in the TODOs, then run  python tools/rule-validator.py")


if __name__ == "__main__":
    main()
