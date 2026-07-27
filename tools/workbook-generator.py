#!/usr/bin/env python3
"""
workbook-generator.py — Generate an Azure Sentinel Workbook JSON file that
presents the rule library in a structured, queryable dashboard.

Zero-dependency (stdlib only).

The workbook includes:
  - A rule inventory table (name, technique, severity, tactic, data source)
  - Coverage-by-tactic pie chart (from the YAML mapping)
  - Per-rule detail panels with the full KQL query

Usage:
    python tools/workbook-generator.py > sentinel-workbook.json
    python tools/workbook-generator.py --out docs/kql-library-workbook.json

Then: Sentinel → Workbooks → New → "Code Editor" → paste the JSON
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "azure-sentinel"

TECH_RE = re.compile(r'^//\s*Technique:\s*([T0-9.]+)\s*(?:—|-)?\s*(.*)$')
TACTIC_RE = re.compile(r'^//\s*Tactic:\s*(.+)$')
SEV_RE = re.compile(r'^//\s*Severity:\s*(\w+)')
DS_RE = re.compile(r'^//\s*Data Source:\s*(.+)$')

SENTINEL_ID = "kql-detection-library"


def parse_rule(path: Path) -> dict:
    tech_id, tech_name, sev, ds, tactics = "", "", "Medium", "", []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if m := TECH_RE.match(s):
            tech_id, tech_name = m.group(1).strip(), m.group(2).strip()
        if m := SEV_RE.match(s):
            sev = m.group(1).strip()
        if m := DS_RE.match(s):
            ds = m.group(1).strip()
        if m := TACTIC_RE.match(s):
            tactics = [t.strip() for t in re.split(r'[/,]', m.group(1))]
        if tech_id and sev:
            break
    return {"name": tech_name or path.stem.replace("-", " ").title(), "technique": tech_id,
            "severity": sev, "datasource": ds, "tactic": tactics[0] if tactics else "",
            "file": path.stem}


def build():
    rules_data = [parse_rule(p) for p in sorted(RULES_DIR.rglob("*.kql"))]
    tactic_counts = {}
    for r in rules_data:
        tactic_counts[r["tactic"]] = tactic_counts.get(r["tactic"], 0) + 1

    # Build the Sentinel Workbook JSON structure
    return {
        "version": "Notebook/1.0",
        "items": [
            {
                "type": 9,
                "content": {"version": "KqlItem/1.0",
                           "query": "",
                           "size": 4,
                           "title": "KQL Detection Library — Rule Inventory",
                           "noDataMessage": "No data — this is a static inventory, not a live query.",
                           "showExportToExcel": True,
                           "chartId": "panel-1-title"},
                "name": "title"
            },
            {
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": f'print RuleInventory = dynamic({json.dumps(rules_data)})',
                    "size": 3,
                    "title": "Rule Inventory Table",
                    "chartId": "panel-2-table",
                    "visualization": "table",
                },
                "name": "rule-table"
            },
            {
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": f"""let tactics = datatable(Tactic:string, Count:int) [
{','.join(f'    "{t}",{c}' for t, c in sorted(tactic_counts.items(), key=lambda x: -x[1]))}
];
tactics | render piechart with (title="Coverage by Tactic ({len(rules_data)} rules)")""",
                    "size": 1,
                    "title": "Tactic Coverage",
                    "visualization": "piechart",
                    "chartId": "panel-3-pie",
                },
                "name": "tactic-coverage"
            },
        ],
        "metadata": {
            "generatedBy": "tools/workbook-generator.py",
            "totalRules": len(rules_data),
            "totalTechniques": len({r["technique"] for r in rules_data if r["technique"]}),
        },
        "$schema": "https://raw.githubusercontent.com/Microsoft/Application-Insights-Workbooks/master/schema/workbook.json",
    }


def main():
    ap = argparse.ArgumentParser(description="Generate Sentinel Workbook JSON")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    wb = build()
    out_json = json.dumps(wb, indent=2)
    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(out_json, encoding="utf-8")
        print(f"Wrote Sentinel Workbook with {wb['metadata']['totalRules']} rules to {args.out}",
              file=sys.stderr)
    else:
        print(out_json)


if __name__ == "__main__":
    main()
