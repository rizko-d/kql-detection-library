#!/usr/bin/env python3
"""
ATT&CK Navigator Layer Exporter — export KQL detection rules as a MITRE ATT&CK
Navigator heatmap layer JSON file.

Zero-dependency (stdlib only).

Parses every rule's Technique: and Severity: headers, maps severity to a
Navigator score (0-100), and produces a layer file you can load at
https://mitre-attack.github.io/attack-navigator/

Usage:
    python tools/navigator-export.py > navigator-layer.json
    python tools/navigator-export.py --out docs/attack-layer.json

Then: open https://mitre-attack.github.io/attack-navigator/
      → "Open Existing Layer" → select the generated JSON
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "azure-sentinel"

TECH_RE = re.compile(r'^//\s*Technique:\s*([T0-9.]+)')
SEV_RE = re.compile(r'^//\s*Severity:\s*(\w+)')
TACTIC_RE = re.compile(r'^//\s*Tactic:\s*(.+)')

# Map severity to Navigator score (0-100)
SEV_SCORE = {"Critical": 100, "High": 80, "Medium": 60, "Low": 40, "Informational": 20}
# Navigator colors per score range
SCORE_COLORS = [
    {"score": 0, "color": "#999999"},
    {"score": 40, "color": "#e6b422"},
    {"score": 70, "color": "#e68122"},
    {"score": 90, "color": "#cc2222"},
]


def parse_rule(path: Path) -> dict:
    tech_id, sev, tactics = "", "Medium", []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if m := TECH_RE.match(s):
            tech_id = m.group(1).strip()
        if m := SEV_RE.match(s):
            sev = m.group(1).strip()
        if m := TACTIC_RE.match(s):
            tactics = [t.strip() for t in re.split(r'[/,]', m.group(1))]
        if tech_id and sev:
            break
    return {"id": tech_id, "severity": sev, "tactics": tactics, "rule": path.stem}


def main():
    ap = argparse.ArgumentParser(description="Export rules as ATT&CK Navigator layer")
    ap.add_argument("--out", default="", help="output path (default: stdout)")
    args = ap.parse_args()

    # Collect techniques + scores (max per technique across all rules covering it)
    techs = {}
    for rule in sorted(RULES_DIR.rglob("*.kql")):
        r = parse_rule(rule)
        if not r["id"]:
            continue
        score = SEV_SCORE.get(r["severity"], 60)
        if r["id"] not in techs or score > techs[r["id"]]["score"]:
            techs[r["id"]] = {"score": score, "comment": f"{r['rule']} ({r['severity']})",
                               "enabled": True}

    # Build Navigator layer
    layer = {
        "name": "KQL Detection Library Coverage",
        "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "mitre-enterprise",
        "description": f"Auto-generated from kql-detection-library ({len(techs)} techniques covered). "
                       "Score = rule severity (Critical=100, High=80, Medium=60, Low=40).",
        "filters": {"platforms": ["Windows", "Azure", "Azure AD", "Office 365", "SaaS", "IaaS", "Containers"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [{"techniqueID": tid, "score": v["score"], "color": "", "comment": v["comment"],
                         "enabled": v["enabled"]}
                        for tid, v in sorted(techs.items())],
        "gradient": {"colors": SCORE_COLORS, "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Critical", "color": "#cc2222"},
            {"label": "High", "color": "#e68122"},
            {"label": "Medium", "color": "#e6b422"},
            {"label": "Low/Info", "color": "#999999"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1b26",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
    }

    out_json = json.dumps(layer, indent=2)
    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(out_json, encoding="utf-8")
        print(f"Wrote Navigator layer ({len(techs)} techniques) to {args.out}", file=sys.stderr)
    else:
        print(out_json)


if __name__ == "__main__":
    main()
