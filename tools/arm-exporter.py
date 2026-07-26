#!/usr/bin/env python3
"""
arm-exporter.py — Export KQL detection rules as Microsoft Sentinel Scheduled
Analytics Rules in an ARM template (deployable via az deployment).

Zero-dependency (stdlib only).

Reads each rule's // header block for metadata (severity, technique, tactic),
strips the header, and emits a Microsoft.SecurityInsights/alertRules ARM resource
per rule. Tactics are mapped to Sentinel's supported tactic enum.

Usage:
    python tools/arm-exporter.py > sentinel-rules.json
    python tools/arm-exporter.py --out deploy/sentinel-rules.json
    # then: az deployment group create -g <rg> --template-file sentinel-rules.json \
    #         --parameters workspace=<workspaceName>
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

# Sentinel-supported tactic enum (subset relevant here)
SENTINEL_TACTICS = {
    "reconnaissance": "Reconnaissance", "resource development": "ResourceDevelopment",
    "initial access": "InitialAccess", "execution": "Execution",
    "persistence": "Persistence", "privilege escalation": "PrivilegeEscalation",
    "defense evasion": "DefenseEvasion", "credential access": "CredentialAccess",
    "discovery": "Discovery", "lateral movement": "LateralMovement",
    "collection": "Collection", "command and control": "CommandAndControl",
    "exfiltration": "Exfiltration", "impact": "Impact",
}

SEV_MAP = {"Critical": "High", "High": "High", "Medium": "Medium",
           "Low": "Low", "Informational": "Informational"}


def parse_meta(text: str):
    tech_id, tech_name, tactics, sev = "", "", [], "Medium"
    for line in text.splitlines():
        s = line.strip()
        m = TECH_RE.match(s)
        if m:
            tech_id, tech_name = m.group(1).strip(), m.group(2).strip()
        m2 = TACTIC_RE.match(s)
        if m2:
            tactics = [t.strip() for t in re.split(r'[/,]', m2.group(1))]
        m3 = SEV_RE.match(s)
        if m3:
            sev = m3.group(1).strip()
    return tech_id, tech_name, tactics, sev


def strip_header(text: str) -> str:
    """Return the KQL query body after the // === QUERY === marker."""
    if "// === QUERY ===" in text:
        return text.split("// === QUERY ===", 1)[1].strip()
    # fallback: drop leading comment block
    lines = text.splitlines()
    body = [l for l in lines if not l.strip().startswith("//")]
    return "\n".join(body).strip()


def map_tactics(tactics):
    out = []
    for t in tactics:
        key = t.strip().lower()
        if key in SENTINEL_TACTICS:
            out.append(SENTINEL_TACTICS[key])
    return out or ["Execution"]


def build_rule_resource(path: Path):
    text = path.read_text(encoding="utf-8")
    tech_id, tech_name, tactics, sev = parse_meta(text)
    query = strip_header(text)
    display = tech_name or path.stem.replace("-", " ").title()
    rule_guid_seed = path.stem

    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2023-02-01",
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', guid('{rule_guid_seed}'))]",
        "kind": "Scheduled",
        "properties": {
            "displayName": f"[KQL-Lib] {display}",
            "description": f"Auto-exported from kql-detection-library ({path.name}). Technique {tech_id}.",
            "severity": SEV_MAP.get(sev, "Medium"),
            "enabled": True,
            "query": query,
            "queryFrequency": "PT1H",
            "queryPeriod": "P1D",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": map_tactics(tactics),
            "techniques": [tech_id] if tech_id else [],
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Export rules as a Sentinel ARM template")
    ap.add_argument("--out", default="", help="output path (default: stdout)")
    args = ap.parse_args()

    resources = [build_rule_resource(p) for p in sorted(RULES_DIR.rglob("*.kql"))]

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Log Analytics / Sentinel workspace name"},
            }
        },
        "resources": resources,
    }

    out_json = json.dumps(template, indent=2)
    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(out_json, encoding="utf-8")
        print(f"Wrote {len(resources)} rules to {args.out}", file=sys.stderr)
    else:
        print(out_json)


if __name__ == "__main__":
    main()
