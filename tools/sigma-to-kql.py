#!/usr/bin/env python3
"""
sigma-to-kql.py — Simple Sigma rule → KQL converter.

Zero-dependency (stdlib only).

Converts a Sigma detection rule (YAML) to a basic KQL query. Supports common
Sigma field mappings for Windows Security/Event logs. This is a simplified
mapper — it handles the detection field → KQL where-clause translation but
does NOT yet handle complex Sigma features (correlation, near, CWR).

Usage:
    python tools/sigma-to-kql.py path/to/rule.yml
    python tools/sigma-to-kql.py --batch path/to/sigma/rules/ --out azure-sentinel/converted/
"""
import argparse
import re
import sys
from pathlib import Path


# Simple Sigma field → KQL column mapping (common Windows Security events)
FIELD_MAP = {
    "EventID": "EventID",
    "Image": "NewProcessName",
    "CommandLine": "ProcessCommandLine",
    "ParentImage": "ParentProcessName",
    "User": "TargetUserName",
    "Computer": "Computer",
    "ProcessId": "ProcessId",
    "ServiceName": "ServiceName",
    "ServiceFileName": "ServiceFileName",
    "TargetObject": "ObjectName",
    "Details": "NewValue",
    "PipeName": "PipeName",
    "ShareName": "ShareName",
    "LogonType": "LogonType",
    "IpAddress": "IpAddress",
    "DestinationIp": "DestinationIp",
    "DestinationPort": "DestinationPort",
    "SourceIp": "SourceIp",
}

OP_MAP = {
    "contains": "has",
    "contains|all": "has_all",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "matches regex",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}


def sigma_value_to_kql(field: str, op: str, value) -> str:
    """Convert a Sigma field + modifier + value to a KQL where-condition."""
    col = FIELD_MAP.get(field, field)
    kql_op = OP_MAP.get(op, "==")
    if isinstance(value, list):
        if kql_op in ("has", "contains", "startswith"):
            vals = ", ".join(f'"{v}"' for v in value)
            return f'{col} {kql_op} ({vals})'
        vals = ", ".join(f'"{v}"' for v in value)
        return f'{col} in~ ({vals})'
    if kql_op in (">", ">=", "<", "<="):
        return f'{col} {kql_op} {value}'
    if kql_op == "has":
        return f'{col} has "{value}"'
    if kql_op == "matches regex":
        return f'{col} matches regex @"{value}"'
    return f'{col} =~ "{value}"'


def simple_parse_sigma(text: str) -> dict:
    """Bare-minimum Sigma YAML parser (no pyyaml). Returns {key: value}."""
    data = {}
    current_key = None
    in_list = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # top-level key
        m = re.match(r'^(\w[\w\s]*):\s*(.*)', stripped)
        if m and not line.startswith("  "):
            current_key = m.group(1).strip()
            val = m.group(2).strip()
            if val:
                data[current_key] = val
            in_list = False
        elif current_key:
            # nested under current key
            if stripped.startswith("- "):
                item = stripped[2:].strip()
                if current_key not in data:
                    data[current_key] = []
                data[current_key].append(item)
                in_list = True
            elif not in_list and ": " in stripped:
                nk, nv = stripped.split(": ", 1)
                data[f"{current_key}.{nk.strip()}"] = nv.strip()
    return data


def parse_selection(selection: str, raw_data: dict) -> str:
    """Convert a Sigma logsource + detection section to KQL."""
    lines = []
    for line in selection.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Simple key: value pair (or key: list)
        m = re.match(r'^(\w[\w.]*)\s*:\s*(.+)', stripped)
        if m:
            field = m.group(1).strip()
            value_str = m.group(2).strip()
            # Detect modifier suffix
            mod = ""
            if '|' in field:
                field, mod = field.rsplit('|', 1)

            if value_str.startswith("["):
                values = [v.strip().strip("'\"") for v in value_str[1:-1].split(",")]
                lines.append(sigma_value_to_kql(field, mod, values))
            else:
                val = value_str.strip("'\"")
                lines.append(sigma_value_to_kql(field, mod, val))
    return " and ".join(f"({l})" for l in lines) if lines else "1==1"


def convert_sigma(text: str) -> tuple[str, str]:
    """Convert Sigma YAML text to (KQL query, technique_id)."""
    data = simple_parse_sigma(text)
    title = data.get("title", "Converted Sigma rule")
    tid = ""
    # Extract technique from tags
    tags = data.get("tags", "")
    if isinstance(tags, list):
        for t in tags:
            m = re.match(r'attack\.(t\d+)', str(t).lower())
            if m:
                tid = m.group(1).upper()
    logsource = data.get("logsource", "")
    detection = "\n".join(text.splitlines())  # crude — keep the detection section

    # Try to parse detection conditions
    det_lines = [l for l in text.splitlines() if l.startswith("    ") and not l.startswith("    #")]
    where = "1==1"
    if det_lines:
        where = parse_selection("\n".join(det_lines), data)

    # Build KQL output
    kql = f"""// === MITRE ATT&CK ===
// Technique: {tid or 'T0000'} — {title}
// Tactic: {data.get('tags', '')}
// Severity: Medium
// Data Source: {logsource}
//
// Converted from Sigma by tools/sigma-to-kql.py
// Original: {data.get('id', '')}
//
// False Positives:
// - TODO
//
// Recommended Response:
// 1. TODO
// === QUERY ===

let lookback = 1d;

SecurityEvent
| where TimeGenerated > ago(lookback)
| where {where}
| project TimeGenerated, Computer, EventID, TargetUserName, ProcessCommandLine"""
    return kql, tid


def main():
    ap = argparse.ArgumentParser(description="Convert Sigma YAML rules to KQL")
    ap.add_argument("source", nargs="?", help="path to a single Sigma .yml rule")
    ap.add_argument("--batch", default="", help="batch-convert a directory of Sigma rules")
    ap.add_argument("--out", default="", help="output directory for batch mode")
    args = ap.parse_args()

    if args.batch:
        batch_dir = Path(args.batch)
        out_dir = Path(args.out or (batch_dir / "converted"))
        out_dir.mkdir(parents=True, exist_ok=True)
        converted = 0
        for yml in sorted(batch_dir.rglob("*.yml")):
            kql, _ = convert_sigma(yml.read_text(encoding="utf-8"))
            out_file = out_dir / f"{yml.stem}.kql"
            out_file.write_text(kql, encoding="utf-8")
            converted += 1
        print(f"Converted {converted} Sigma rules → {out_dir}")
    elif args.source:
        kql, tid = convert_sigma(Path(args.source).read_text(encoding="utf-8"))
        print(kql)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
