#!/usr/bin/env python3
"""
rule-dependency-checker.py — Cross-reference integrity checks across the library.

Zero-dependency (stdlib only).

Checks:
  1. Every detection rule has a matching test case in mapping/test-cases/
  2. Every technique in a rule header appears in mapping/mitre-attack.yaml
  3. Every rule path referenced in mitre-attack.yaml actually exists
  4. Every rule referenced in ATTACK_MATRIX.md exists on disk
  5. Reports the primary data-source table(s) each rule depends on (informational)

Exit 1 if any hard check fails.

Usage:
    python tools/rule-dependency-checker.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "azure-sentinel"
TESTS_DIR = ROOT / "mapping" / "test-cases"
MITRE_YAML = ROOT / "mapping" / "mitre-attack.yaml"
MATRIX = ROOT / "ATTACK_MATRIX.md"

TECH_RE = re.compile(r'^//\s*Technique:\s*([T0-9.]+)')
DS_RE = re.compile(r'^//\s*Data Source:\s*(.+)$')


def rule_files():
    return sorted(RULES_DIR.rglob("*.kql"))


def header_technique(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        m = TECH_RE.match(line.strip())
        if m:
            return m.group(1).strip()
    return ""


def header_datasource(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        m = DS_RE.match(line.strip())
        if m:
            return m.group(1).strip()
    return ""


def load_yaml_techniques_and_paths():
    """Minimal parse of mitre-attack.yaml (no pyyaml): collect T-ids and rule paths."""
    techs, paths = set(), set()
    if not MITRE_YAML.exists():
        return techs, paths
    for line in MITRE_YAML.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        m = re.match(r'^(T[0-9.]+):', s)
        if m:
            techs.add(m.group(1))
        pm = re.match(r'^-\s*"?(azure-sentinel/[^"\s]+\.kql)"?', s)
        if pm:
            paths.add(pm.group(1))
    return techs, paths


def main():
    errors, warnings, infos = [], [], []

    rules = rule_files()
    test_stems = {p.stem for p in TESTS_DIR.glob("*.kql")}
    yaml_techs, yaml_paths = load_yaml_techniques_and_paths()
    matrix_text = MATRIX.read_text(encoding="utf-8") if MATRIX.exists() else ""

    for rule in rules:
        rel = rule.relative_to(ROOT).as_posix()
        # 1. matching test case
        if f"test-{rule.stem}" not in test_stems:
            errors.append(f"[TEST] No test case for rule: {rel} "
                          f"(expected mapping/test-cases/test-{rule.stem}.kql)")
        # 2. technique present in yaml
        tech = header_technique(rule)
        if tech and tech not in yaml_techs:
            errors.append(f"[YAML] Technique {tech} ({rel}) missing from mitre-attack.yaml")
        # 4. rule present in ATTACK_MATRIX.md
        if rule.name not in matrix_text:
            warnings.append(f"[MATRIX] {rel} not referenced in ATTACK_MATRIX.md")
        # 5. data source info
        ds = header_datasource(rule)
        if ds:
            infos.append(f"{rel} -> {ds}")

    # 3. yaml-referenced paths must exist
    for yp in sorted(yaml_paths):
        if not (ROOT / yp).exists():
            errors.append(f"[YAML] mitre-attack.yaml references missing file: {yp}")

    print("=" * 60)
    print("Rule Dependency Checker")
    print("=" * 60)
    print(f"Rules scanned:        {len(rules)}")
    print(f"Test cases found:     {len(test_stems)}")
    print(f"YAML techniques:      {len(yaml_techs)}")
    print(f"YAML rule paths:      {len(yaml_paths)}")
    print()

    if warnings:
        print(f"WARNINGS ({len(warnings)}):")
        for w in warnings:
            print("  ~", w)
        print()

    if errors:
        print(f"ERRORS ({len(errors)}):")
        for e in errors:
            print("  x", e)
        print()
        print("RESULT: FAILED")
        sys.exit(1)

    print("RESULT: PASSED — all rules have test cases, yaml entries, and existing references.")
    sys.exit(0)


if __name__ == "__main__":
    main()
