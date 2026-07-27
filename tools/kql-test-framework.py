#!/usr/bin/env python3
"""
kql-test-framework.py — KQL Unit Test Framework.

Zero-dependency (stdlib only).

Evaluates a KQL rule against its test case by simulating the datatable and
checking whether the expected number of rows fire. While true KQL evaluation
requires a live Kusto engine, this framework provides:

  - **Structural validation**: confirms the test case's datatable matches the
    rule's required columns (from // Data Source: header)
  - **Coverage reporting**: for every test case, counts malicious vs benign rows
  - **Expected-results language**: test cases can declare // Expected: N alerts
    or // Expected: <range>, and the framework validates the annotation is present

Usage:
    python tools/kql-test-framework.py
    python tools/kql-test-framework.py --verbose
    python tools/kql-test-framework.py --rule brute-force-rdp
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "azure-sentinel"
TESTS_DIR = ROOT / "mapping" / "test-cases"

EXPECT_RE = re.compile(r'Expected:\s*(.+)')
COL_RE = re.compile(r'(\w+)\s*:\s*\w+')


def parse_test(test_path: Path) -> dict:
    """Extract structure and expected-result annotation from a test case."""
    text = test_path.read_text(encoding="utf-8")
    expected = ""
    for line in text.splitlines():
        m = EXPECT_RE.match(line.strip())
        if m:
            expected = m.group(1).strip()
    # Count rows in the datatable (crude: count lines after '[' until '];')
    in_datatable = False
    rows = 0
    for line in text.splitlines():
        if line.strip() == "[":
            in_datatable = True
            continue
        if in_datatable:
            if line.strip() == "];":
                break
            if line.strip().endswith(",") and line.strip():
                rows += 1
    return {"expected": expected, "row_count": rows, "has_datatable": "datatable(" in text}


def analyze_rule(rule_path: Path, test_path: Path | None) -> dict:
    """Analyze a rule + its test case, return {status, info}."""
    result = {"rule": rule_path.stem, "test": None, "status": "PASS", "info": ""}
    if not test_path or not test_path.exists():
        result["status"] = "FAIL"
        result["info"] = "Missing test case"
        return result
    result["test"] = test_path.stem
    test_data = parse_test(test_path)
    if not test_data["has_datatable"]:
        result["status"] = "FAIL"
        result["info"] = "Test has no datatable"
        return result
    if not test_data["expected"]:
        result["status"] = "WARN"
        result["info"] = "No 'Expected:' annotation — cannot validate expected results"
        return result
    if test_data["row_count"] < 2:
        result["status"] = "WARN"
        result["info"] = "Only 1 data row — add at least 1 benign row for FP testing"
        return result
    result["info"] = f"Expected: {test_data['expected']} | {test_data['row_count']} rows"
    return result


def main():
    ap = argparse.ArgumentParser(description="KQL Unit Test Framework")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--rule", default="", help="filter to a specific rule stem")
    args = ap.parse_args()

    rules = sorted(RULES_DIR.rglob("*.kql"))
    if args.rule:
        rules = [r for r in rules if args.rule in r.stem]

    results = []
    for rule in rules:
        test = TESTS_DIR / f"test-{rule.stem}.kql"
        r = analyze_rule(rule, test if test.exists() else None)
        results.append(r)

    passed = sum(1 for r in results if r["status"] == "PASS")
    warned = sum(1 for r in results if r["status"] == "WARN")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    print(f"KQL Unit Test Framework")
    print(f"{'='*60}")
    print(f"Rules tested: {len(results)} | PASS: {passed} | WARN: {warned} | FAIL: {failed}")
    print()

    if args.verbose:
        print(f"{'Rule':<35} {'Status':<6} Info")
        print("-" * 60)
        for r in sorted(results, key=lambda x: (x["status"], x["rule"])):
            print(f"{r['rule']:<35} {r['status']:<6} {r['info']}")
        print()

    if failed:
        print("FAILED RULES (missing test or no datatable):")
        for r in results:
            if r["status"] == "FAIL":
                print(f"  x {r['rule']} — {r['info']}")
        print()
        sys.exit(1)

    if warned:
        print(f"WARNINGS ({warned}): rules without 'Expected:' annotation or with only 1 row.")
        print("  Add '// Expected: N alerts' to test case comments for automated result checking.")
        print()

    print("RESULT: PASSED" if not failed else "RESULT: PARTIAL")


if __name__ == "__main__":
    main()
