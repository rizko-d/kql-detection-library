#!/usr/bin/env python3
"""
fp-report.py — False-Positive tuning coverage report.

Zero-dependency (stdlib only).

For each detection rule this reports:
  - Whether the rule documents a "False Positives:" section (and how many entries)
  - Whether it documents "Recommended Response:" steps
  - Whether its test case includes BOTH a malicious and a benign/should-NOT-fire row
    (a good FP-tuning signal — the test proves the rule doesn't over-fire)
  - A simple "FP-hardening score" per rule (0-3)

Produces a markdown table you can paste into a dashboard or wiki.

Usage:
    python tools/fp-report.py               # markdown table to stdout
    python tools/fp-report.py --out docs/fp-coverage.md
    python tools/fp-report.py --min-score 2 # exit 1 if any rule scores below 2
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "azure-sentinel"
TESTS_DIR = ROOT / "mapping" / "test-cases"


def count_fp_entries(text: str) -> int:
    """Count bullet entries under the // False Positives: header."""
    lines = text.splitlines()
    count, in_fp = 0, False
    for line in lines:
        s = line.strip()
        if s.startswith("// False Positives:"):
            in_fp = True
            continue
        if in_fp:
            if s.startswith("// Recommended Response:") or s.startswith("// === QUERY ==="):
                break
            if re.match(r'^//\s*-\s+\S', s):
                count += 1
    return count


def has_response(text: str) -> bool:
    return bool(re.search(r'^//\s*Recommended Response:', text, re.M))


def test_has_benign(test_text: str) -> bool:
    """Heuristic: a benign/should-not-fire row is documented in the test."""
    tl = test_text.lower()
    return any(k in tl for k in ("benign", "should not fire", "should stay", "not fire", "lower severity"))


def main():
    ap = argparse.ArgumentParser(description="False-positive tuning coverage report")
    ap.add_argument("--out", default="")
    ap.add_argument("--min-score", type=int, default=0,
                    help="exit 1 if any rule scores below this (0-3)")
    args = ap.parse_args()

    rows = []
    test_stems = {p.stem: p for p in TESTS_DIR.glob("*.kql")}

    for rule in sorted(RULES_DIR.rglob("*.kql")):
        text = rule.read_text(encoding="utf-8")
        fp_count = count_fp_entries(text)
        resp = has_response(text)
        test_path = test_stems.get(f"test-{rule.stem}")
        benign = test_has_benign(test_path.read_text(encoding="utf-8")) if test_path else False

        score = (1 if fp_count > 0 else 0) + (1 if resp else 0) + (1 if benign else 0)
        rows.append((rule.relative_to(ROOT).as_posix(), fp_count, resp, benign, score))

    # Render markdown
    lines = ["# False-Positive Tuning Coverage", "",
             f"**Rules analyzed:** {len(rows)} | "
             f"**Avg FP-hardening score:** {sum(r[4] for r in rows)/max(len(rows),1):.2f} / 3",
             "",
             "Score = has_FP_section + has_response + test_has_benign_row (0-3).",
             "",
             "| Rule | FP entries | Response | Benign test row | Score |",
             "|---|---|---|---|---|"]
    for rel, fp, resp, benign, score in sorted(rows, key=lambda x: x[4]):
        lines.append(f"| {rel} | {fp} | {'✅' if resp else '❌'} | "
                     f"{'✅' if benign else '❌'} | {score}/3 |")
    md = "\n".join(lines)

    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(md + "\n", encoding="utf-8")
        print(f"Wrote FP coverage report to {args.out}", file=sys.stderr)
    else:
        print(md)

    if args.min_score > 0:
        low = [r for r in rows if r[4] < args.min_score]
        if low:
            print(f"\n{len(low)} rule(s) below min-score {args.min_score}:", file=sys.stderr)
            for rel, _, _, _, score in low:
                print(f"  {rel}: {score}/3", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
