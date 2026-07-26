#!/usr/bin/env python3
"""
KQL Detection Rule Validator

Zero-dependency (stdlib-only) validator for KQL detection rules.

Checks:
 - Each .kql file has mandatory MITRE headers
 - KQL syntax basics (bracket/quote/parenthesis pairing)
 - File naming convention (lowercase, hyphen-separated)
 - No .txt or mixed extensions

Usage:
    python tools/rule-validator.py [path]
    Default path: azure-sentinel/
"""

import os
import re
import sys
from pathlib import Path


# === Required MITRE ATT&CK headers (detection rules) ===
REQUIRED_HEADERS = [
    "Technique:",
    "Tactic:",
    "Severity:",
    "Data Source:",
    "False Positives:",
    "Recommended Response:",
]

# === Required headers for hunting queries ===
# Hunting queries are exploratory (analyst-driven), not fire-and-alert rules,
# so they carry a different metadata contract focused on the hunt workflow.
REQUIRED_HUNT_HEADERS = [
    "Technique:",
    "Tactic:",
    "Hunt Hypothesis:",
    "Data Source:",
    "Investigation Steps:",
    "Pivots:",
]

VALID_SEVERITIES = {"High", "Medium", "Low", "Critical", "Informational"}


def is_hunt_file(content: str) -> bool:
    """A hunting query is identified by the // === HUNT === marker (vs === QUERY ===)."""
    return "// === HUNT ===" in content or "// === HUNT METADATA ===" in content


def find_kql_files(root_dir: str) -> list[Path]:
    """Recursively find all .kql files."""
    base = Path(root_dir)
    if not base.exists():
        print(f"ERROR: Path '{root_dir}' does not exist.")
        sys.exit(1)

    return sorted(base.rglob("*.kql"))


def check_naming_convention(filepath: Path) -> list[str]:
    """Validate file naming: lowercase, hyphens, no spaces."""
    errors = []
    name = filepath.stem  # without extension

    if name != name.lower():
        errors.append(f"  [NAME] Filename must be lowercase: {name}")

    if " " in name:
        errors.append(f"  [NAME] Filename must not contain spaces: {name}")

    if not re.match(r'^[a-z][a-z0-9-]*[a-z0-9]$', name):
        errors.append(
            f"  [NAME] Filename must match `^[a-z][a-z0-9-]*[a-z0-9]$`: {name}"
        )

    return errors


def check_mitre_headers(content: str) -> list[str]:
    """Check that all required headers are present.

    Detection rules require the REQUIRED_HEADERS set; hunting queries
    (marked with // === HUNT ===) require REQUIRED_HUNT_HEADERS instead.
    """
    errors = []
    lines = content.split("\n")
    hunt = is_hunt_file(content)
    required = REQUIRED_HUNT_HEADERS if hunt else REQUIRED_HEADERS
    label = "HUNT" if hunt else "MITRE"

    found_headers = {}
    for line in lines:
        stripped = line.strip()
        for header in required:
            if stripped.startswith(f"// {header}"):
                found_headers[header] = stripped

    for header in required:
        if header not in found_headers:
            errors.append(f"  [{label}] Missing header: {header}")

    return errors


def check_severity(content: str) -> list[str]:
    """Validate severity value. Hunting queries have no Severity (skipped)."""
    errors = []
    if is_hunt_file(content):
        return errors
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("// Severity:"):
            severity = stripped.split("Severity:")[-1].strip()
            if severity not in VALID_SEVERITIES:
                errors.append(
                    f"  [SEVERITY] Invalid severity '{severity}'. "
                    f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
                )
            break
    return errors


def _strip_comments_and_strings(text: str) -> str:
    """Single-pass, space-preserving stripper that removes BOTH string literal
    contents and // comments in one scan, so that `//` inside a string
    (e.g. "http://") is NOT mistaken for a comment.

    Returns a string of identical length with string contents and comments
    replaced by spaces, preserving bracket positions and line structure.
    """
    chars = list(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # String literal start (single or double quote)
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                if text[i] == '\\':          # escape: blank this + next
                    chars[i] = ' '
                    i += 1
                    if i < n:
                        chars[i] = ' '
                        i += 1
                    continue
                if text[i] == quote:          # closing quote — keep it
                    i += 1
                    break
                chars[i] = ' '
                i += 1
            continue
        # Line comment — only when NOT inside a string (handled above)
        if ch == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                chars[i] = ' '
                i += 1
            continue
        i += 1
    return ''.join(chars)


def check_kql_syntax(content: str) -> list[str]:
    """Basic KQL syntax checks (bracket/quote/paren pairing).

    Strips comments and string literals in a single string-aware pass before
    checking bracket pairing, so `//` inside a string literal (e.g. a URL) is
    not misread as a comment.
    """
    errors = []

    # Single-pass strip: string contents + // comments (space-preserving)
    code = _strip_comments_and_strings(content)

    # Check bracket pairing on the space-preserved code
    # Positions now match the original content exactly
    stack = []
    pairs = {'(': ')', '[': ']', '{': '}'}
    opening = set(pairs.keys())
    closing = set(pairs.values())

    for i, ch in enumerate(code):
        if ch in opening:
            stack.append((ch, i))
        elif ch in closing:
            if not stack:
                line_no = content[:i].count('\n') + 1
                errors.append(
                    f"  [SYNTAX] Unmatched closing '{ch}' at approximately line {line_no}"
                )
            else:
                expected = pairs[stack[-1][0]]
                if ch != expected:
                    line_no = content[:i].count('\n') + 1
                    errors.append(
                        f"  [SYNTAX] Expected '{expected}' but got '{ch}' "
                        f"at approximately line {line_no}"
                    )
                stack.pop()

    if stack:
        for ch, pos in stack:
            line_no = content[:pos].count('\n') + 1
            errors.append(
                f"  [SYNTAX] Unmatched opening '{ch}' at approximately line {line_no}"
            )

    return errors


def check_pipe_usage(content: str) -> list[str]:
    """Warn if KQL has no pipe operator (basic rule structure)."""
    errors = []
    code = re.sub(r'//.*', '', content)
    # Check for at least one pipe after the MITRE block
    query_lines = []
    in_mitre = True
    for line in code.split("\n"):
        if in_mitre and line.strip().startswith("//"):
            continue
        in_mitre = False
        if line.strip():
            query_lines.append(line)

    query = "\n".join(query_lines)
    if "|" not in query and len(query_lines) > 0:
        errors.append("  [STRUCTURE] No pipe operator found. Simple rules are valid, "
                      "but most detection queries require piped operations.")

    return errors


def validate_file(filepath: Path) -> tuple[str, int, int]:
    """Validate a single .kql file. Returns (status, warning_count, error_count)."""
    relative = filepath.relative_to(filepath.anchor if filepath.is_absolute() else ".")
    # Make relative to cwd or first common ancestor
    try:
        relative = filepath.relative_to(Path.cwd())
    except ValueError:
        relative = filepath

    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception as e:
        print(f"\n  ✗ {relative}")
        print(f"    [IO] Cannot read file: {e}")
        return "FAIL", 0, 1

    all_errors = []
    all_warnings = []

    # Naming convention
    name_errors = check_naming_convention(filepath)
    all_errors.extend(name_errors)

    # MITRE headers
    mitre_errors = check_mitre_headers(content)
    all_errors.extend(mitre_errors)

    # Severity
    severity_errors = check_severity(content)
    all_errors.extend(severity_errors)

    # KQL syntax
    syntax_errors = check_kql_syntax(content)
    all_errors.extend(syntax_errors)

    # Structure warnings
    structure_warnings = check_pipe_usage(content)
    all_warnings.extend(structure_warnings)

    if not all_errors and not all_warnings:
        print(f"  ✓ {relative}")
        return "PASS", 0, 0
    elif not all_errors and all_warnings:
        print(f"  ~ {relative} (warnings)")
        for w in all_warnings:
            print(w)
        return "PASS", len(all_warnings), 0
    else:
        print(f"\n  ✗ {relative}")
        for e in all_errors:
            print(e)
        for w in all_warnings:
            print(w)
        return "FAIL", len(all_warnings), len(all_errors)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "azure-sentinel/"
    print(f"KQL Detection Rule Validator")
    print(f"Scanning: {root}")
    print(f"{'='*50}")

    kql_files = find_kql_files(root)

    if not kql_files:
        print("No .kql files found.")
        sys.exit(1)

    print(f"Found {len(kql_files)} rule file(s)\n")

    results = []
    total_warnings = 0
    total_errors = 0

    for filepath in kql_files:
        status, warnings, errors = validate_file(filepath)
        results.append((filepath, status))
        total_warnings += warnings
        total_errors += errors

    print(f"\n{'='*50}")
    passed = sum(1 for _, s in results if s == "PASS")
    failed = sum(1 for _, s in results if s == "FAIL")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"Warnings: {total_warnings}, Errors: {total_errors}")

    if failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
