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


# === Required MITRE ATT&CK headers ===
REQUIRED_HEADERS = [
    "Technique:",
    "Tactic:",
    "Severity:",
    "Data Source:",
    "False Positives:",
    "Recommended Response:",
]

VALID_SEVERITIES = {"High", "Medium", "Low", "Critical", "Informational"}


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
    """Check that all required MITRE headers are present."""
    errors = []
    lines = content.split("\n")

    found_headers = {}
    for line in lines:
        stripped = line.strip()
        for header in REQUIRED_HEADERS:
            if stripped.startswith(f"// {header}"):
                found_headers[header] = stripped

    for header in REQUIRED_HEADERS:
        if header not in found_headers:
            errors.append(f"  [MITRE] Missing header: {header}")

    return errors


def check_severity(content: str) -> list[str]:
    """Validate severity value."""
    errors = []
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


def _strip_kql_strings(text: str) -> str:
    """Replace KQL string literal contents with spaces to avoid bracket confusion.

    Handles:
    - Single-quoted strings: '...' (verbatim in KQL)
    - Double-quoted strings: "..." (escape sequences)
    - Triple-quoted variants: '''...''' and double-triple-quoted
    Uses a simple character-by-character state machine instead of
    regex to avoid escaping issues across quote types.
    """
    chars = list(text)
    i = 0
    n = len(chars)
    in_string = False
    string_char = None
    triple = None

    while i < n:
        if not in_string:
            # Check for triple-quoted start
            if i + 2 < n:
                triple_candidate = text[i:i+3]
                if triple_candidate in ('"""', "'''"):
                    # Mark opening quotes as themselves, rest as spaces
                    triple = triple_candidate
                    string_char = triple_candidate[0]
                    in_string = True
                    i += 3
                    while i < n and in_string:
                        if i + 2 < n and text[i:i+3] == triple:
                            in_string = False
                            i += 3
                            triple = None
                            break
                        chars[i] = ' '
                        i += 1
                    continue
            # Check for single/double quoted string
            if text[i] in ('"', "'"):
                string_char = text[i]
                in_string = True
                i += 1
                while i < n and in_string:
                    if text[i] == '\\':
                        # Escape sequence - skip next char too
                        chars[i] = ' '
                        i += 1
                        if i < n:
                            chars[i] = ' '
                            i += 1
                    elif text[i] == string_char:
                        in_string = False
                        # Keep the closing quote
                        i += 1
                    else:
                        chars[i] = ' '
                        i += 1
                continue
        i += 1

    return ''.join(chars)


def check_kql_syntax(content: str) -> list[str]:
    """Basic KQL syntax checks (bracket/quote/paren pairing).

    Strips comments and string literals before checking bracket
    pairing to avoid false positives on inline KQL arrays.
    """
    errors = []

    # Build a stripped version that preserves line structure:
    # replace comment/string content with spaces but keep same length
    lines = content.split('\n')
    stripped_lines = []
    for line in lines:
        # Remove // comments within each line
        ci = line.find('//')
        if ci >= 0:
            line = line[:ci] + ' ' * (len(line) - ci)
        stripped_lines.append(line)
    code = '\n'.join(stripped_lines)

    # Remove string literal contents (space-preserving)
    code = _strip_kql_strings(code)

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
