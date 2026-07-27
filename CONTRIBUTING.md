# Contributing

Thanks for considering contributing to the KQL Detection Library. Here's how.

## Quickstart

```bash
git clone https://github.com/rizko-d/kql-detection-library.git
cd kql-detection-library
make check  # validate everything
```

## Adding a new rule

```bash
python tools/rule-scaffold.py rule \
    --name my-new-rule \
    --category credential-access \
    --technique T1003.001 \
    --tactic "Credential Access" \
    --severity High \
    --data-source "SecurityEvent (Windows)"

# Fill in the TODOs in the generated .kql file, then:

python tools/rule-validator.py azure-sentinel/
python tools/rule-dependency-checker.py
python tools/coverage-report.py --write   # refresh ATT&CK coverage matrix
python tools/fp-report.py                  # check FP hardening score
```

## Adding a hunting query

```bash
python tools/rule-scaffold.py hunt \
    --name my-hunt \
    --technique T1078 \
    --tactic "Initial Access" \
    --data-source "SigninLogs"
```

## Before submitting a PR

Run the full check suite:

```bash
make check
```

This runs:
- `rule-validator.py` — checks all 6 MITRE or hunt headers + KQL syntax
- `rule-dependency-checker.py` — verifies every rule has a test case + yaml entry
- `coverage-report.py --check` — confirms ATTACK_MATRIX.md is in sync with rules
- `kql-test-framework.py` — validates test cases have Expected: annotations

All must pass before merge. CI enforces this automatically on every PR.

## Conventions

- **Detection rules**: `// === MITRE ATT&CK ===` header block → `// === QUERY ===` → KQL
- **Hunting queries**: `// === HUNT ===` header block → `// === QUERY ===` → KQL
- **No `| take N`** — let Sentinel Analytics control result caps
- **No trailing newline** at EOF — last line ends with the query, no blank line
- **Lowercase, hyphen-separated filenames**: `brute-force-rdp.kql`, not `BruteForceRDP.kql`
- **Test case for every rule**: `mapping/test-cases/test-<rule-stem>.kql`

## Project structure

```
azure-sentinel/           # detection rules by tactic
hunting-queries/          # analyst-driven hunting queries
mapping/
  mitre-attack.yaml       # technique→rule mapping
  test-cases/             # datatable-based test fixtures per rule
tools/                    # zero-dependency CLI tools
docs/                     # guides (watchlist, FP coverage)
ATTACK_MATRIX.md          # auto-generated tactic coverage matrix
Makefile                  # quick validation + deploy targets
```
