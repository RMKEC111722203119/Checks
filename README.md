# Checks Repository

This repository contains independent Python code-standard checks. Each check has exactly two required files:

```text
checks/<check_folder>/
├── test.yml          # discovery metadata and defaults
└── Txx_name.py       # independent Python implementation
```

There is no SDK, no shared business-rule code, and no generic `check.py`. Even when two checks need similar helper logic, each check keeps its own implementation.

## Structure

```text
checks-repo/
├── checks/
│   ├── folder_naming_convention/
│   │   ├── test.yml
│   │   └── T01_folder_naming_convention.py
│   └── function_naming_convention/
│       ├── test.yml
│       └── T02_function_naming_convention.py
├── docs/
│   ├── ADDING_NEW_TEST_CASE.md
│   └── TEST_CONTRACT.md
├── orchestrator.py
├── prompt.md
├── requirements.txt
└── VERSION
```

## Why `test.yml` exists

The Code Standards Tool must discover checks without hardcoding T01, T02 or future tests. It scans `checks/**/test.yml`, reads the entrypoint and defaults, then runs the referenced Python file.

`test.yml` contains only test metadata and configuration defaults:

```yaml
test_id: T02
test_name: Function Naming Convention
entrypoint: T02_function_naming_convention.py
severity: High
confidence: Certain
supported_extensions: [.py, .sql]
timeout_seconds: 180
parameters: {}
```

The Python file contains the actual rule. Adding T03 requires no orchestrator change.

## Production flow

```text
Code Standards Tool
  1. clones the branch requested by the client
  2. discovers checks/**/test.yml
  3. selects requested checks or folders
  4. sends an isolated project path and authoritative file list to each Python entrypoint
  5. receives structured JSON findings
  6. creates Excel and JSON reports
  7. uploads reports to Azure Blob Storage
  8. returns the Excel read/download link to CLI and CI
```

Excel, Blob upload, remote CLI and CI behaviour belong to the Code Standards Tool, not this repository.

## Included checks

### T01 Folder Naming Convention

Checks folders represented by the supplied files. It supports snake_case, kebab-case, lower case, PascalCase, camelCase and a custom regex. Folder findings use a null line number because a folder has no source-code line.

### T02 Function Naming Convention

Checks Python and notebook functions, JavaScript/TypeScript functions, SQL functions and dbt/Jinja macros. It returns exact file, line, column, evidence, reason, expected convention and a suggested name.

## Check-author commands

```bash
pip install -r requirements.txt
python orchestrator.py --list
python orchestrator.py --target ../client-app --output-dir output
python orchestrator.py --target ../client-app --include-test T02 --output-dir output
python orchestrator.py --target ../client-app --include-test checks/function_naming_convention
python orchestrator.py --target ../client-app --exclude-test T01
```

Local outputs:

```text
output/results.json
output/findings.csv
```

Exit codes: `0` clean, `1` findings, `2` execution/configuration error.

## Branches

Every branch is a complete independent catalogue, for example:

```text
main
dev/data-engineering
dev/sql-standards
dev/python-security
```

The Code Standards Tool clones one requested branch. It does not merge tests from multiple branches during a run.
