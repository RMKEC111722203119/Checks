# Adding a New Independent Check

## 1. Assign a permanent ID

Use the next ID, such as T03. Never reuse deleted IDs because historical reports refer to them.

## 2. Create two files

```text
checks/<snake_case_folder>/test.yml
checks/<snake_case_folder>/T03_<snake_case_name>.py
```

`test.yml` is the discovery record. The Python file is the full independent implementation.

## 3. Keep the check independent

Do not import another check, an SDK, shared business-rule helpers or the orchestrator. Duplicate helper code when necessary. This avoids branch coupling and lets one check be copied or changed without affecting another.

## 4. Manifest fields

Required fields are:

```yaml
test_id: T03
test_name: Example Test
test_version: 1.0.0
description: Clear purpose
entrypoint: T03_example_test.py
severity: Medium
confidence: Likely
category: Code Quality
supported_extensions: [.py]
timeout_seconds: 180
enabled_by_default: true
parameters: {}
```

The orchestrator discovers `test.yml` files. No source-code change is needed when T03, T04 or T100 is added.

## 5. Follow the JSON contract

Read `docs/TEST_CONTRACT.md`. Only inspect files supplied in `request["files"]`. Return exact location, concise evidence, reason, expectation and remediation.

## 6. Safe evidence

Evidence is written to Excel and Blob reports. Do not expose complete secrets, access tokens or sensitive personal data. Mask the matched value while preserving enough context for the developer.

## 7. Failure isolation

A bad file should produce a warning and scanning should continue. Use ERROR only when the check itself cannot complete.

## 8. Manual validation

```bash
python orchestrator.py --list
python orchestrator.py --target ../sample-client --include-test T03 --output-dir output
```

Inspect `output/results.json` and `output/findings.csv`.

## 9. Versioning

Increment `test_version` whenever behaviour changes. Increment repository `VERSION` whenever a branch release changes its check catalogue or behaviour.
