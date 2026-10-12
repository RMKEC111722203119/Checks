# AI Prompt for Creating an Independent Check

Copy the prompt below into an approved AI coding assistant and replace all `<...>` values.

---

Create one production-quality code-standard check for this repository.

## Required deliverables

Generate exactly these two files and no others:

```text
checks/<snake_case_folder>/test.yml
checks/<snake_case_folder>/T<NN>_<snake_case_name>.py
```

## Independence rules


- Do not import another check.
- Do not import `orchestrator.py`.
- Do not create shared utilities.
- Duplicate helper logic inside this check when needed.
- Prefer the Python standard library.
- Do not create test suites, fixtures, CI workflows, Excel logic or Azure code.

## Check definition

```text
ID: <T03>
Name: <Sensitive Client Data Exposure>
Folder: <sensitive_client_data_exposure>
Python file: <T03_sensitive_client_data_exposure.py>
Description: <Detect possible client-sensitive values committed in source files>
Default severity: <Medium>
Default confidence: <Likely>
Category: <Data Security>
Supported extensions: <.py, .sql, .md, .json, .jsonl, .yml, .yaml, .txt>
Timeout seconds: <180>
Configurable parameters: <ignored_paths, ignored_patterns, detection_patterns, maximum_evidence_length>
```

## `test.yml` requirements

It must contain:

```yaml
test_id: <T03>
test_name: <name>
test_version: 1.0.0
description: <description>
entrypoint: <T03_name.py>
severity: <Critical|High|Medium|Low>
confidence: <Certain|Likely|Possible>
category: <category>
supported_extensions: []
timeout_seconds: 180
enabled_by_default: true
parameters: {}
```

Do not put executable logic in YAML.

## Python command contract

The Python file must support:

```bash
python T<NN>_<name>.py --input request.json --output response.json
```

Input:

```json
{
  "contract_version": "1.0",
  "project_dir": "/isolated/client/source",
  "files": ["src/file.py"],
  "test_configuration": {
    "severity": "Medium",
    "confidence": "Likely",
    "parameters": {}
  },
  "execution_context": {}
}
```

Rules:

- `files` is authoritative. Do not recursively scan `project_dir`.
- Validate that every path remains under `project_dir`.
- Do not modify source files.
- Ignore unsupported file extensions.
- Continue when one file is unreadable and record a warning.
- The same input must produce the same ordered output.

Output:

```json
{
  "contract_version": "1.0",
  "test": {
    "test_id": "T03",
    "test_name": "Sensitive Client Data Exposure",
    "test_version": "1.0.0"
  },
  "status": "PASSED | FAILED | ERROR",
  "summary": "...",
  "files_received": 0,
  "files_scanned": 0,
  "findings_count": 0,
  "findings": [],
  "warnings": [],
  "errors": []
}
```

Every finding must provide as much useful detail as available:

```json
{
  "test_id": "T03",
  "test_name": "Sensitive Client Data Exposure",
  "test_version": "1.0.0",
  "severity": "Medium",
  "confidence": "Likely",
  "category": "Data Security",
  "language": "Any",
  "file_path": ".dbx_quality_ai/audit_log.jsonl",
  "line_number": 1,
  "column_number": 1,
  "end_line_number": 1,
  "end_column_number": 50,
  "cell_number": null,
  "symbol": null,
  "symbol_type": null,
  "evidence": "masked or safe evidence, maximum 500 characters",
  "reason": "Pattern resembling a phone number found in committed code",
  "expected": "Client-sensitive values must not be committed",
  "suggestion": "Remove or mask the value and store it in an approved secure system",
  "documentation_reference": "Client data handling standard",
  "blocking_recommendation": false
}
```

Quality rules:

- Give exact 1-based line and column numbers where possible.
- Evidence must be concise and safe.
- For secret or sensitive-data rules, mask detected values. Never reproduce complete credentials or sensitive values.
- Explain what matched and why it matters.
- Give a specific remediation.
- Avoid duplicate findings for the same file, line, column and reason.
- Sort findings by file, cell, line and column.
- A completed scan with findings returns `status: FAILED` and process exit code `0`.
- A clean scan returns `status: PASSED` and exit code `0`.
- An unrecoverable problem writes `status: ERROR` and returns exit code `2`.

## Rule-specific requirements

```text
<Describe exact detection logic, inclusions, exclusions, false-positive protections,
confidence assignment, evidence masking and remediation.>
```

Return the complete contents of the two requested files only. Do not generate other files.
