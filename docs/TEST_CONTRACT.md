# Test Contract Version 1.0

## Commands required from every test

```bash
python Txx_name.py --describe
python Txx_name.py --input request.json --output response.json
```

## Input request

```json
{
  "contract_version": "1.0",
  "project_dir": "/isolated/client/source",
  "files": [
    "src/service.py",
    "sql/functions.sql"
  ],
  "test_configuration": {
    "severity": "High",
    "confidence": "Certain",
    "parameters": {}
  },
  "execution_context": {
    "repository": "ORG/client-app",
    "branch": "feature/example",
    "commit_sha": "abc123",
    "pull_request_number": "25",
    "run_id": "1001"
  }
}
```

`files` is authoritative. A test must not scan unrelated files outside this list.

## Output response

```json
{
  "contract_version": "1.0",
  "test": {
    "test_id": "T02",
    "test_name": "Function Naming Convention",
    "test_version": "1.0.0"
  },
  "status": "FAILED",
  "summary": "1 violation found.",
  "files_received": 10,
  "files_scanned": 5,
  "findings_count": 1,
  "findings": [
    {
      "test_id": "T02",
      "test_name": "Function Naming Convention",
      "test_version": "1.0.0",
      "severity": "High",
      "confidence": "Certain",
      "category": "Naming Convention",
      "language": "python",
      "file_path": "src/service.py",
      "line_number": 42,
      "column_number": 5,
      "end_line_number": 42,
      "end_column_number": 16,
      "cell_number": null,
      "symbol": "GetEmployee",
      "symbol_type": "function",
      "evidence": "def GetEmployee(employee_id):",
      "reason": "Function name does not follow snake_case.",
      "expected": "snake_case function name",
      "suggestion": "Rename 'GetEmployee' to 'get_employee'.",
      "documentation_reference": "Project function naming standard",
      "blocking_recommendation": true
    }
  ],
  "warnings": [],
  "errors": []
}
```

## Required finding fields

```text
test_id
test_name
test_version
severity
confidence
file_path
line_number
evidence
reason
```

## Recommended detailed fields

```text
category
language
column_number
end_line_number
end_column_number
cell_number
symbol
symbol_type
expected
suggestion
documentation_reference
blocking_recommendation
```

## Status meanings

- `PASSED`: the test executed and produced zero findings.
- `FAILED`: the test executed and produced one or more findings.
- `ERROR`: the test could not complete.

A `FAILED` result is not a Python process failure. The test should return exit code `0` after successfully writing findings. Exit code `2` is reserved for execution errors.
