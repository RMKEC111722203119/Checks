#!/usr/bin/env python3
"""T02 - Function Naming Convention.

Independent test case. All naming logic is intentionally contained in this file.
It does not import another test, an SDK, or shared check utilities.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

TEST_ID = "T02"
TEST_NAME = "Function Naming Convention"
TEST_VERSION = "1.0.0"
DEFAULT_SEVERITY = "High"
DEFAULT_CONFIDENCE = "Certain"
SUPPORTED_EXTENSIONS = [".py", ".sql", ".js", ".jsx", ".ts", ".tsx", ".ipynb"]

PATTERNS = {
    "snake_case": r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    "camelCase": r"^[a-z][a-zA-Z0-9]*$",
    "PascalCase": r"^[A-Z][a-zA-Z0-9]*$",
}


def metadata() -> dict[str, Any]:
    return {
        "test_id": TEST_ID,
        "test_name": TEST_NAME,
        "test_version": TEST_VERSION,
        "description": "Checks function, method, SQL function and macro names against language-specific naming conventions.",
        "default_severity": DEFAULT_SEVERITY,
        "default_confidence": DEFAULT_CONFIDENCE,
        "supported_extensions": SUPPORTED_EXTENSIONS,
        "parameters": {
            "styles": {
                "python": "snake_case",
                "sql": "snake_case",
                "javascript": "camelCase",
                "typescript": "camelCase"
            },
            "custom_patterns": {},
            "maximum_length": 60,
            "allow_leading_underscore": True,
            "ignore_dunder_methods": True,
            "ignored_names": ["setUp", "tearDown", "setUpClass", "tearDownClass"],
        },
    }


def split_words(value: str) -> list[str]:
    return re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", value.replace("-", "_").replace(" ", "_"))


def convert_name(value: str, style: str) -> str:
    prefix = value[: len(value) - len(value.lstrip("_"))]
    words = [word.lower() for word in split_words(value.lstrip("_"))]
    if not words:
        return value
    if style == "snake_case":
        converted = "_".join(words)
    elif style == "camelCase":
        converted = words[0] + "".join(word.capitalize() for word in words[1:])
    elif style == "PascalCase":
        converted = "".join(word.capitalize() for word in words)
    else:
        return value
    return prefix + converted


def line_evidence(source: str, line_number: int) -> str:
    lines = source.splitlines()
    return lines[line_number - 1].strip()[:500] if 0 < line_number <= len(lines) else ""


def python_definitions(source: str) -> list[dict[str, Any]]:
    tree = ast.parse(source)
    definitions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
            definitions.append({
                "name": node.name,
                "line": node.lineno,
                "column": node.col_offset + len(prefix) + 1,
                "kind": "function",
            })
    return definitions


def notebook_definitions(source: str) -> list[dict[str, Any]]:
    notebook = json.loads(source)
    definitions = []
    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue
        cell_source = cell.get("source", "")
        cell_source = "".join(cell_source) if isinstance(cell_source, list) else str(cell_source)
        cleaned = "\n".join("" if line.lstrip().startswith(("%", "!")) else line for line in cell_source.splitlines())
        try:
            found = python_definitions(cleaned)
        except SyntaxError:
            found = []
        for item in found:
            item["cell_number"] = cell_number
            item["evidence"] = line_evidence(cell_source, item["line"])
            definitions.append(item)
    return definitions


def regex_definitions(source: str, language: str) -> list[dict[str, Any]]:
    if language in {"javascript", "typescript"}:
        expressions = [
            (re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("), "function"),
            (re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=>"), "function"),
        ]
    else:
        expressions = [
            (re.compile(r"\bcreate\s+(?:or\s+replace\s+)?(?:temporary\s+|temp\s+)?function\s+(?:if\s+not\s+exists\s+)?(?:[\w`\"\[\]]+\.){0,2}[`\"\[]?([A-Za-z_]\w*)[`\"\]]?", re.I), "sql_function"),
            (re.compile(r"\{%-?\s*macro\s+([A-Za-z_]\w*)\s*\("), "macro"),
        ]
    definitions = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if line.lstrip().startswith(("//", "--", "#", "*")):
            continue
        for expression, kind in expressions:
            for match in expression.finditer(line):
                definitions.append({
                    "name": match.group(1),
                    "line": line_number,
                    "column": match.start(1) + 1,
                    "kind": kind,
                })
    return definitions


def execute(request: dict[str, Any]) -> dict[str, Any]:
    project_dir = Path(request["project_dir"]).resolve()
    files = sorted({str(path).replace("\\", "/") for path in request.get("files", [])})
    configured = request.get("test_configuration", {}) or {}
    parameters = {**metadata()["parameters"], **(configured.get("parameters", {}) or {})}
    parameters["styles"] = {**metadata()["parameters"]["styles"], **(parameters.get("styles", {}) or {})}
    severity = configured.get("severity") or DEFAULT_SEVERITY
    confidence = configured.get("confidence") or DEFAULT_CONFIDENCE

    styles = parameters["styles"]
    custom_patterns = parameters.get("custom_patterns", {}) or {}
    maximum_length = int(parameters.get("maximum_length", 60) or 0)
    allow_leading_underscore = bool(parameters.get("allow_leading_underscore", True))
    ignore_dunder = bool(parameters.get("ignore_dunder_methods", True))
    ignored_names = set(parameters.get("ignored_names", []))

    language_by_extension = {
        ".py": "python", ".ipynb": "python", ".sql": "sql",
        ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
    }
    findings = []
    scanned = 0
    warnings = []

    for file_path in files:
        extension = Path(file_path).suffix.lower()
        language = language_by_extension.get(extension)
        if not language:
            continue
        absolute_path = (project_dir / file_path).resolve()
        if project_dir != absolute_path and project_dir not in absolute_path.parents:
            warnings.append(f"Ignored unsafe path: {file_path}")
            continue
        if not absolute_path.is_file():
            warnings.append(f"File was supplied but not found: {file_path}")
            continue

        scanned += 1
        source = absolute_path.read_text(encoding="utf-8", errors="replace")
        try:
            if extension == ".ipynb":
                definitions = notebook_definitions(source)
            elif language == "python":
                definitions = python_definitions(source)
            else:
                definitions = regex_definitions(source, language)
        except (SyntaxError, ValueError, json.JSONDecodeError) as exc:
            warnings.append(f"Could not parse {file_path}: {type(exc).__name__}: {exc}")
            continue

        style = styles.get(language, "snake_case")
        pattern_text = custom_patterns.get(language) if style == "custom" else PATTERNS.get(style)
        if not pattern_text:
            raise ValueError(f"T02 has no pattern for language '{language}' and style '{style}'.")
        pattern = re.compile(pattern_text)

        for definition in definitions:
            name = definition["name"]
            if name in ignored_names:
                continue
            if ignore_dunder and name.startswith("__") and name.endswith("__"):
                continue
            comparison_name = name.lstrip("_") if allow_leading_underscore else name
            evidence = definition.get("evidence") or line_evidence(source, definition["line"])
            cell_number = definition.get("cell_number")

            if comparison_name and not pattern.fullmatch(comparison_name):
                suggested = convert_name(name, style)
                findings.append({
                    "test_id": TEST_ID,
                    "test_name": TEST_NAME,
                    "test_version": TEST_VERSION,
                    "severity": severity,
                    "confidence": confidence,
                    "category": "Naming Convention",
                    "language": language,
                    "file_path": file_path,
                    "line_number": definition["line"],
                    "column_number": definition["column"],
                    "end_line_number": definition["line"],
                    "end_column_number": definition["column"] + len(name),
                    "cell_number": cell_number,
                    "symbol": name,
                    "symbol_type": definition["kind"],
                    "evidence": evidence,
                    "reason": f"{definition['kind'].replace('_', ' ').title()} name '{name}' does not follow the configured '{style}' convention for {language}.",
                    "expected": f"Name matching {pattern_text}",
                    "suggestion": f"Rename '{name}' to '{suggested}'." if suggested != name else f"Rename '{name}' to follow {style}.",
                    "documentation_reference": "Project function naming standard",
                    "blocking_recommendation": severity.lower() in {"critical", "high"},
                })

            if maximum_length and len(name) > maximum_length:
                findings.append({
                    "test_id": TEST_ID,
                    "test_name": TEST_NAME,
                    "test_version": TEST_VERSION,
                    "severity": severity,
                    "confidence": confidence,
                    "category": "Naming Convention",
                    "language": language,
                    "file_path": file_path,
                    "line_number": definition["line"],
                    "column_number": definition["column"],
                    "end_line_number": definition["line"],
                    "end_column_number": definition["column"] + len(name),
                    "cell_number": cell_number,
                    "symbol": name,
                    "symbol_type": definition["kind"],
                    "evidence": evidence,
                    "reason": f"Name '{name}' is {len(name)} characters long; the configured maximum is {maximum_length}.",
                    "expected": f"Name with no more than {maximum_length} characters",
                    "suggestion": f"Shorten '{name}' while preserving its meaning.",
                    "documentation_reference": "Project function naming standard",
                    "blocking_recommendation": severity.lower() in {"critical", "high"},
                })

    findings.sort(key=lambda item: (item["file_path"], item.get("cell_number") or 0, item.get("line_number") or 0, item.get("column_number") or 0))
    return {
        "contract_version": "1.0",
        "test": metadata(),
        "status": "FAILED" if findings else "PASSED",
        "summary": f"{len(findings)} function naming violation(s) found across {scanned} supported file(s).",
        "files_received": len(files),
        "files_scanned": scanned,
        "findings_count": len(findings),
        "findings": findings,
        "warnings": warnings,
        "errors": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=TEST_NAME)
    parser.add_argument("--describe", action="store_true", help="Print test metadata as JSON.")
    parser.add_argument("--input", help="Input JSON path supplied by the orchestrator.")
    parser.add_argument("--output", help="Output JSON path written by this test.")
    args = parser.parse_args()

    if args.describe:
        print(json.dumps(metadata(), indent=2))
        return 0
    if not args.input or not args.output:
        parser.error("--input and --output are required unless --describe is used.")

    try:
        with open(args.input, encoding="utf-8") as handle:
            request = json.load(handle)
        response = execute(request)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(response, handle, indent=2)
        return 0
    except Exception as exc:
        response = {
            "contract_version": "1.0",
            "test": metadata(),
            "status": "ERROR",
            "summary": f"{type(exc).__name__}: {exc}",
            "files_received": 0,
            "files_scanned": 0,
            "findings_count": 0,
            "findings": [],
            "errors": [{"type": type(exc).__name__, "message": str(exc)}],
        }
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(response, handle, indent=2)
        print(response["summary"], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
