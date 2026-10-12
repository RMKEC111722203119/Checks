#!/usr/bin/env python3
"""T01 - Folder Naming Convention.

Independent test case. It receives one JSON request and returns one JSON response.
It has no dependency on an SDK or another test case.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import PurePosixPath
from typing import Any

TEST_ID = "T01"
TEST_NAME = "Folder Naming Convention"
TEST_VERSION = "1.0.0"
DEFAULT_SEVERITY = "Medium"
DEFAULT_CONFIDENCE = "Certain"
SUPPORTED_EXTENSIONS = ["*"]

PATTERNS = {
    "snake_case": r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    "kebab-case": r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$",
    "lowercase": r"^[a-z][a-z0-9]*$",
    "PascalCase": r"^[A-Z][a-zA-Z0-9]*$",
    "camelCase": r"^[a-z][a-zA-Z0-9]*$",
}


def metadata() -> dict[str, Any]:
    return {
        "test_id": TEST_ID,
        "test_name": TEST_NAME,
        "test_version": TEST_VERSION,
        "description": "Checks that folders containing in-scope files follow the configured naming convention.",
        "default_severity": DEFAULT_SEVERITY,
        "default_confidence": DEFAULT_CONFIDENCE,
        "supported_extensions": SUPPORTED_EXTENSIONS,
        "parameters": {
            "style": "snake_case",
            "custom_pattern": None,
            "allow_leading_number": True,
            "ignored_folder_names": [
                ".git", ".github", ".venv", "venv", "__pycache__",
                "node_modules", ".idea", ".vscode"
            ],
            "allowed_folder_names": [],
        },
    }


def suggestion_for(name: str, style: str) -> str:
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", name.replace("-", "_").replace(" ", "_"))
    words = [word.lower() for word in words if word]
    if not words:
        return name
    if style == "snake_case":
        return "_".join(words)
    if style == "kebab-case":
        return "-".join(words)
    if style == "lowercase":
        return "".join(words)
    if style == "PascalCase":
        return "".join(word.capitalize() for word in words)
    if style == "camelCase":
        return words[0] + "".join(word.capitalize() for word in words[1:])
    return name


def execute(request: dict[str, Any]) -> dict[str, Any]:
    files = sorted({str(path).replace("\\", "/") for path in request.get("files", [])})
    configured = request.get("test_configuration", {}) or {}
    parameters = {**metadata()["parameters"], **(configured.get("parameters", {}) or {})}
    severity = configured.get("severity") or DEFAULT_SEVERITY
    confidence = configured.get("confidence") or DEFAULT_CONFIDENCE

    style = str(parameters["style"])
    custom_pattern = parameters.get("custom_pattern")
    if style == "custom":
        if not custom_pattern:
            raise ValueError("T01 parameter 'custom_pattern' is required when style is 'custom'.")
        pattern = re.compile(str(custom_pattern))
    elif style in PATTERNS:
        pattern = re.compile(PATTERNS[style])
    else:
        raise ValueError(f"T01 unsupported style '{style}'. Supported: {', '.join(PATTERNS)}, custom")

    ignored = set(parameters.get("ignored_folder_names", []))
    allowed = set(parameters.get("allowed_folder_names", []))
    allow_leading_number = bool(parameters.get("allow_leading_number", True))

    discovered: dict[str, dict[str, Any]] = {}
    for file_path in files:
        parts = PurePosixPath(file_path).parts[:-1]
        for index in range(len(parts)):
            full_path = "/".join(parts[: index + 1])
            record = discovered.setdefault(full_path, {"name": parts[index], "files": []})
            record["files"].append(file_path)

    findings = []
    for folder_path, info in sorted(discovered.items()):
        name = info["name"]
        if name in ignored or name in allowed:
            continue
        name_to_validate = name
        if allow_leading_number:
            name_to_validate = re.sub(r"^\d+[_-]?", "", name)
        if name_to_validate and pattern.fullmatch(name_to_validate):
            continue

        suggested_name = suggestion_for(name, style)
        parent = str(PurePosixPath(folder_path).parent)
        suggested_path = suggested_name if parent == "." else f"{parent}/{suggested_name}"
        example_file = sorted(info["files"])[0]
        findings.append({
            "test_id": TEST_ID,
            "test_name": TEST_NAME,
            "test_version": TEST_VERSION,
            "severity": severity,
            "confidence": confidence,
            "category": "Naming Convention",
            "language": "Any",
            "file_path": folder_path + "/",
            "line_number": None,
            "column_number": None,
            "end_line_number": None,
            "end_column_number": None,
            "symbol": name,
            "evidence": f"Folder '{folder_path}/' contains {len(info['files'])} in-scope file(s); example: {example_file}",
            "reason": f"Folder name '{name}' does not follow the configured '{style}' naming convention.",
            "expected": f"Folder name matching {custom_pattern if style == 'custom' else style}",
            "suggestion": f"Rename '{folder_path}/' to '{suggested_path}/'.",
            "documentation_reference": "Project folder naming standard",
            "blocking_recommendation": severity.lower() in {"critical", "high"},
        })

    return {
        "contract_version": "1.0",
        "test": metadata(),
        "status": "FAILED" if findings else "PASSED",
        "summary": f"{len(findings)} folder naming violation(s) found across {len(discovered)} folder(s).",
        "files_received": len(files),
        "files_scanned": len(files),
        "findings_count": len(findings),
        "findings": findings,
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
