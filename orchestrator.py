#!/usr/bin/env python3
"""Generic local orchestrator for independent Python standard checks.

Discovery is manifest-driven. Every check folder contains:
  test.yml       metadata, entrypoint, defaults and supported parameters
  Txx_name.py    completely independent Python implementation

The production Code Standards Tool will implement the same contract after cloning the
requested checks-repository branch. This local orchestrator exists for check authors.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
CHECKS_ROOT = ROOT / "checks"
REQUIRED_MANIFEST_FIELDS = {
    "test_id", "test_name", "test_version", "description", "entrypoint",
    "severity", "confidence", "category", "supported_extensions",
    "timeout_seconds", "enabled_by_default", "parameters",
}
FINDING_COLUMNS = [
    "test_id", "test_name", "test_version", "severity", "confidence", "category",
    "language", "file_path", "line_number", "column_number", "end_line_number",
    "end_column_number", "cell_number", "symbol", "symbol_type", "evidence",
    "reason", "expected", "suggestion", "documentation_reference",
    "blocking_recommendation",
]
DEFAULT_FILE_EXCLUDES = [
    ".git/**", "**/.git/**", "**/__pycache__/**", "**/.venv/**",
    "**/venv/**", "**/node_modules/**", "**/dist/**", "**/build/**",
]


def discover_tests() -> list[dict[str, Any]]:
    """Discover checks solely from test.yml files; never hardcode a test name or folder."""
    registry: list[dict[str, Any]] = []
    ids: set[str] = set()
    for manifest_path in sorted(CHECKS_ROOT.rglob("test.yml")):
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{manifest_path}: manifest must contain a YAML mapping")
        missing = REQUIRED_MANIFEST_FIELDS - set(data)
        if missing:
            raise ValueError(f"{manifest_path}: missing fields: {', '.join(sorted(missing))}")
        test_id = str(data["test_id"])
        if test_id in ids:
            raise ValueError(f"Duplicate test_id '{test_id}' in {manifest_path}")
        if not test_id.startswith("T") or not test_id[1:].isdigit():
            raise ValueError(f"{manifest_path}: test_id must use format T01, T02, ...")
        ids.add(test_id)
        entrypoint = (manifest_path.parent / str(data["entrypoint"])).resolve()
        if manifest_path.parent.resolve() not in entrypoint.parents or not entrypoint.is_file():
            raise ValueError(f"{manifest_path}: entrypoint is missing or escapes its check folder")
        data["manifest_path"] = manifest_path.relative_to(ROOT).as_posix()
        data["entrypoint_path"] = entrypoint
        registry.append(data)
    return sorted(registry, key=lambda item: int(str(item["test_id"])[1:]))


def selected(manifest: dict[str, Any], includes: list[str], excludes: list[str]) -> bool:
    values = {
        str(manifest["test_id"]), str(manifest["test_name"]),
        str(manifest["manifest_path"]),
        Path(str(manifest["manifest_path"])).parent.as_posix(),
    }
    def match(selectors: list[str]) -> bool:
        return any(any(selector == value or fnmatch.fnmatch(value, selector) for value in values) for selector in selectors)
    return (not includes or match(includes)) and not match(excludes)


def collect_files(project_dir: Path, includes: list[str], excludes: list[str]) -> list[str]:
    result: list[str] = []
    for current_root, directories, filenames in os.walk(project_dir, followlinks=False):
        current = Path(current_root)
        directories[:] = [name for name in directories if not (current / name).is_symlink()]
        for filename in filenames:
            path = current / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(project_dir).as_posix()
            if includes and not any(fnmatch.fnmatch(relative, pattern) for pattern in includes):
                continue
            if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
                continue
            result.append(relative)
    return sorted(result)


def merge_configuration(manifest: dict[str, Any], user_config: dict[str, Any]) -> dict[str, Any]:
    override = (user_config.get("tests", {}) or {}).get(str(manifest["test_id"]), {}) or {}
    return {
        "severity": override.get("severity", manifest["severity"]),
        "confidence": override.get("confidence", manifest["confidence"]),
        "parameters": {**(manifest.get("parameters") or {}), **(override.get("parameters") or {})},
    }


def run_one(manifest: dict[str, Any], project_dir: Path, files: list[str], user_config: dict[str, Any], workspace: Path) -> dict[str, Any]:
    test_id = str(manifest["test_id"])
    request_path = workspace / f"{test_id}_request.json"
    response_path = workspace / f"{test_id}_response.json"
    request = {
        "contract_version": "1.0",
        "project_dir": str(project_dir),
        "files": files,
        "test_configuration": merge_configuration(manifest, user_config),
        "execution_context": user_config.get("execution_context", {}),
    }
    request_path.write_text(json.dumps(request, indent=2), encoding="utf-8")
    started = time.monotonic()
    try:
        process = subprocess.run(
            [sys.executable, str(manifest["entrypoint_path"]), "--input", str(request_path), "--output", str(response_path)],
            cwd=workspace, capture_output=True, text=True,
            timeout=int(manifest["timeout_seconds"]),
        )
        duration = round(time.monotonic() - started, 3)
    except subprocess.TimeoutExpired:
        return error_result(manifest, "TIMEOUT", f"Exceeded {manifest['timeout_seconds']} seconds")

    if not response_path.is_file():
        return error_result(manifest, "ERROR", "Test did not create its output JSON file")
    try:
        response = json.loads(response_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return error_result(manifest, "ERROR", f"Test output is not valid JSON: {exc}")
    response["execution"] = {
        "duration_seconds": duration,
        "exit_code": process.returncode,
        "entrypoint": str(manifest["entrypoint"]),
        "manifest": str(manifest["manifest_path"]),
        "stdout": process.stdout[-4000:],
        "stderr": process.stderr[-4000:],
    }
    return response


def error_result(manifest: dict[str, Any], status: str, message: str) -> dict[str, Any]:
    return {
        "contract_version": "1.0",
        "test": {key: manifest[key] for key in ("test_id", "test_name", "test_version")},
        "status": status, "summary": message, "files_received": 0,
        "files_scanned": 0, "findings_count": 0, "findings": [],
        "warnings": [], "errors": [{"message": message}],
    }


def write_results(output_dir: Path, results: list[dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = [finding for result in results for finding in result.get("findings", [])]
    overall = "ERROR" if any(result.get("status") in {"ERROR", "TIMEOUT"} for result in results) else "FAILED" if findings else "PASSED"
    payload = {
        "contract_version": "1.0", "status": overall,
        "checks_repository_version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "totals": {
            "tests": len(results), "passed": sum(r.get("status") == "PASSED" for r in results),
            "failed": sum(r.get("status") == "FAILED" for r in results),
            "errored": sum(r.get("status") in {"ERROR", "TIMEOUT"} for r in results),
            "findings": len(findings),
        },
        "test_results": results, "findings": findings,
    }
    (output_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    with (output_dir / "findings.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FINDING_COLUMNS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(findings)


def print_results(results: list[dict[str, Any]]) -> None:
    for result in results:
        test = result.get("test", {})
        print(f"\n[{result.get('status')}] {test.get('test_id')} - {test.get('test_name')}")
        print(result.get("summary", ""))
        for finding in result.get("findings", []):
            location = str(finding.get("file_path", ""))
            if finding.get("cell_number"): location += f" [cell {finding['cell_number']}]"
            if finding.get("line_number"): location += f":{finding['line_number']}"
            if finding.get("column_number"): location += f":{finding['column_number']}"
            print(f"  {finding.get('severity')} | {finding.get('confidence')} | {location}")
            print(f"    Evidence: {finding.get('evidence')}")
            print(f"    Reason: {finding.get('reason')}")
            print(f"    Suggestion: {finding.get('suggestion')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Manifest-driven local checks orchestrator")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--include-test", action="append", default=[])
    parser.add_argument("--exclude-test", action="append", default=[])
    parser.add_argument("--include-file", action="append", default=["**"])
    parser.add_argument("--exclude-file", action="append", default=[])
    parser.add_argument("--configuration", help="Optional JSON overrides used only for local author testing")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--max-parallel", type=int, default=4)
    args = parser.parse_args()

    registry = discover_tests()
    if args.list:
        for item in registry:
            print(f"{item['test_id']:<6} {item['test_name']:<38} {item['manifest_path']}")
        return 0
    if not args.target:
        parser.error("--target is required unless --list is used")
    registry = [item for item in registry if selected(item, args.include_test, args.exclude_test)]
    if not registry:
        print("No tests selected", file=sys.stderr); return 2
    project_dir = Path(args.target).resolve()
    if not project_dir.is_dir():
        print(f"Target directory not found: {project_dir}", file=sys.stderr); return 2
    config = json.loads(Path(args.configuration).read_text(encoding="utf-8")) if args.configuration else {}
    files = collect_files(project_dir, args.include_file, DEFAULT_FILE_EXCLUDES + args.exclude_file)
    with tempfile.TemporaryDirectory(prefix="checks-orchestrator-") as temp:
        workspace = Path(temp)
        by_id: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=max(1, args.max_parallel)) as pool:
            futures = {pool.submit(run_one, item, project_dir, files, config, workspace): item["test_id"] for item in registry}
            for future in as_completed(futures): by_id[futures[future]] = future.result()
        results = [by_id[item["test_id"]] for item in registry]
    print_results(results)
    output_dir = Path(args.output_dir).resolve(); write_results(output_dir, results)
    print(f"\nJSON: {output_dir / 'results.json'}\nCSV:  {output_dir / 'findings.csv'}")
    if any(r.get("status") in {"ERROR", "TIMEOUT"} for r in results): return 2
    return 1 if any(r.get("findings") for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
