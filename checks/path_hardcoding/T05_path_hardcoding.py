#!/usr/bin/env python3
"""T05 - Hardcoded Path and Storage Location Exposure

Finds hardcoded local, personal workspace, DBFS, mount, cloud storage (ADLS/S3/GCS), OneLake and file URLs. Parameterized paths and Fabric /lakehouse/default paths are accepted; documentation and comments are reported at Low.

Independent check for Databricks, Microsoft Fabric and Snowflake repositories.
Runs with no configuration. Optional (same for every check): exclude_folders, exclude_files.
Inline suppression: '# codestandards: ignore[RULE]'.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import fnmatch
import hashlib
import json
import math
import re
import sys
import tomllib
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

# =============================================================================
# SHARED RUNTIME
# Duplicated in every check so each check is fully independent.
# Check-specific logic lives after the END OF SHARED RUNTIME marker.
#
# Defaults are designed to work with no configuration. Every check accepts the SAME two
# optional parameters, for exceptional cases only:
#   exclude_folders   folders this check should skip    e.g. legacy  or  src/archive
#   exclude_files     files this check should skip      e.g. config_loader.py  or  *.ipynb
# A few checks add one extra optional parameter (see PARAMETERS in the check section).
# Values may be a single value, a comma-separated string, [a,b] or a JSON list.
#
# Inline suppression in client code (no configuration needed):
#   x = "/mnt/shared"   # codestandards: ignore            -> all checks, this line
#   x = "/mnt/shared"   # codestandards: ignore[PTH008]    -> one rule, this line
#   -- codestandards: ignore[T08]                         -> on its own line: applies to the next line
#   # codestandards: ignore-file[T03]                     -> anywhere in the first 20 lines: whole file
# =============================================================================

CONTRACT_VERSION = "1.0"
SEVERITIES = ("Critical", "High", "Medium", "Low")
MAX_FINDINGS = 5000
MAX_FILE_SIZE_KB = 2048

COMMON_PARAMETERS: dict[str, Any] = {
    "exclude_folders": [],
    "exclude_files": [],
}

DEFAULT_EXCLUDES = [
    ".git/**", "**/.git/**", "**/__pycache__/**", "**/.venv/**", "**/venv/**",
    "**/node_modules/**", "**/dist/**", "**/build/**", "**/target/**",
    "**/.ipynb_checkpoints/**", "**/site-packages/**", "**/.pytest_cache/**",
    "**/.mypy_cache/**", "**/.ruff_cache/**", "**/.tox/**", "**/.idea/**", "**/.vscode/**",
    ".env", "**/.env", ".env.*", "**/.env.*", "**/*.pem", "**/*.key", "**/*.pfx",
    "**/*.p12", "**/id_rsa", "**/id_rsa.*", "**/*.min.js", "**/package-lock.json",
    "**/yarn.lock", "**/code-standards-results/**",
]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf", ".zip",
    ".gz", ".tgz", ".tar", ".7z", ".rar", ".whl", ".egg", ".jar", ".war", ".class",
    ".parquet", ".avro", ".orc", ".delta", ".xlsx", ".xls", ".xlsm", ".docx", ".doc",
    ".pptx", ".ppt", ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".db", ".sqlite",
    ".bin", ".pkl", ".pickle", ".h5", ".joblib", ".onnx", ".pt", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".pbix", ".pbit",
}

LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".ipynb": "notebook", ".sql": "sql", ".ddl": "sql", ".dml": "sql",
    ".hql": "sql", ".scala": "scala", ".r": "r", ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".jsonl": "json", ".toml": "toml", ".cfg": "config", ".ini": "config",
    ".conf": "config", ".properties": "config", ".sh": "shell", ".bash": "shell",
    ".ps1": "powershell", ".md": "markdown", ".rst": "markdown", ".txt": "text",
    ".csv": "data", ".tsv": "data", ".xml": "xml", ".tf": "terraform", ".bicep": "bicep",
    ".j2": "template", ".jinja": "template",
}

CODE_KINDS = ("python", "sql", "scala", "r")


# --------------------------------------------------------------------------- utils
def deep_merge(base: dict, override: dict | None) -> dict:
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def to_list(value: Any) -> list[str]:
    """Accept JSON lists, [a,b] (PowerShell strips quotes), comma-separated strings or a single value."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except ValueError:
        pass
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return [item.strip().strip(chr(34) + chr(39)) for item in text.split(",") if item.strip().strip(chr(34) + chr(39))]


def glob_match(path: str, pattern: str) -> bool:
    """Case-insensitive glob. Supports **, directory/** and bare file names."""
    path = str(path).replace("\\", "/").lower()
    pattern = str(pattern).replace("\\", "/").strip().lower()
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if not pattern:
        return False
    if pattern.endswith("/"):
        pattern += "**"
    candidates = [pattern]
    if pattern.startswith("**/"):
        candidates.append(pattern[3:])
    for candidate in candidates:
        if fnmatch.fnmatchcase(path, candidate):
            return True
        if candidate.endswith("/**"):
            base = candidate[:-3]
            parts = path.split("/")
            for index in range(1, len(parts) + 1):
                if fnmatch.fnmatchcase("/".join(parts[:index]), base):
                    return True
    if "/" not in pattern and fnmatch.fnmatchcase(PurePosixPath(path).name, pattern):
        return True
    if "/" not in pattern and "*" not in pattern and pattern in path.split("/"):
        return True
    return False


def matches_any(path: str, patterns: Iterable[str] | None) -> bool:
    return any(glob_match(path, pattern) for pattern in patterns or [])


def extension(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def language_of(path: str) -> str:
    return LANGUAGE_BY_EXTENSION.get(extension(path), "text")


def clean_evidence(value: Any, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def mask_value(value: str, keep_start: int = 3, keep_end: int = 2) -> str:
    value = str(value)
    if len(value) <= keep_start + keep_end + 2:
        return "*" * len(value)
    return value[:keep_start] + "*" * min(12, len(value) - keep_start - keep_end) + value[-keep_end:]


def compile_patterns(patterns: Iterable[str] | None, flags: int = re.I) -> list[re.Pattern]:
    compiled = []
    for pattern in patterns or []:
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error:
            pass
    return compiled


def name_tokens(value: Any) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", str(value).lower()) if token]


def classify(value: Any, groups: dict[str, list[str]]) -> str | None:
    """Return the single group whose tokens appear in value, or None if zero/ambiguous."""
    hits = classify_all(value, groups)
    return hits[0] if len(hits) == 1 else None


def classify_all(value: Any, groups: dict[str, list[str]]) -> list[str]:
    tokens = set(name_tokens(value))
    return [group for group, words in (groups or {}).items()
            if tokens & {str(word).lower() for word in words or []}]


def is_comment_line(line: str, kind: str) -> bool:
    stripped = line.strip()
    if kind in ("python", "r", "shell", "yaml", "config", "toml"):
        return stripped.startswith("#")
    if kind == "sql":
        return stripped.startswith(("--", "//", "/*", "*"))
    if kind == "scala":
        return stripped.startswith(("//", "/*", "*"))
    return False


# ---------------------------------------------------------------------- documents
@dataclass
class Unit:
    kind: str                      # python | sql | scala | r | markdown | output | <language>
    lines: list[str]
    numbers: list[int]             # reported line number for each entry in lines
    cell: int | None = None
    origin: str = "file"           # file | cell | embedded | output
    is_parameters: bool = False    # Fabric/Papermill parameters cell: values are intended defaults
    _text: str | None = field(default=None, repr=False)
    _tree: Any = field(default=False, repr=False)

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = "\n".join(self.lines)
        return self._text

    def line_at(self, index: int) -> int | None:
        if not self.numbers:
            return None
        return self.numbers[max(0, min(index, len(self.numbers) - 1))]

    def line_of_offset(self, offset: int) -> int | None:
        return self.line_at(self.text.count("\n", 0, max(0, offset)))


@dataclass
class Document:
    path: str
    language: str
    raw: str
    units: list[Unit]
    is_notebook: bool = False
    has_parameter_cell: bool = False

    def code_units(self, kinds: Iterable[str] = CODE_KINDS) -> list[Unit]:
        kinds = set(kinds)
        return [unit for unit in self.units if unit.kind in kinds]

    @property
    def lines(self) -> list[str]:
        return self.raw.splitlines()


_NB_HEADER = re.compile(r"(Databricks notebook source|Fabric notebook source)", re.I)
_NB_SEPARATOR = re.compile(
    r"^\s*(?:#|--|//)\s*(COMMAND\s*-{3,}|CELL\s*\*{3,}|METADATA\s*\*{3,}|MARKDOWN\s*\*{3,}|PARAMETERS\s+CELL\s*\*{3,})")
_NB_MAGIC = re.compile(r"^\s*(?:#|--|//)\s?MAGIC ?(.*)$")
_MAGIC_KIND = {
    "%sql": "sql", "%%sql": "sql", "%md": "markdown", "%%md": "markdown", "%markdown": "markdown",
    "%%markdown": "markdown", "%python": "python", "%%python": "python", "%pyspark": "python",
    "%%pyspark": "python", "%scala": "scala", "%%scala": "scala", "%%spark": "scala",
    "%r": "r", "%%r": "r", "%%sparkr": "r", "%sh": "shell", "%%sh": "shell", "%%bash": "shell",
}
_LANGUAGE_ALIASES = {
    "python": "python", "python3": "python", "pyspark": "python", "sql": "sql", "sparksql": "sql",
    "spark-sql": "sql", "scala": "scala", "spark": "scala", "r": "r", "sparkr": "r",
}


def _apply_magic(lines: list[str], default_kind: str) -> tuple[str, list[str]]:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        word = stripped.split()[0].lower()
        if word in _MAGIC_KIND:
            copy = list(lines)
            copy[index] = ""
            return _MAGIC_KIND[word], copy
        return default_kind, lines
    return default_kind, lines


def looks_like_source_notebook(text: str) -> bool:
    head = text[:300]
    return bool(_NB_HEADER.search(head)) or bool(re.search(
        r"^\s*(?:#|--|//)\s*(COMMAND\s*-{3,}|CELL\s*\*{3,})", text, re.M))


def parse_source_notebook(text: str, default_kind: str) -> tuple[list[Unit], bool]:
    units: list[Unit] = []
    buffer: list[tuple[int, str]] = []
    hint: str | None = None
    has_parameters = False
    cell_number = 0

    def emit() -> None:
        nonlocal cell_number, has_parameters
        if hint == "skip" or not buffer:
            return
        if not any(line.strip() for _, line in buffer):
            return
        cell_number += 1
        numbers = [number for number, _ in buffer]
        content = []
        for _, line in buffer:
            magic = _NB_MAGIC.match(line)
            content.append(magic.group(1) if magic else line)
        kind, content = _apply_magic(content, "markdown" if hint == "markdown" else default_kind)
        if hint == "parameters":
            has_parameters = True
        units.append(Unit(kind, content, numbers, cell=cell_number, origin="cell", is_parameters=hint == "parameters"))

    for number, line in enumerate(text.splitlines(), start=1):
        separator = _NB_SEPARATOR.match(line)
        if separator:
            emit()
            buffer = []
            token = separator.group(1).split()[0].upper().rstrip("*-")
            hint = {"METADATA": "skip", "MARKDOWN": "markdown", "PARAMETERS": "parameters"}.get(token)
            continue
        if number == 1 and _NB_HEADER.search(line):
            continue
        buffer.append((number, line))
    emit()
    return units, has_parameters


def parse_ipynb(text: str) -> tuple[list[Unit], bool]:
    notebook = json.loads(text)
    metadata = notebook.get("metadata") or {}
    language = ((metadata.get("kernelspec") or {}).get("language")
                or (metadata.get("language_info") or {}).get("name") or "python")
    default_kind = _LANGUAGE_ALIASES.get(str(language).lower(), "python")
    units: list[Unit] = []
    has_parameters = False
    for index, cell in enumerate(notebook.get("cells") or [], start=1):
        source = cell.get("source", "")
        source = "".join(source) if isinstance(source, list) else str(source)
        lines = source.splitlines()
        numbers = list(range(1, len(lines) + 1))
        cell_type = cell.get("cell_type")
        tags = ((cell.get("metadata") or {}).get("tags")) or []
        if "parameters" in tags:
            has_parameters = True
        if cell_type == "markdown":
            units.append(Unit("markdown", lines, numbers, cell=index, origin="cell"))
        elif cell_type == "code":
            kind, lines = _apply_magic(lines, default_kind)
            units.append(Unit(kind, lines, numbers, cell=index, origin="cell", is_parameters="parameters" in tags))
        else:
            units.append(Unit("text", lines, numbers, cell=index, origin="cell"))
        output_lines: list[str] = []
        for output in cell.get("outputs") or []:
            value = output.get("text")
            if value:
                output_lines.extend(("".join(value) if isinstance(value, list) else str(value)).splitlines())
            plain = (output.get("data") or {}).get("text/plain")
            if plain:
                output_lines.extend(("".join(plain) if isinstance(plain, list) else str(plain)).splitlines())
            for line in output.get("traceback") or []:
                output_lines.append(re.sub(r"\x1b\[[0-9;]*m", "", str(line)))
        if output_lines:
            units.append(Unit("output", output_lines, list(range(1, len(output_lines) + 1)),
                              cell=index, origin="output"))
    return units, has_parameters


def build_document(path: str, text: str) -> Document:
    ext = extension(path)
    language = language_of(path)
    if ext == ".ipynb":
        try:
            units, parameters = parse_ipynb(text)
            return Document(path, "notebook", text, units, True, parameters)
        except (ValueError, TypeError, AttributeError):
            pass
    if ext in (".py", ".sql", ".scala", ".r") and looks_like_source_notebook(text):
        units, parameters = parse_source_notebook(text, language)
        return Document(path, language, text, units, True, parameters)
    lines = text.splitlines()
    return Document(path, language, text, [Unit(language, lines, list(range(1, len(lines) + 1)))])


# --------------------------------------------------------------------------- python
def python_tree(unit: Unit):
    if unit._tree is False:
        source = "\n".join("" if line.lstrip().startswith(("%", "!")) else line for line in unit.lines)
        try:
            unit._tree = ast.parse(source)
        except (SyntaxError, ValueError):
            unit._tree = None
    return unit._tree


def string_value(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                try:
                    parts.append("{" + ast.unparse(value.value) + "}")
                except Exception:
                    parts.append("{expr}")
        return "".join(parts)
    return None


def docstring_nodes(tree) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and string_value(body[0].value) is not None:
                ids.add(id(body[0].value))
    return ids


def python_strings(unit: Unit) -> list[tuple[str, int]]:
    """(value, 1-based line index within unit) for every string literal, docstrings excluded."""
    tree = python_tree(unit)
    if tree is None:
        return []
    skip = docstring_nodes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for child in node.values:
                skip.add(id(child))
    result = []
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        value = string_value(node)
        if value is not None and hasattr(node, "lineno"):
            result.append((value, node.lineno))
    return result


SQL_START = re.compile(
    r"^\s*(?:\(\s*)?(?:SELECT|WITH|INSERT|MERGE|CREATE|DROP|DELETE|TRUNCATE|UPDATE|COPY\s+INTO|ALTER|USE|"
    r"REPLACE\s+TABLE|OPTIMIZE|VACUUM|GRANT|REVOKE|CALL|EXECUTE\s+IMMEDIATE|UNDROP)\b", re.I | re.S)
_TRIPLE = re.compile(r"(\"\"\"|''')(.*?)\1", re.S)
_INLINE_SQL = re.compile(r"\b(?:sql|execute|query|run_sql|exec)\s*\(\s*[sfr]?(\"|')([^\"'\n]{8,})\1", re.I)


def embedded_sql(unit: Unit) -> list[Unit]:
    candidates: list[tuple[str, int]] = []
    if unit.kind == "python" and python_tree(unit) is not None:
        candidates = python_strings(unit)
    else:
        for match in list(_TRIPLE.finditer(unit.text)) + list(_INLINE_SQL.finditer(unit.text)):
            candidates.append((match.group(2), unit.text.count("\n", 0, match.start(2)) + 1))
    units = []
    for value, start in candidates:
        if not SQL_START.search(value):
            continue
        lines = value.split("\n")
        numbers = [unit.line_at(start - 1 + offset) for offset in range(len(lines))]
        units.append(Unit("sql", lines, numbers, cell=unit.cell, origin="embedded", is_parameters=unit.is_parameters))
    return units


def sql_units(document: Document) -> list[Unit]:
    units = []
    for unit in document.units:
        if unit.kind == "sql":
            units.append(unit)
        elif unit.kind in ("python", "scala", "r"):
            units.extend(embedded_sql(unit))
    return units


# ------------------------------------------------------------------------------ sql
def sql_mask(text: str, mask_strings: bool = True) -> str:
    """Same-length copy of SQL text with comments (and optionally string contents) blanked."""
    chars = list(text)
    length = len(text)
    i = 0

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, length)):
            if chars[k] != "\n":
                chars[k] = " "

    while i < length:
        ch = text[i]
        if text.startswith("--", i) or text.startswith("//", i):
            end = text.find("\n", i)
            end = length if end < 0 else end
            blank(i, end)
            i = end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = length if end < 0 else end + 2
            blank(i, end)
            i = end
            continue
        if ch in "`\"[":
            close = "]" if ch == "[" else ch
            end = text.find(close, i + 1)
            if end < 0 or "\n" in text[i:end]:
                i += 1
                continue
            i = end + 1
            continue
        if ch == "'":
            j = i + 1
            while j < length:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "'":
                    if j + 1 < length and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            if mask_strings:
                blank(i + 1, j)
            i = j + 1
            continue
        i += 1
    return "".join(chars)


_IDENT = (r"(?:`[^`\n]+`|\"[^\"\n]+\"|\[[^\]\n]+\]|\$\{[^}\n]+\}|\{\{[^}\n]*\}\}|\{[^{}\n]+\}|"
          r"IDENTIFIER\s*\([^)\n]*\)|:[A-Za-z_]\w*|\$[A-Za-z_]\w*|[A-Za-z_][\w$]*)")
QNAME = rf"{_IDENT}(?:\s*\.\s*{_IDENT}){{0,3}}"
_IDENT_RE = re.compile(_IDENT)

SQL_RESERVED = {
    "select", "from", "where", "as", "on", "using", "values", "lateral", "table", "unnest", "with",
    "set", "into", "only", "if", "not", "exists", "by", "group", "order", "partition", "join",
    "inner", "left", "right", "full", "cross", "outer", "natural", "union", "all", "case", "when",
    "then", "else", "end", "and", "or", "in", "is", "null", "true", "false", "limit", "qualify",
    "having", "window", "over", "current_date", "current_timestamp", "dual", "each", "the", "a",
}
FILE_FORMATS = {"delta", "parquet", "csv", "json", "orc", "avro", "text", "binaryfile", "iceberg", "xml"}

WRITE_PATTERNS = [
    ("create_table", re.compile(
        rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL|TEMPORARY|TEMP|TRANSIENT|VOLATILE|EXTERNAL|"
        rf"ICEBERG|HYBRID|DYNAMIC|STREAMING|LIVE)\s+)*TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({QNAME})", re.I)),
    ("create_view", re.compile(
        rf"\bCREATE\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?(?:(?:GLOBAL|LOCAL|TEMPORARY|TEMP|SECURE|RECURSIVE|"
        rf"MATERIALIZED|LIVE|STREAMING)\s+)*VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?({QNAME})", re.I)),
    ("insert_overwrite", re.compile(rf"\bINSERT\s+OVERWRITE\s+(?:TABLE\s+|INTO\s+)?({QNAME})", re.I)),
    ("insert", re.compile(rf"\bINSERT\s+INTO\s+(?:TABLE\s+)?({QNAME})", re.I)),
    ("merge", re.compile(rf"\bMERGE\s+INTO\s+({QNAME})", re.I)),
    ("update", re.compile(rf"\bUPDATE\s+({QNAME})\s+(?:(?:AS\s+)?[A-Za-z_]\w*\s+)?SET\b", re.I)),
    ("delete", re.compile(rf"\bDELETE\s+FROM\s+({QNAME})", re.I)),
    ("copy_into", re.compile(rf"\bCOPY\s+INTO\s+({QNAME})", re.I)),
    ("truncate", re.compile(rf"\bTRUNCATE\s+(?:TABLE\s+)?(?:IF\s+EXISTS\s+)?({QNAME})", re.I)),
]
READ_PATTERN = re.compile(rf"\b(FROM|JOIN|USING)\s+({QNAME})", re.I)
CTE_PATTERN = re.compile(r"(?:\bWITH\b(?:\s+RECURSIVE)?|,)\s*([A-Za-z_][\w$]*)\s*(?:\([^()]*\))?\s+AS\s*\(", re.I)
_FROM_FUNCTIONS = {"extract", "trim", "substring", "substr", "position", "overlay", "date_part"}


@dataclass
class TableRef:
    raw: str
    parts: list[str]
    op: str
    offset: int
    parameterized: bool

    @property
    def name(self) -> str:
        return ".".join(self.parts).lower()

    @property
    def key(self) -> str:
        parts = ["*" if is_parameter(part) else part.lower() for part in self.parts]
        return ".".join(parts[-2:]) if parts else ""

    @property
    def is_path(self) -> bool:
        return any("/" in part or ":" in part for part in self.parts)


@dataclass
class Statement:
    start: int
    end: int
    text: str
    masked: str
    writes: list[TableRef]
    reads: list[TableRef]
    ctes: set[str]


def is_parameter(value: str) -> bool:
    return bool(re.search(r"\$\{|\{\{|\{|^:|^\$|IDENTIFIER\s*\(|%\(|%s|\?", value, re.I))


def make_ref(raw: str, op: str, offset: int) -> TableRef | None:
    idents = _IDENT_RE.findall(raw)
    parts = [ident.strip().strip("`\"").strip("[]") if not is_parameter(ident) else ident for ident in idents]
    if not parts:
        return None
    if len(parts) == 1 and parts[0].lower() in SQL_RESERVED:
        return None
    return TableRef(raw, parts, op, offset, any(is_parameter(ident) for ident in idents))


def _enclosing_call(masked: str, position: int) -> str | None:
    depth = 0
    index = position - 1
    while index >= 0:
        ch = masked[index]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                match = re.search(r"([A-Za-z_]\w*)\s*$", masked[:index])
                return match.group(1).lower() if match else ""
            depth -= 1
        index -= 1
    return None


def matching_paren(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def split_statements(text: str) -> list[tuple[int, int]]:
    masked = sql_mask(text)
    spans, start = [], 0
    for index, ch in enumerate(masked):
        if ch == ";":
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(text)))
    return [(s, e) for s, e in spans if masked[s:e].strip()]


def parse_statements(text: str) -> list[Statement]:
    masked_all = sql_mask(text)
    statements = []
    for start, end in split_statements(text):
        masked = masked_all[start:end]
        original = text[start:end]
        ctes = {match.group(1).lower() for match in CTE_PATTERN.finditer(masked)}
        writes, write_spans = [], set()
        for op, pattern in WRITE_PATTERNS:
            for match in pattern.finditer(masked):
                ref = make_ref(match.group(1), op, start + match.start(1))
                if ref:
                    writes.append(ref)
                    write_spans.add(match.start(1))
        reads = []
        has_merge = bool(re.search(r"\bMERGE\b", masked, re.I))
        for match in READ_PATTERN.finditer(masked):
            keyword = match.group(1).upper()
            if match.start(2) in write_spans:
                continue
            if keyword == "USING" and not has_merge:
                continue
            if masked[match.end(2):match.end(2) + 3].lstrip().startswith("("):
                continue
            if keyword == "FROM" and masked[max(0, match.start() - 12):match.start()].lower().rstrip().endswith("distinct"):
                continue
            if keyword == "FROM" and _enclosing_call(masked, match.start()) in _FROM_FUNCTIONS:
                continue
            ref = make_ref(match.group(2), keyword.lower(), start + match.start(2))
            if not ref or ref.name in ctes or (ref.parts[0].lower() in FILE_FORMATS and len(ref.parts) > 1):
                continue
            reads.append(ref)
        statements.append(Statement(start, end, original, masked, writes, reads, ctes))
    return statements


# ------------------------------------------------------------------ python table io
PY_TABLE_WRITE = re.compile(
    r"\.(saveAsTable|save_as_table|insertInto|insert_into|toTable|to_table|write_pandas)\(\s*"
    r"(?:[A-Za-z_][\w.]*\s*,\s*){0,2}(?:(?:name|table_name|tableName)\s*=\s*)?[rbfuRBFU]{0,2}([\"'])(.+?)\2")
PY_TABLE_READ = re.compile(r"\.(?:table|read_table)\(\s*[rbfuRBFU]{0,2}([\"'])(.+?)\1")
PY_FORNAME = re.compile(r"forName\(\s*[\w.]+\s*,\s*[rbfuRBFU]{0,2}([\"'])(.+?)\1")
PY_PATH_WRITE = re.compile(r"\.write(?:Stream)?\b[\s\S]{0,400}?\.(save|parquet|csv|json|orc|text|start)\(", re.M)


def python_table_io(unit: Unit) -> tuple[list[TableRef], list[TableRef]]:
    writes, reads = [], []
    for match in PY_TABLE_WRITE.finditer(unit.text):
        ref = make_ref(match.group(3), "py_write", match.start(3))
        if ref:
            writes.append(ref)
    for pattern in (PY_TABLE_READ, PY_FORNAME):
        for match in pattern.finditer(unit.text):
            ref = make_ref(match.group(2), "py_read", match.start(2))
            if ref and not ref.is_path:
                reads.append(ref)
    return writes, reads


# --------------------------------------------------------------------------- context
@dataclass
class Context:
    project_dir: Path
    received_files: list[str]
    files: list[str]
    params: dict[str, Any]
    request: dict[str, Any]
    severity_override: str | None = None
    confidence_override: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rule_severity: dict[str, str] = field(default_factory=dict)
    disabled_rules: list[str] = field(default_factory=list)
    _text: dict[str, str | None] = field(default_factory=dict)
    _docs: dict[str, Document | None] = field(default_factory=dict)

    def read_text(self, relative: str) -> str | None:
        if relative in self._text:
            return self._text[relative]
        value = None
        try:
            path = (self.project_dir / relative).resolve()
            if self.project_dir in path.parents and path.is_file() and extension(relative) not in BINARY_EXTENSIONS:
                if path.stat().st_size > MAX_FILE_SIZE_KB * 1024:
                    self.warnings.append(f"Skipped {relative}: larger than {MAX_FILE_SIZE_KB} KB")
                else:
                    data = path.read_bytes()
                    if b"\x00" not in data[:4096]:
                        value = data.decode("utf-8", errors="replace").lstrip("\ufeff")
        except OSError as exc:
            self.warnings.append(f"Could not read {relative}: {exc}")
        self._text[relative] = value
        return value

    def document(self, relative: str) -> Document | None:
        if relative not in self._docs:
            text = self.read_text(relative)
            try:
                self._docs[relative] = build_document(relative, text) if text is not None else None
            except Exception as exc:  # one unreadable file must never stop the check
                self.warnings.append(f"Could not parse {relative}: {type(exc).__name__}: {exc}")
                self._docs[relative] = None
        return self._docs[relative]

    def documents(self, extensions: Iterable[str] | None = None) -> Iterator[Document]:
        allowed = {ext.lower() for ext in extensions} if extensions and "*" not in extensions else None
        for relative in self.files:
            if allowed and extension(relative) not in allowed:
                continue
            document = self.document(relative)
            if document is not None:
                yield document


def normalize_severity(value: Any) -> str | None:
    text = str(value or "").strip().title()
    return text if text in SEVERITIES else None


def folder_patterns(values: list[str]) -> list[str]:
    """'legacy' skips any folder named legacy; 'src/legacy' skips that path; globs are allowed."""
    patterns = []
    for value in values:
        value = value.replace("\\", "/").strip().strip("/")
        if value.startswith("./"):
            value = value[2:]
        if not value:
            continue
        patterns.append(f"{value}/**")
        if "/" not in value:
            patterns.append(f"**/{value}/**")
    return patterns


def file_patterns(values: list[str]) -> list[str]:
    """'a.py' or '*.ipynb' match by file name anywhere; 'src/a.py' matches that path."""
    result = []
    for value in values:
        value = value.replace("\\", "/").strip()
        while value.startswith("./"):
            value = value[2:]
        if value:
            result.append(value)
    return result


def build_context(request: dict[str, Any]) -> Context:
    project_dir = Path(request["project_dir"]).resolve()
    if not project_dir.is_dir():
        raise ValueError(f"project_dir does not exist: {project_dir}")
    configuration = request.get("test_configuration") or {}
    supplied = configuration.get("parameters") or {}
    exposed = {**COMMON_PARAMETERS, **globals().get("PARAMETERS", {})}
    user = {}
    for key, default in exposed.items():
        value = supplied.get(key)
        if isinstance(default, list):
            user[key] = to_list(value)
        else:
            user[key] = default if value in (None, "") else value
    ignored = sorted(set(supplied) - set(exposed))
    received = sorted({str(item).replace("\\", "/").lstrip("/") for item in request.get("files") or []})
    safe = [item for item in received if ".." not in PurePosixPath(item).parts]
    excludes = DEFAULT_EXCLUDES + folder_patterns(user["exclude_folders"]) + file_patterns(user["exclude_files"])
    files = [item for item in safe if not matches_any(item, excludes)]
    context = Context(project_dir, safe, files, deep_merge(SETTINGS, user), request)
    if ignored:
        context.warnings.append(f"Ignored unknown parameter(s): {', '.join(ignored)}")
    severity = normalize_severity(configuration.get("severity"))
    if severity and severity != DEFAULT_SEVERITY:
        context.severity_override = severity
    confidence = str(configuration.get("confidence") or "").strip()
    if confidence and confidence.lower() != DEFAULT_CONFIDENCE.lower():
        context.confidence_override = confidence.title()
    return context


def add_finding(ctx: Context, rule_id: str, rule_name: str, file_path: str, line: int | None, *,
                severity: str, confidence: str, reason: str, suggestion: str, evidence: Any = "",
                expected: str = "", language: str | None = None, column: int | None = None,
                cell: int | None = None, symbol: str | None = None, symbol_type: str | None = None,
                end_line: int | None = None, extra: dict[str, Any] | None = None) -> None:
    level = (ctx.rule_severity.get(rule_id.upper()) or ctx.rule_severity.get("*")
             or ctx.severity_override or severity)
    finding = {
        "test_id": TEST_ID, "test_name": TEST_NAME, "test_version": TEST_VERSION,
        "rule_id": rule_id, "rule_name": rule_name, "severity": level,
        "confidence": ctx.confidence_override or confidence, "category": CATEGORY,
        "language": language or language_of(file_path), "file_path": file_path,
        "line_number": line, "column_number": column, "end_line_number": end_line,
        "end_column_number": None, "cell_number": cell, "symbol": symbol, "symbol_type": symbol_type,
        "evidence": clean_evidence(evidence), "reason": reason, "expected": expected,
        "suggestion": suggestion, "documentation_reference": f"{TEST_ID} {TEST_NAME} / {rule_id}",
        "blocking_recommendation": level in ("Critical", "High"),
    }
    for key, value in (extra or {}).items():
        finding.setdefault(key, value)
    ctx.findings.append(finding)


_SUPPRESS = re.compile(r"codestandards\s*:\s*(ignore-file|ignore)(?:\[([^\]]*)\])?", re.I)


def _targets(ids: str | None, rule_id: str) -> bool:
    if not ids or not ids.strip():
        return True
    wanted = [item.strip().upper() for item in ids.split(",") if item.strip()]
    return any(fnmatch.fnmatchcase(rule_id.upper(), w) or w == TEST_ID for w in wanted)


def _source_lines(ctx: Context, finding: dict[str, Any]) -> list[str]:
    document = ctx.document(finding["file_path"]) if not str(finding["file_path"]).startswith("<") else None
    if document is None:
        return []
    if extension(document.path) == ".ipynb" and finding.get("cell_number"):
        for unit in document.units:
            if unit.cell == finding["cell_number"] and unit.origin == "cell":
                return unit.lines
        return []
    return document.lines


def is_suppressed(ctx: Context, finding: dict[str, Any]) -> bool:
    if any(fnmatch.fnmatchcase(finding["rule_id"].upper(), rule) or rule == TEST_ID for rule in ctx.disabled_rules):
        return True
    lines = _source_lines(ctx, finding)
    if not lines:
        return False
    for line in lines[:20]:
        for match in _SUPPRESS.finditer(line):
            if match.group(1).lower() == "ignore-file" and _targets(match.group(2), finding["rule_id"]):
                return True
    number = finding.get("line_number")
    if not number or number > len(lines):
        return False
    for match in _SUPPRESS.finditer(lines[number - 1]):
        if match.group(1).lower() == "ignore" and _targets(match.group(2), finding["rule_id"]):
            return True
    if number >= 2:
        above = lines[number - 2].strip()
        if above.startswith(("#", "--", "//", "/*")):
            for match in _SUPPRESS.finditer(above):
                if match.group(1).lower() == "ignore" and _targets(match.group(2), finding["rule_id"]):
                    return True
    return False


def finish(ctx: Context) -> dict[str, Any]:
    seen, unique, suppressed = set(), [], 0
    for finding in ctx.findings:
        key = (finding["rule_id"], finding["file_path"], finding["line_number"], finding["cell_number"],
               finding["column_number"], finding["symbol"], finding["evidence"])
        if key in seen:
            continue
        seen.add(key)
        if is_suppressed(ctx, finding):
            suppressed += 1
            continue
        unique.append(finding)
    unique.sort(key=lambda f: (f["file_path"], f["cell_number"] or 0, f["line_number"] or 0, f["rule_id"]))
    if len(unique) > MAX_FINDINGS:
        ctx.warnings.append(f"Findings truncated from {len(unique)} to {MAX_FINDINGS}")
        unique = unique[:MAX_FINDINGS]
    return {
        "contract_version": CONTRACT_VERSION,
        "test": {"test_id": TEST_ID, "test_name": TEST_NAME, "test_version": TEST_VERSION},
        "status": "FAILED" if unique else "PASSED",
        "summary": (f"{len(unique)} finding(s) across {len({f['file_path'] for f in unique})} file(s); "
                    f"{len(ctx.files)} file(s) in scope") if unique else f"No findings; {len(ctx.files)} file(s) in scope",
        "files_received": len(ctx.received_files),
        "files_scanned": len(ctx.files),
        "findings_count": len(unique),
        "findings": unique,
        "warnings": ctx.warnings[:200],
        "errors": [],
        "metadata": {"findings_by_rule": dict(Counter(f["rule_id"] for f in unique)), "suppressed": suppressed},
    }


def describe() -> dict[str, Any]:
    return {
        "test_id": TEST_ID, "test_name": TEST_NAME, "test_version": TEST_VERSION,
        "description": DESCRIPTION, "severity": DEFAULT_SEVERITY, "confidence": DEFAULT_CONFIDENCE,
        "category": CATEGORY, "parameters": {**COMMON_PARAMETERS, **globals().get("PARAMETERS", {})},
    }


def run() -> int:
    parser = argparse.ArgumentParser(description=f"{TEST_ID} - {TEST_NAME}")
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--input")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(), indent=2))
        return 0
    if not args.input or not args.output:
        parser.error("--input and --output are required")
    try:
        request = json.loads(Path(args.input).read_text(encoding="utf-8"))
        context = build_context(request)
        analyze(context)
        result = finish(context)
        code = 0
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        result = {
            "contract_version": CONTRACT_VERSION,
            "test": {"test_id": TEST_ID, "test_name": TEST_NAME, "test_version": TEST_VERSION},
            "status": "ERROR", "summary": f"{type(exc).__name__}: {exc}", "files_received": 0,
            "files_scanned": 0, "findings_count": 0, "findings": [], "warnings": [],
            "errors": [{"type": type(exc).__name__, "message": str(exc)}],
        }
        code = 2
    Path(args.output).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return code


# =============================================================================
# END OF SHARED RUNTIME
# =============================================================================


# CHECK-SPECIFIC LOGIC

TEST_ID = "T05"
TEST_NAME = "Hardcoded Path and Storage Location Exposure"
TEST_VERSION = "1.0.0"
FOLDER = "path_hardcoding"
DESCRIPTION = ("Finds hardcoded local, personal workspace, DBFS, mount, cloud storage (ADLS/S3/GCS), OneLake and file "
               "URLs. Parameterized paths and Fabric /lakehouse/default paths are accepted; documentation and comments "
               "are reported at Low.")
DEFAULT_SEVERITY = "Medium"
DEFAULT_CONFIDENCE = "Likely"
CATEGORY = "Portability"
SUPPORTED_EXTENSIONS = ["*"]
TIMEOUT_SECONDS = 240

PARAMETERS = {
    "approved_paths": [],   # e.g. /mnt/shared, abfss://reference@  (path prefixes that are allowed)
}

SETTINGS = {
    "approved_path_patterns": [],
    "documentation_extensions": [".md", ".rst", ".txt"],
}

PATH_RULES = [
    ("PTH006", "OneLake path", r"(?:abfss://[^\s\"'`@]+@)?onelake\.(?:dfs|blob)\.fabric\.microsoft\.com/[^\s\"'`,;)]+", "Medium"),
    ("PTH005", "Cloud storage location",
     r"\b(?:abfss?|wasbs?|s3a?|s3n|gs|adl|azure|oci)://[^\s\"'`,;)]+|https://[a-z0-9-]+\.(?:blob|dfs)\.core\.windows\.net/[^\s\"'`,;)]*|https://[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com/[^\s\"'`,;)]*",
     "Medium"),
    ("PTH007", "Local file URL", r"\bfile:/{2,3}[^\s\"'`,;)]+", "High"),
    ("PTH001", "Local Windows path", r"(?<![\w/])[A-Za-z]:[\\/](?:[^\s\"'`,;)<>|]+)", "High"),
    ("PTH003", "Personal workspace path", r"/(?:Workspace/)?(?:Users|Repos)/[^\s\"'`,;)]*@[^\s\"'`,;)]+", "High"),
    ("PTH002", "Personal home directory path", r"(?<![\w.:/])(?:/Users/|/home/|~/)[A-Za-z0-9._-]+[^\s\"'`,;)]*", "High"),
    ("PTH004", "DBFS path", r"(?:\bdbfs:/|(?<![\w])/dbfs/)[^\s\"'`,;)]*", "Medium"),
    ("PTH008", "Mount point path", r"(?<![\w/])/mnt/[^\s\"'`,;)]+", "Medium"),
]
LOWER = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Low"}
RUNTIME_LOOKUP = re.compile(r"getenv|environ|widgets\.get|getArgument|\.get\(|config\[|conf\.get|parameters", re.I)


def analyze(ctx: Context) -> None:
    p = ctx.params
    rules = [(rid, label, re.compile(rx, re.I), sev) for rid, label, rx, sev in PATH_RULES]
    approved = compile_patterns(list(p["approved_path_patterns"]) + [re.escape(x) for x in p["approved_paths"]])
    doc_ext = {e.lower() for e in p["documentation_extensions"]}
    for document in ctx.documents():
        is_doc = extension(document.path) in doc_ext
        for unit in document.units:
            if unit.kind == "output":
                continue
            for index, line in enumerate(unit.lines):
                comment = is_comment_line(line, unit.kind)
                taken: list[tuple[int, int]] = []
                for rule_id, label, pattern, severity in rules:
                    for match in pattern.finditer(line):
                        span = match.span()
                        if any(s <= span[0] < e or s < span[1] <= e for s, e in taken):
                            continue
                        value = match.group(0).rstrip(".")
                        if any(rx.search(value) for rx in approved) or re.match(r"^/lakehouse/default/", value, re.I):
                            continue
                        taken.append(span)
                        if re.search(r"\{[^}]*\}|\$\{|%s|%\(|\{\{", value):
                            continue
                        level, confidence, note = severity, "Likely", ""
                        if RUNTIME_LOOKUP.search(line):
                            level, confidence, note = LOWER[severity], "Possible", " (used as a default/fallback value)"
                        if is_doc or comment or unit.kind == "markdown":
                            level, confidence, note = "Low", "Possible", " (documentation or comment)"
                        if rule_id == "PTH005" and re.search(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:EXTERNAL\s+)?(?:STAGE|LOCATION)\b", line, re.I):
                            level, note = "Low", " (external location/stage definition)"
                        add_finding(ctx, rule_id, label, document.path, unit.line_at(index), severity=level,
                                    confidence=confidence, cell=unit.cell, column=span[0] + 1, symbol=value,
                                    evidence=line, reason=f"{label} '{value}' is hardcoded{note}.",
                                    expected="Paths from configuration, parameters, volumes/external locations, "
                                             "Fabric lakehouse references or Snowflake stages.",
                                    suggestion="Move the location into configuration or parameters. If this path is "
                                               f"approved, add '# codestandards: ignore[{rule_id}]' on the line.")


if __name__ == "__main__":
    raise SystemExit(run())
