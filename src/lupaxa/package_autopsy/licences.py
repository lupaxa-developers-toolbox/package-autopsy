"""Licence metadata and bundled licence files. Not legal advice."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import Finding

_SPDX_TOKEN = re.compile(
    r"^([A-Za-z0-9]+[A-Za-z0-9.\-]*\+?|LicenseRef-[A-Za-z0-9.\-]+|DocumentRef-[A-Za-z0-9.\-]+:LicenseRef-[A-Za-z0-9.\-]+)$"
)
_LICENCE_NAMES = ("license", "licence", "copying", "notice", "authors", "licences")


def analyse_licences(dist: Distribution) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    meta = dist.metadata
    expression = meta.license_expression if meta else None
    legacy = meta.license if meta else None
    classifiers = [item for item in (meta.classifiers if meta else []) if item.startswith("License ::")]
    declared_files = list(meta.license_files) if meta else []
    bundled = _licence_files(dist)
    if expression:
        ok, reason = validate_spdx(expression)
        if not ok:
            findings.append(
                Finding(
                    "LICENCE-SPDX-INVALID",
                    "licence",
                    "warning",
                    f"License-Expression is not a valid SPDX expression: {reason}",
                    field="License-Expression",
                    standard="PEP 639",
                    confidence="heuristic",
                )
            )
    missing = [item for item in declared_files if not _file_exists(dist, item)]
    for item in missing:
        findings.append(
            Finding(
                "LICENCE-FILE-MISSING",
                "licence",
                "warning",
                f"Declared licence file {item} is not in the distribution.",
                path=item,
                field="License-File",
                standard="PEP 639",
            )
        )
    if expression and legacy and legacy.strip() not in {expression.strip(), ""}:
        findings.append(
            Finding(
                "LICENCE-METADATA-CONFLICT",
                "licence",
                "warning",
                "License and License-Expression both present and differ.",
                field="License",
                standard="PEP 639",
                confidence="heuristic",
            )
        )
    if len(bundled) > 1:
        findings.append(
            Finding(
                "LICENCE-MULTIPLE-FILES",
                "licence",
                "informational",
                "Multiple licence-like files are bundled.",
                confidence="heuristic",
            )
        )
    if not expression and not legacy and not classifiers and not bundled:
        findings.append(
            Finding(
                "LICENCE-MISSING",
                "licence",
                "warning",
                "No licence metadata or licence-like files were found.",
                confidence="heuristic",
            )
        )
    payload = {
        "license_expression": expression,
        "legacy_license": legacy,
        "classifiers": classifiers,
        "declared_files": declared_files,
        "bundled_files": bundled,
        "note": "Licence findings are packaging observations, not legal advice.",
    }
    return payload, findings


def _licence_files(dist: Distribution) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for member in dist.archive.members:
        if member.is_dir:
            continue
        stem = PurePosixPath(member.name).name.lower()
        if any(stem.startswith(prefix) for prefix in _LICENCE_NAMES):
            found.append({"path": member.name, "size": member.size})
    return found


def _file_exists(dist: Distribution, declared: str) -> bool:
    declared = declared.replace("\\", "/").lstrip("./")
    names = set(dist.names())
    if declared in names:
        return True
    return any(name.endswith(f"/{declared}") or name.endswith(declared) for name in names)


def validate_spdx(expression: str) -> tuple[bool, str]:
    text = expression.strip()
    if not text:
        return False, "empty expression"
    tokens = _spdx_tokens(text)
    if tokens is None:
        return False, "unbalanced parentheses or invalid characters"
    if not _spdx_parse(tokens):
        return False, "expression grammar did not parse"
    return True, ""


def _spdx_tokens(text: str) -> list[str] | None:
    tokens: list[str] = []
    i = 0
    depth = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            if ch == "(":
                depth += 1
            else:
                depth -= 1
                if depth < 0:
                    return None
            tokens.append(ch)
            i += 1
            continue
        j = i
        while j < len(text) and not text[j].isspace() and text[j] not in "()":
            j += 1
        tokens.append(text[i:j])
        i = j
    if depth != 0:
        return None
    return tokens


def _spdx_parse(tokens: list[str]) -> bool:
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take(expected: str | None = None) -> str | None:
        nonlocal pos
        if pos >= len(tokens):
            return None
        token = tokens[pos]
        if expected is not None and token.upper() != expected.upper():
            return None
        pos += 1
        return token

    def license_id() -> bool:
        token = peek()
        if token is None or token in {"(", ")", "AND", "OR", "WITH"}:
            return False
        if not _SPDX_TOKEN.match(token):
            return False
        take()
        return True

    def compound() -> bool:
        if peek() == "(":
            take("(")
            return expression() and take(")") is not None
        if not license_id():
            return False
        nxt = peek()
        if nxt is not None and nxt.upper() == "WITH":
            take("WITH")
            if not license_id():
                return False
        return True

    def expression() -> bool:
        if not compound():
            return False
        while True:
            nxt = peek()
            if nxt is None or nxt.upper() not in {"AND", "OR"}:
                break
            take()
            if not compound():
                return False
        return True

    ok = expression()
    return ok and pos == len(tokens)
