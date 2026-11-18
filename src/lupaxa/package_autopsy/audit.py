"""Packaging hygiene and potential sensitive-file detection."""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath
from typing import Any

from lupaxa.package_autopsy.config import Settings
from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import Finding
from lupaxa.package_autopsy.safety import REDACTED, redact

FILENAME_RULES: list[tuple[str, str, str]] = [
    ("*.env", "AUDIT-ENV-FILE", "Environment file"),
    (".env", "AUDIT-ENV-FILE", "Environment file"),
    ("**/.env", "AUDIT-ENV-FILE", "Environment file"),
    ("*.pem", "AUDIT-PRIVATE-KEY", "PEM file"),
    ("*.key", "AUDIT-PRIVATE-KEY", "Key file"),
    ("id_rsa", "AUDIT-SSH-KEY", "SSH private key"),
    ("id_dsa", "AUDIT-SSH-KEY", "SSH private key"),
    ("id_ecdsa", "AUDIT-SSH-KEY", "SSH private key"),
    ("id_ed25519", "AUDIT-SSH-KEY", "SSH private key"),
    (".git/**", "AUDIT-VCS", "Version-control metadata"),
    ("**/.git/**", "AUDIT-VCS", "Version-control metadata"),
    ("**/.gitignore", "AUDIT-VCS", "Version-control metadata"),
    ("**/__pycache__/**", "AUDIT-BYTECODE", "Python cache"),
    ("**/*.pyc", "AUDIT-BYTECODE", "Compiled bytecode"),
    ("**/*.pyo", "AUDIT-BYTECODE", "Compiled bytecode"),
    ("**/*~", "AUDIT-BACKUP", "Backup file"),
    ("**/*.bak", "AUDIT-BACKUP", "Backup file"),
    ("**/*.swp", "AUDIT-SWAP", "Editor swap file"),
    ("**/.DS_Store", "AUDIT-EDITOR", "Editor / OS metadata"),
    ("**/.vscode/**", "AUDIT-EDITOR", "Editor configuration"),
    ("**/.idea/**", "AUDIT-EDITOR", "Editor configuration"),
    ("**/.venv/**", "AUDIT-VENV", "Virtual environment"),
    ("**/venv/**", "AUDIT-VENV", "Virtual environment"),
    ("**/.tox/**", "AUDIT-VENV", "Test environment"),
    ("**/*.tmp", "AUDIT-TEMP", "Temporary file"),
    ("**/credentials*", "AUDIT-CREDENTIALS", "Credential file"),
    ("**/.aws/**", "AUDIT-CLOUD-CREDENTIALS", "Cloud credential configuration"),
    ("**/.netrc", "AUDIT-CREDENTIALS", "Netrc credentials"),
]

CONTENT_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "AUDIT-PRIVATE-KEY-CONTENT",
        "PEM private key material",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AUDIT-AWS-KEY", "AWS access key id"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "AUDIT-GITHUB-TOKEN", "GitHub token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "AUDIT-GITHUB-TOKEN", "GitHub token"),
    (re.compile(r"(?i)postgres(?:ql)?://[^\s]+"), "AUDIT-DB-URL", "Database connection string"),
    (
        re.compile(r"(?i)(mysql|mongodb|redis)://[^\s]+"),
        "AUDIT-DB-URL",
        "Database connection string",
    ),
    (re.compile(r"(?i)password\s*[:=]\s*\S+"), "AUDIT-PASSWORD", "Embedded password"),
    (re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+"), "AUDIT-API-TOKEN", "API token"),
]

LARGE_FILE = 5 * 1024 * 1024


def audit_distribution(
    dist: Distribution,
    settings: Settings,
    *,
    strict: bool = False,
) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    deny = list(settings.audit.get("deny", []))
    ignore = list(settings.audit.get("ignore", []))
    hashes: dict[str, list[str]] = {}
    for member in dist.archive.members:
        if member.is_dir:
            continue
        if _ignored(member.name, ignore):
            continue
        for pattern, identifier, label in FILENAME_RULES:
            if fnmatch.fnmatch(member.name, pattern) or fnmatch.fnmatch(PurePosixPath(member.name).name, pattern):
                findings.append(
                    _file_finding(
                        identifier,
                        member.name,
                        f"Potential {label.lower()} bundled in the distribution.",
                    )
                )
        for pattern in deny:
            if fnmatch.fnmatch(member.name, pattern):
                findings.append(
                    _file_finding(
                        "AUDIT-DENIED-PATTERN",
                        member.name,
                        f"File matches denied pattern {pattern}.",
                    )
                )
        if member.size >= LARGE_FILE:
            findings.append(
                Finding(
                    "AUDIT-LARGE-FILE",
                    "hygiene",
                    "warning",
                    f"{member.name} is unusually large ({member.size} bytes).",
                    path=member.name,
                    confidence="heuristic",
                )
            )
        if dist.format == "wheel" and _looks_like_test(member.name):
            findings.append(
                Finding(
                    "AUDIT-TESTS-IN-WHEEL",
                    "hygiene",
                    "warning",
                    f"Test path {member.name} is included in a wheel.",
                    path=member.name,
                    confidence="heuristic",
                )
            )
        if member.mode and member.mode & 0o111 and member.name.endswith((".py", ".txt", ".md")):
            findings.append(
                Finding(
                    "AUDIT-EXEC-BIT",
                    "hygiene",
                    "informational",
                    f"{member.name} has executable permission bits.",
                    path=member.name,
                    confidence="heuristic",
                )
            )
        try:
            data = dist.archive.read_capped(member.name, settings.limits.max_scan_size)
        except Exception:
            continue
        digest = __import__("hashlib").sha256(data).hexdigest()
        hashes.setdefault(digest, []).append(member.name)
        if _looks_text(data):
            text = data.decode("utf-8", errors="replace")
            for regex, ident, label in CONTENT_RULES:
                match = regex.search(text)
                if match:
                    findings.append(
                        Finding(
                            ident,
                            "secrets",
                            "warning",
                            f"Potential {label.lower()} in {member.name}.",
                            path=member.name,
                            evidence=_redacted_evidence(match.group(0)),
                            confidence="heuristic",
                            suggestion="Confirm whether this value is a real secret before publishing.",
                        )
                    )
        else:
            if member.name.endswith((".exe", ".bin")) or (
                member.mode and member.mode & 0o111 and not member.name.endswith((".so", ".pyd", ".dll", ".dylib"))
            ):
                findings.append(
                    Finding(
                        "AUDIT-UNEXPECTED-EXECUTABLE",
                        "hygiene",
                        "warning",
                        f"Unexpected executable {member.name}.",
                        path=member.name,
                        confidence="heuristic",
                    )
                )
    for _digest, names in hashes.items():
        if len(names) > 1:
            findings.append(
                Finding(
                    "AUDIT-DUPLICATE-CONTENT",
                    "hygiene",
                    "informational",
                    "Duplicate packaged file contents: " + ", ".join(names),
                    confidence="certain",
                )
            )
    findings = [item for item in findings if not _suppressed(item, settings)]
    if strict:
        findings = [
            Finding(
                item.identifier,
                item.category,
                "error" if item.severity == "warning" else item.severity,
                item.explanation,
                path=item.path,
                field=item.field,
                standard=item.standard,
                suggestion=item.suggestion,
                confidence=item.confidence,
                evidence=item.evidence,
            )
            for item in findings
        ]
    payload = {
        "findings": [item.as_dict() for item in findings],
        "note": "Secret-like values are labelled as potential exposures and are redacted.",
    }
    return payload, findings


def _file_finding(identifier: str, path: str, explanation: str) -> Finding:
    return Finding(
        identifier,
        "audit",
        "warning",
        explanation,
        path=path,
        confidence="heuristic",
        suggestion="Ignore or suppress this rule if the file is intentional.",
    )


def _looks_like_test(name: str) -> bool:
    lowered = f"/{name.lower()}/"
    return "/tests/" in lowered or "/test/" in lowered or PurePosixPath(name).name.startswith("test_")


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:1024]:
        return False
    sample = data[:512]
    printable = sum(32 <= byte < 127 or byte in {9, 10, 13} for byte in sample)
    return printable / max(len(sample), 1) > 0.85


def _redacted_evidence(value: str) -> str:
    cleaned = redact(value)
    if cleaned == value and len(value) > 8:
        return value[:3] + REDACTED
    return cleaned


def _ignored(name: str, patterns: list[Any]) -> bool:
    return any(fnmatch.fnmatch(name, str(pattern)) for pattern in patterns)


def _suppressed(finding: Finding, settings: Settings) -> bool:
    for rule in settings.suppress:
        ident = str(rule.get("id") or rule.get("identifier") or "")
        path = str(rule.get("path") or "")
        if ident and finding.identifier != ident:
            continue
        if path and finding.path and not fnmatch.fnmatch(finding.path, path):
            continue
        if ident or path:
            return True
    return False
