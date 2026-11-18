"""Wheel RECORD verification and archive integrity."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import zipfile
from typing import Any

from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.metadata import dist_info_file
from lupaxa.package_autopsy.models import Finding, VerificationStatus

SUPPORTED_HASHES = {"sha256", "sha384", "sha512", "md5", "sha1"}


def verify_distribution(dist: Distribution) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    if dist.format == "wheel":
        record_status, extra = verify_record(dist)
        findings.extend(extra)
    else:
        record_status = "unsupported"
        findings.append(
            Finding(
                "VERIFY-RECORD-UNSUPPORTED",
                "integrity",
                "informational",
                "RECORD verification applies to wheels.",
                path=dist.filename,
            )
        )
    archive_status, extra = verify_archive(dist)
    findings.extend(extra)
    errors = [item for item in findings if item.severity == "error"]
    if errors:
        status: VerificationStatus = "failed"
    elif record_status == "incomplete" or archive_status == "incomplete":
        status = "incomplete"
    elif record_status == "unsupported" and dist.format != "wheel":
        status = archive_status
    else:
        status = (
            "passed"
            if archive_status in {"passed", "unsupported"}
            and record_status
            in {
                "passed",
                "unsupported",
            }
            else record_status
        )
    payload = {
        "status": status,
        "record": record_status,
        "archive": archive_status,
        "limitations": [
            "Matching RECORD hashes prove consistency with this archive's recorded contents.",
            "They do not prove publisher identity, authenticity, or absence of malicious code.",
        ],
    }
    return payload, findings


def verify_record(dist: Distribution) -> tuple[VerificationStatus, list[Finding]]:
    findings: list[Finding] = []
    path = dist_info_file(dist.archive, "RECORD")
    if path is None:
        findings.append(
            Finding(
                "RECORD-MISSING",
                "integrity",
                "error",
                "RECORD file is missing.",
                standard="PEP 376 / PEP 427",
            )
        )
        return "failed", findings
    try:
        text = dist.read(path).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                "RECORD-UNREADABLE",
                "integrity",
                "error",
                f"RECORD could not be read: {exc}",
                path=path,
            )
        )
        return "failed", findings
    rows = list(csv.reader(io.StringIO(text)))
    recorded: dict[str, tuple[str, str]] = {}
    for row in rows:
        if not row or all(not cell.strip() for cell in row):
            continue
        if len(row) < 3:
            findings.append(
                Finding(
                    "RECORD-ROW-INVALID",
                    "integrity",
                    "error",
                    f"RECORD row does not have three fields: {row!r}",
                    path=path,
                    standard="PEP 376",
                )
            )
            continue
        name, digest, size = row[0], row[1], row[2]
        if name in recorded:
            findings.append(
                Finding(
                    "RECORD-DUPLICATE",
                    "integrity",
                    "error",
                    f"Duplicate RECORD path {name}.",
                    path=name,
                )
            )
        if ".." in name.split("/") or name.startswith("/"):
            findings.append(
                Finding(
                    "RECORD-PATH-INVALID",
                    "integrity",
                    "error",
                    f"RECORD path is unsafe: {name}",
                    path=name,
                )
            )
        recorded[name] = (digest, size)

    actual = {member.name: member for member in dist.archive.members if not member.is_dir}
    incomplete = False
    for name, (digest, size) in recorded.items():
        if name not in actual:
            findings.append(
                Finding(
                    "RECORD-MISSING-FILE",
                    "integrity",
                    "error",
                    f"RECORD lists {name} but the archive does not contain it.",
                    path=name,
                    standard="PEP 427",
                )
            )
            continue
        member = actual[name]
        allow_empty = digest == "" and size == ""
        if allow_empty:
            if not name.endswith("/RECORD") and name != path:
                findings.append(
                    Finding(
                        "RECORD-EMPTY-HASH",
                        "integrity",
                        "warning",
                        f"{name} has no hash or size in RECORD.",
                        path=name,
                        confidence="heuristic",
                    )
                )
            continue
        if size and int(size) != member.size:
            findings.append(
                Finding(
                    "RECORD-SIZE-MISMATCH",
                    "integrity",
                    "error",
                    f"{name} size {member.size} does not match RECORD size {size}.",
                    path=name,
                    standard="PEP 376",
                )
            )
        if digest:
            algo, _, encoded = digest.partition("=")
            algo = algo.lower()
            if algo not in SUPPORTED_HASHES:
                findings.append(
                    Finding(
                        "RECORD-HASH-UNSUPPORTED",
                        "integrity",
                        "warning",
                        f"{name} uses unrecognised hash algorithm {algo}.",
                        path=name,
                    )
                )
                incomplete = True
                continue
            try:
                expected = _b64decode(encoded)
            except Exception:
                findings.append(
                    Finding(
                        "RECORD-HASH-ENCODING",
                        "integrity",
                        "error",
                        f"{name} has an invalid RECORD hash encoding.",
                        path=name,
                    )
                )
                continue
            try:
                payload = dist.read(name)
            except Exception as exc:  # noqa: BLE001
                findings.append(
                    Finding(
                        "RECORD-READ-FAILED",
                        "integrity",
                        "error",
                        f"{name} could not be read for hashing: {exc}",
                        path=name,
                    )
                )
                incomplete = True
                continue
            actual_digest = hashlib.new(algo, payload).digest()
            if actual_digest != expected:
                findings.append(
                    Finding(
                        "RECORD-HASH-MISMATCH",
                        "integrity",
                        "error",
                        f"{name} content hash does not match RECORD.",
                        path=name,
                        standard="PEP 376",
                    )
                )
    for name in actual:
        if name not in recorded:
            findings.append(
                Finding(
                    "RECORD-UNEXPECTED-FILE",
                    "integrity",
                    "error",
                    f"{name} is in the archive but not in RECORD.",
                    path=name,
                    standard="PEP 427",
                )
            )
    errors = [item for item in findings if item.severity == "error"]
    if errors:
        return "failed", findings
    if incomplete:
        return "incomplete", findings
    return "passed", findings


def verify_archive(dist: Distribution) -> tuple[VerificationStatus, list[Finding]]:
    findings: list[Finding] = []
    if dist.archive.kind == "zip":
        try:
            with zipfile.ZipFile(dist.path) as zf:
                bad = zf.testzip()
            if bad:
                findings.append(
                    Finding(
                        "ARCHIVE-CRC-MISMATCH",
                        "integrity",
                        "error",
                        f"ZIP CRC check failed for {bad}.",
                        path=bad,
                    )
                )
                return "failed", findings
        except zipfile.BadZipFile as exc:
            findings.append(
                Finding(
                    "ARCHIVE-ZIP-INVALID",
                    "integrity",
                    "error",
                    f"ZIP structure is invalid: {exc}",
                    path=dist.filename,
                )
            )
            return "failed", findings
        return "passed", findings
    if dist.archive.kind == "tar":
        findings.append(
            Finding(
                "ARCHIVE-TAR-STRUCTURAL",
                "integrity",
                "informational",
                "TAR members were parsed; compression-stream errors are reported during read.",
                path=dist.filename,
            )
        )
        return "passed", findings
    return "unsupported", findings


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
