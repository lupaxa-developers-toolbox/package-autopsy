"""Structural and metadata validation for wheels and source distributions."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from lupaxa.package_autopsy.entrypoints import parse_entry_points, validate_entry_points
from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.metadata import dist_info_file
from lupaxa.package_autopsy.models import Finding
from lupaxa.package_autopsy.modules import discover_modules
from lupaxa.package_autopsy.verify import verify_distribution


def validate_distribution(dist: Distribution, *, strict: bool = False) -> tuple[dict[str, Any], list[Finding]]:
    findings = list(dist.findings)
    if dist.format == "wheel":
        findings.extend(_validate_wheel(dist))
    elif dist.format == "sdist":
        findings.extend(_validate_sdist(dist, strict=strict))
    elif dist.format in {"malformed", "ordinary_archive", "unsupported"}:
        findings.append(
            Finding(
                "VALIDATE-NOT-DISTRIBUTION",
                "structure",
                "error" if dist.format == "malformed" else "informational",
                f"Cannot apply distribution validation to a {dist.format.replace('_', ' ')}.",
                path=dist.filename,
            )
        )
    points, extra = parse_entry_points(dist)
    findings.extend(extra)
    modules = discover_modules(dist, points)
    findings.extend(validate_entry_points(dist, points, modules))
    verify_payload, extra = verify_distribution(dist)
    if dist.format == "wheel":
        findings.extend(extra)
    if strict:
        upgraded: list[Finding] = []
        for item in findings:
            if item.severity == "warning" and item.identifier.startswith(("WHEEL-", "METADATA-", "RECORD-")):
                upgraded.append(
                    Finding(
                        item.identifier,
                        item.category,
                        "error",
                        item.explanation,
                        path=item.path,
                        field=item.field,
                        standard=item.standard,
                        suggestion=item.suggestion,
                        confidence=item.confidence,
                        evidence=item.evidence,
                    )
                )
            else:
                upgraded.append(item)
        findings = upgraded
    errors = sum(1 for item in findings if item.severity == "error")
    warnings = sum(1 for item in findings if item.severity == "warning")
    status = "failed" if errors else "passed"
    payload = {
        "status": status,
        "errors": errors,
        "warnings": warnings,
        "informational": sum(1 for item in findings if item.severity == "informational"),
        "integrity": verify_payload,
        "findings": [item.as_dict() for item in findings],
    }
    return payload, findings


def _validate_wheel(dist: Distribution) -> list[Finding]:
    findings: list[Finding] = []
    if dist.dist_info is None:
        return findings
    dist_info_parts = PurePosixPath(dist.dist_info).name
    if dist.wheel_name:
        expected = f"{_wheel_escape(dist.wheel_name.distribution)}-{dist.wheel_name.version}.dist-info"
        if dist_info_parts != expected and not dist_info_parts.endswith(".dist-info"):
            findings.append(
                Finding(
                    "WHEEL-DIST-INFO-NAME",
                    "wheel",
                    "warning",
                    f".dist-info directory {dist_info_parts} does not match the usual "
                    f"{{name}}-{{version}}.dist-info form ({expected}).",
                    path=dist.dist_info,
                    standard="PEP 427",
                    confidence="heuristic",
                )
            )
    wheel_path = dist_info_file(dist.archive, "WHEEL")
    if wheel_path and dist.wheel_file:
        if "wheel-version" not in dist.wheel_file:
            findings.append(
                Finding(
                    "WHEEL-VERSION-MISSING",
                    "wheel",
                    "error",
                    "WHEEL file has no Wheel-Version.",
                    path=wheel_path,
                    standard="PEP 427",
                )
            )
        tags = dist.wheel_file.get("tag", [])
        if not tags:
            findings.append(
                Finding(
                    "WHEEL-TAG-MISSING",
                    "wheel",
                    "error",
                    "WHEEL file has no Tag fields.",
                    path=wheel_path,
                    standard="PEP 427",
                )
            )
        elif dist.wheel_name:
            filename_tag = (
                f"{'.'.join(dist.wheel_name.python_tags)}-"
                f"{'.'.join(dist.wheel_name.abi_tags)}-"
                f"{'.'.join(dist.wheel_name.platform_tags)}"
            )
            if tags and filename_tag not in tags and not any(filename_tag.replace(".", ".") in tag for tag in tags):
                # Compare component-wise; multiple tags are allowed.
                joined = " ".join(tags)
                py = dist.wheel_name.python_tags[0] if dist.wheel_name.python_tags else ""
                if py and py not in joined:
                    findings.append(
                        Finding(
                            "WHEEL-TAG-FILENAME-MISMATCH",
                            "wheel",
                            "warning",
                            "WHEEL Tag fields are not consistent with the filename tags.",
                            path=wheel_path,
                            standard="PEP 427",
                            confidence="heuristic",
                        )
                    )
    for member in dist.archive.members:
        parts = PurePosixPath(member.name).parts
        if not parts:
            continue
        head = parts[0]
        if head.endswith(".dist-info") or head.endswith(".data"):
            continue
        if member.is_dir:
            continue
        # Files at wheel root should be importable or extra package data.
        if "/" not in member.name and member.name not in {"METADATA", "WHEEL", "RECORD"}:
            pass
    data_dirs = [
        member.name
        for member in dist.archive.members
        if member.is_dir and member.name.endswith(".data") or (not member.is_dir and ".data/" in member.name)
    ]
    for path in data_dirs:
        parts = PurePosixPath(path).parts
        if len(parts) >= 2 and parts[1] not in {
            "purelib",
            "platlib",
            "headers",
            "scripts",
            "data",
        }:
            findings.append(
                Finding(
                    "WHEEL-DATA-SCHEME",
                    "wheel",
                    "warning",
                    f"Unrecognised wheel .data scheme in {path}.",
                    path=path,
                    standard="PEP 427",
                    confidence="heuristic",
                )
            )
    return findings


def _validate_sdist(dist: Distribution, *, strict: bool) -> list[Finding]:
    findings: list[Finding] = []
    root = dist.sdist_root
    if not root:
        findings.append(
            Finding(
                "SDIST-ROOT-UNUSUAL",
                "sdist",
                "warning",
                "Source distribution does not have a single wrapping directory.",
                standard="PyPA source distribution",
                confidence="heuristic",
            )
        )
    pkg = any(name.endswith("PKG-INFO") for name in dist.names())
    if not pkg and strict:
        findings.append(
            Finding(
                "SDIST-PKG-INFO-MISSING",
                "sdist",
                "error",
                "Modern source distributions should include PKG-INFO.",
                standard="PEP 643",
            )
        )
    elif not pkg:
        findings.append(
            Finding(
                "SDIST-PKG-INFO-MISSING",
                "sdist",
                "warning",
                "PKG-INFO is missing; this may be a legacy or incomplete source archive.",
                standard="PEP 643",
                confidence="heuristic",
            )
        )
    system = dist.pyproject.get("build-system") if dist.pyproject else None
    if isinstance(system, dict):
        if "requires" not in system:
            findings.append(
                Finding(
                    "SDIST-BUILD-REQUIRES-MISSING",
                    "sdist",
                    "warning",
                    "build-system table has no requires list.",
                    path="pyproject.toml",
                    standard="PEP 518",
                )
            )
        if "build-backend" not in system and dist.has_setup_py:
            findings.append(
                Finding(
                    "SDIST-BUILD-BACKEND-IMPLICIT",
                    "sdist",
                    "informational",
                    "No build-backend is declared; setup.py is present and will not be executed.",
                    path="pyproject.toml",
                    standard="PEP 517",
                )
            )
    for field_name in dist.dynamic_fields:
        findings.append(
            Finding(
                "SDIST-DYNAMIC-FIELD",
                "metadata",
                "informational",
                f"Metadata field {field_name} is declared dynamic and is not materialised here.",
                field=field_name,
                standard="PEP 621",
                confidence="incomplete",
            )
        )
    return findings


def _wheel_escape(name: str) -> str:
    return name.replace("-", "_")
