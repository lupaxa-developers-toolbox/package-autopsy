"""Shared analysis assembly used by inspect, report, and JSON payloads."""

from __future__ import annotations

from typing import Any

from lupaxa.package_autopsy.binaries import inspect_binaries
from lupaxa.package_autopsy.config import Limits, Settings
from lupaxa.package_autopsy.contents import annotate, size_report
from lupaxa.package_autopsy.dependencies import MarkerContext, analyse_dependencies
from lupaxa.package_autopsy.entrypoints import (
    bundled_scripts,
    parse_entry_points,
    validate_entry_points,
)
from lupaxa.package_autopsy.licences import analyse_licences
from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import Finding
from lupaxa.package_autopsy.modules import discover_modules
from lupaxa.package_autopsy.validate import validate_distribution


def inspect_payload(
    dist: Distribution,
    settings: Settings,
    *,
    context: MarkerContext | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = list(dist.findings)
    annotate(dist)
    points, extra = parse_entry_points(dist)
    findings.extend(extra)
    modules = discover_modules(dist, points)
    findings.extend(validate_entry_points(dist, points, modules))
    deps, extra = analyse_dependencies(dist, extras="all", context=context)
    findings.extend(extra)
    binaries, extra = inspect_binaries(dist, settings.limits)
    findings.extend(extra)
    licences, extra = analyse_licences(dist)
    findings.extend(extra)
    validation, extra = validate_distribution(dist)
    findings.extend(extra)
    members = [member for member in dist.archive.members if not member.is_dir]
    sizes = size_report(dist, members)
    meta = dist.metadata
    payload = {
        "schema_version": "1.0",
        "distribution": {
            "name": meta.name if meta else None,
            "version": meta.version if meta else None,
            "format": dist.format,
            "filename": dist.filename,
        },
        "summary": {
            "file_count": dist.file_count,
            "archive_size": dist.archive_size,
            "uncompressed_size": dist.uncompressed_size,
            "has_native_extensions": bool(binaries),
        },
        "requires_python": meta.requires_python if meta else None,
        "compatibility_tags": {
            "python": dist.wheel_name.python_tags if dist.wheel_name else [],
            "abi": dist.wheel_name.abi_tags if dist.wheel_name else [],
            "platform": dist.wheel_name.platform_tags if dist.wheel_name else [],
        },
        "dependencies": [
            item.raw if hasattr(item, "raw") else f"{item.name} {item.specifier}".strip()
            for item in deps
            if item.kind in {"runtime", "environment"}
        ],
        "optional_dependency_groups": list(meta.provides_extra) if meta else [],
        "entry_points": [
            f"{item.name} -> {item.module}" + (f":{item.object}" if item.object else "")
            for item in points
            if item.group in {"console_scripts", "gui_scripts"}
        ],
        "modules": [item.import_path for item in modules],
        "native_extensions": bool(binaries),
        "licence": licences,
        "metadata_version": meta.metadata_version if meta else None,
        "build_backend": dist.build_backend,
        "validation": {
            "status": validation.get("status"),
            "errors": validation.get("errors"),
            "warnings": validation.get("warnings"),
        },
        "sizes": sizes,
        "bundled_scripts": bundled_scripts(dist),
        "warning_messages": [item.explanation for item in findings if item.severity == "warning"],
        "findings": [item.as_dict() for item in _unique(findings)],
        "limitations": [
            "Inspection does not install, import, or execute package code.",
            "Dynamic metadata is not materialised.",
            "RECORD hashes do not prove publisher identity.",
        ],
    }
    # Prefer original Requires-Dist strings for inspect.
    if meta:
        payload["dependencies"] = list(meta.requires_dist)
    return payload, _unique(findings)


def full_report(dist: Distribution, settings: Settings, limits: Limits) -> dict[str, Any]:
    payload, _ = inspect_payload(dist, settings)
    from lupaxa.package_autopsy.audit import audit_distribution
    from lupaxa.package_autopsy.compatibility import analyse_compatibility
    from lupaxa.package_autopsy.contents import member_as_dict
    from lupaxa.package_autopsy.verify import verify_distribution

    compat, _ = analyse_compatibility(dist)
    audit, _ = audit_distribution(dist, settings)
    verify, _ = verify_distribution(dist)
    payload["compatibility"] = compat
    payload["audit"] = audit
    payload["integrity"] = verify
    payload["contents"] = [member_as_dict(member) for member in dist.archive.members if not member.is_dir]
    payload["overall_assessment"] = _overall(payload)
    return payload


def _overall(payload: dict[str, Any]) -> str:
    errors = (payload.get("validation") or {}).get("errors") or 0
    if errors:
        return "issues"
    warnings = (payload.get("validation") or {}).get("warnings") or 0
    if warnings:
        return "warnings"
    return "clean"


def _unique(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None]] = set()
    result: list[Finding] = []
    for item in findings:
        key = (item.identifier, item.path, item.field)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result
