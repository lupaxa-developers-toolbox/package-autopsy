"""Declared dependency analysis. No downloads and no resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from packaging.markers import Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import Dependency, Finding


@dataclass
class MarkerContext:
    python_version: str | None = None
    platform: str | None = None
    implementation: str | None = None
    extras: frozenset[str] = frozenset()

    def environment(self) -> dict[str, str]:
        env = {key: str(value) for key, value in default_environment().items()}
        if self.python_version:
            parts = self.python_version.split(".")
            env["python_version"] = ".".join(parts[:2])
            env["python_full_version"] = self.python_version if len(parts) >= 3 else f"{self.python_version}.0"
        if self.implementation:
            env["implementation_name"] = self.implementation
        if self.platform:
            mapping = {
                "linux": "Linux",
                "darwin": "Darwin",
                "macos": "Darwin",
                "win32": "Windows",
                "windows": "Windows",
            }
            env["sys_platform"] = {
                "linux": "linux",
                "darwin": "darwin",
                "macos": "darwin",
                "win32": "win32",
                "windows": "win32",
            }.get(self.platform.lower(), self.platform)
            env["platform_system"] = mapping.get(self.platform.lower(), self.platform)
        return env


def analyse_dependencies(
    dist: Distribution,
    *,
    extras: str | None = None,
    context: MarkerContext | None = None,
) -> tuple[list[Dependency], list[Finding]]:
    findings: list[Finding] = []
    context = context or MarkerContext()
    selected = _selected_extras(dist, extras)
    context.extras = selected
    deps: list[Dependency] = []
    seen: dict[tuple[str, str | None, str | None], list[Dependency]] = {}

    for raw in dist.metadata.requires_dist if dist.metadata else []:
        dep, extra_findings = _from_requirement(raw, kind="runtime")
        findings.extend(extra_findings)
        if dep is None:
            continue
        dep.applicable = _applicable(dep, context)
        deps.append(dep)
        seen.setdefault((dep.normalised, dep.marker, dep.extra_group), []).append(dep)

    if dist.pyproject:
        system = dist.pyproject.get("build-system")
        if isinstance(system, dict):
            requires = system.get("requires") or []
            if isinstance(requires, list):
                for raw in requires:
                    dep, extra_findings = _from_requirement(str(raw), kind="build")
                    findings.extend(extra_findings)
                    if dep is not None:
                        dep.applicable = True
                        deps.append(dep)

    findings.extend(_duplicate_conflicts(seen, context))
    declared_extras = {canonicalize_name(item) for item in (dist.metadata.provides_extra if dist.metadata else [])}
    used_extras = {canonicalize_name(dep.extra_group) for dep in deps if dep.extra_group}
    for extra in sorted(declared_extras - used_extras):
        findings.append(
            Finding(
                "DEPENDENCY-UNUSED-EXTRA",
                "dependencies",
                "informational",
                f"Extra {extra!r} is declared but no Requires-Dist references it.",
                field="Provides-Extra",
                confidence="heuristic",
            )
        )
    return deps, findings


def _selected_extras(dist: Distribution, extras: str | None) -> frozenset[str]:
    declared = [canonicalize_name(item) for item in (dist.metadata.provides_extra if dist.metadata else [])]
    if extras is None or extras == "":
        return frozenset()
    if extras == "all":
        return frozenset(declared)
    return frozenset(canonicalize_name(part) for part in extras.split(",") if part.strip())


def _from_requirement(raw: str, *, kind: str) -> tuple[Dependency | None, list[Finding]]:
    findings: list[Finding] = []
    try:
        req = Requirement(raw)
    except InvalidRequirement as exc:
        findings.append(
            Finding(
                "DEPENDENCY-INVALID",
                "dependencies",
                "error",
                f"Invalid requirement {raw!r}: {exc}",
                field="Requires-Dist",
                standard="PEP 508",
            )
        )
        return None, findings
    extra_group = None
    marker_text = str(req.marker) if req.marker else None
    if req.marker is not None:
        extra_group = _extra_from_marker(str(req.marker))
    issues: list[str] = []
    if req.url:
        issues.append("direct-url")
        findings.append(
            Finding(
                "DEPENDENCY-DIRECT-URL",
                "dependencies",
                "informational",
                f"{req.name} is a direct URL dependency.",
                field="Requires-Dist",
                standard="PEP 508",
            )
        )
    if str(req.specifier) in {"", "*"}:
        issues.append("unbounded")
    dep = Dependency(
        name=req.name,
        normalised=canonicalize_name(req.name),
        specifier=str(req.specifier),
        extras=tuple(sorted(req.extras)),
        marker=marker_text,
        extra_group=extra_group,
        url=req.url,
        kind=kind if extra_group is None else "extra",
        issues=issues,
    )
    if extra_group:
        dep.kind = "extra"
    elif req.marker:
        dep.kind = "environment"
    return dep, findings


def _extra_from_marker(marker: str) -> str | None:
    match = re_search_extra(marker)
    return match


def re_search_extra(marker: str) -> str | None:
    match = re.search(r"""extra\s*==\s*['"]([^'"]+)['"]""", marker)
    if match:
        return canonicalize_name(match.group(1))
    return None


def _applicable(dep: Dependency, context: MarkerContext) -> bool | None:
    if not dep.marker:
        return True
    try:
        marker = Marker(dep.marker)
        env = context.environment()
        env["extra"] = next(iter(context.extras), "")
        return bool(marker.evaluate(env))
    except Exception:
        return None


def _duplicate_conflicts(
    seen: dict[tuple[str, str | None, str | None], list[Dependency]],
    context: MarkerContext,
) -> list[Finding]:
    findings: list[Finding] = []
    by_name: dict[str, list[Dependency]] = {}
    for deps in seen.values():
        for dep in deps:
            by_name.setdefault(dep.normalised, []).append(dep)
    for name, items in by_name.items():
        if len(items) < 2:
            continue
        findings.append(
            Finding(
                "DEPENDENCY-DUPLICATE",
                "dependencies",
                "warning",
                f"{name} is declared more than once.",
                field="Requires-Dist",
                confidence="heuristic",
            )
        )
        applicable = [item for item in items if item.applicable]
        specifiers = [item.specifier for item in applicable if item.specifier]
        if len(specifiers) >= 2:
            try:
                combined = SpecifierSet(",".join(specifiers))
                if not any(True for _ in [combined]):
                    pass
            except Exception:
                findings.append(
                    Finding(
                        "DEPENDENCY-CONFLICT",
                        "dependencies",
                        "warning",
                        f"{name} has specifier combinations that may conflict.",
                        field="Requires-Dist",
                        confidence="heuristic",
                    )
                )
    return findings


def dependencies_payload(deps: list[Dependency]) -> dict[str, Any]:
    groups = {
        "runtime": [item.as_dict() for item in deps if item.kind == "runtime"],
        "environment": [item.as_dict() for item in deps if item.kind == "environment"],
        "extra": [item.as_dict() for item in deps if item.kind == "extra"],
        "build": [item.as_dict() for item in deps if item.kind == "build"],
    }
    return {
        "dependencies": [item.as_dict() for item in deps],
        "groups": groups,
        "note": (
            "Only direct declared dependencies are shown. Transitive resolution "
            "requires metadata for each dependency distribution."
        ),
    }
