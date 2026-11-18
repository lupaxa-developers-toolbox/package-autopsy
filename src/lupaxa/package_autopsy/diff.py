"""Release comparison and wheel/sdist consistency."""

from __future__ import annotations

import difflib
import hashlib
from collections.abc import Iterable
from typing import Any

from lupaxa.package_autopsy.contents import annotate
from lupaxa.package_autopsy.entrypoints import parse_entry_points
from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import ChangeKind, Finding
from lupaxa.package_autopsy.modules import discover_modules

TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".txt",
    ".md",
    ".rst",
    ".toml",
    ".cfg",
    ".ini",
    ".json",
    ".yml",
    ".yaml",
}


def compare_distributions(
    left: Distribution,
    right: Distribution,
    *,
    context: int = 3,
    ignore_whitespace: bool = False,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size: int | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    left_meta = left.metadata
    right_meta = right.metadata
    version_change = {
        "from": left_meta.version if left_meta else None,
        "to": right_meta.version if right_meta else None,
        "kind": _change(left_meta.version if left_meta else None, right_meta.version if right_meta else None),
    }
    modules = _named_change(
        {item.import_path for item in discover_modules(left)},
        {item.import_path for item in discover_modules(right)},
    )
    left_eps, _ = parse_entry_points(left)
    right_eps, _ = parse_entry_points(right)
    entry_points = _named_change(
        {f"{item.group}:{item.name}" for item in left_eps},
        {f"{item.group}:{item.name}" for item in right_eps},
    )
    left_deps = set(left_meta.requires_dist if left_meta else [])
    right_deps = set(right_meta.requires_dist if right_meta else [])
    dependencies = _named_change(left_deps, right_deps)
    files = _file_changes(left, right, include=include, exclude=exclude)
    breaking: list[str] = []
    if modules["removed"]:
        breaking.append("removed modules")
        findings.append(
            Finding(
                "COMPARE-REMOVED-MODULE",
                "comparison",
                "warning",
                "Modules present in the first distribution are missing in the second.",
                confidence="heuristic",
                suggestion="Treat removed import names as potential compatibility changes.",
            )
        )
    if entry_points["removed"]:
        breaking.append("removed entry points")
    if _python_floor_raised(
        left_meta.requires_python if left_meta else None,
        right_meta.requires_python if right_meta else None,
    ):
        breaking.append("increased minimum Python version")
    payload = {
        "distribution": {
            "from": left_meta.name if left_meta else left.filename,
            "to": right_meta.name if right_meta else right.filename,
        },
        "version": version_change,
        "modules": modules,
        "entry_points": entry_points,
        "dependencies": dependencies,
        "compatibility": {
            "from": left_meta.requires_python if left_meta else None,
            "to": right_meta.requires_python if right_meta else None,
        },
        "size": {"from": left.archive_size, "to": right.archive_size},
        "files": files,
        "diffs": _text_diffs(
            left,
            right,
            files.get("modified", []),
            context=context,
            ignore_whitespace=ignore_whitespace,
            max_file_size=max_file_size,
        ),
        "potential_compatibility_changes": breaking,
        "note": ("These observations come from archive inspection. They do not prove semantic API compatibility."),
    }
    return payload, findings


def consistency_report(
    sdist: Distribution,
    wheels: list[Distribution],
) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    reports = []
    sdist_modules = {item.import_path for item in discover_modules(sdist) if "noninstall" not in item.kind}
    sdist_meta = sdist.metadata
    for wheel in wheels:
        wheel_modules = {item.import_path for item in discover_modules(wheel)}
        wheel_meta = wheel.metadata
        expected = {
            "build configuration",
            "tests",
            "documentation",
            "generated metadata",
            "compiled extensions",
            "generated Python files",
            "build artefacts",
        }
        missing = sorted(sdist_modules - wheel_modules)
        extra = sorted(wheel_modules - sdist_modules)
        meta_issues = []
        if sdist_meta and wheel_meta:
            if sdist_meta.name and wheel_meta.name and sdist_meta.name != wheel_meta.name:
                meta_issues.append("name")
            if sdist_meta.version and wheel_meta.version and sdist_meta.version != wheel_meta.version:
                meta_issues.append("version")
            if (sdist_meta.requires_python or "") != (wheel_meta.requires_python or ""):
                meta_issues.append("requires-python")
            if set(sdist_meta.requires_dist) != set(wheel_meta.requires_dist):
                meta_issues.append("dependencies")
        indeterminate = bool(sdist.dynamic_fields)
        if indeterminate:
            findings.append(
                Finding(
                    "CONSISTENCY-DYNAMIC",
                    "consistency",
                    "informational",
                    "Source distribution declares dynamic metadata; equivalence cannot be proven statically.",
                    path=sdist.filename,
                    confidence="incomplete",
                )
            )
        reports.append(
            {
                "wheel": wheel.filename,
                "missing_modules": missing,
                "extra_modules": extra,
                "metadata_differences": meta_issues,
                "expected_difference_classes": sorted(expected),
                "indeterminate": indeterminate,
            }
        )
        if extra:
            findings.append(
                Finding(
                    "CONSISTENCY-EXTRA-WHEEL-MODULE",
                    "consistency",
                    "informational",
                    f"{wheel.filename} contains import names not found as Python sources in the sdist.",
                    confidence="heuristic",
                    suggestion="Compiled or generated modules are often expected.",
                )
            )
    payload = {
        "sdist": sdist.filename,
        "wheels": reports,
        "note": (
            "Wheels and source distributions are different artefacts. Tests, docs, "
            "and build files are often omitted from wheels on purpose."
        ),
    }
    return payload, findings


def _change(old: Any, new: Any) -> ChangeKind:
    if old == new:
        return "unchanged"
    if old is None:
        return "added"
    if new is None:
        return "removed"
    return "modified"


def _named_change(left: set[str], right: set[str]) -> dict[str, list[str]]:
    return {
        "added": sorted(right - left),
        "removed": sorted(left - right),
        "unchanged": sorted(left & right),
    }


def _file_changes(
    left: Distribution,
    right: Distribution,
    *,
    include: list[str] | None,
    exclude: list[str] | None,
) -> dict[str, Any]:
    from lupaxa.package_autopsy.contents import matches_filters

    annotate(left)
    annotate(right)
    left_map = {
        member.name: member
        for member in left.archive.members
        if not member.is_dir and matches_filters(member.name, include=include, exclude=exclude)
    }
    right_map = {
        member.name: member
        for member in right.archive.members
        if not member.is_dir and matches_filters(member.name, include=include, exclude=exclude)
    }
    added = sorted(set(right_map) - set(left_map))
    removed = sorted(set(left_map) - set(right_map))
    modified = []
    unchanged = []
    for name in sorted(set(left_map) & set(right_map)):
        if left_map[name].size != right_map[name].size:
            modified.append(name)
            continue
        try:
            if _hash(left, name) != _hash(right, name):
                modified.append(name)
            else:
                unchanged.append(name)
        except Exception:
            modified.append(name)
    return {"added": added, "removed": removed, "modified": modified, "unchanged": unchanged}


def _hash(dist: Distribution, name: str) -> str:
    return hashlib.sha256(dist.read(name)).hexdigest()


def _text_diffs(
    left: Distribution,
    right: Distribution,
    names: Iterable[str],
    *,
    context: int,
    ignore_whitespace: bool,
    max_file_size: int | None,
) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    for name in names:
        if not any(name.endswith(suffix) for suffix in TEXT_SUFFIXES):
            diffs.append({"path": name, "kind": "binary", "diff": None})
            continue
        try:
            left_data = left.read(name)
            right_data = right.read(name)
        except Exception:
            diffs.append({"path": name, "kind": "indeterminate", "diff": None})
            continue
        if max_file_size and (len(left_data) > max_file_size or len(right_data) > max_file_size):
            diffs.append({"path": name, "kind": "skipped-size", "diff": None})
            continue
        left_lines = left_data.decode("utf-8", errors="replace").splitlines()
        right_lines = right_data.decode("utf-8", errors="replace").splitlines()
        if ignore_whitespace:
            left_lines = [line.rstrip() for line in left_lines]
            right_lines = [line.rstrip() for line in right_lines]
        rendered = list(
            difflib.unified_diff(
                left_lines,
                right_lines,
                fromfile=f"a/{name}",
                tofile=f"b/{name}",
                n=context,
                lineterm="",
            )
        )
        diffs.append({"path": name, "kind": "text", "diff": "\n".join(rendered)})
    return diffs


def _python_floor_raised(old: str | None, new: str | None) -> bool:
    if not old or not new or old == new:
        return False
    return new.replace(" ", "") != old.replace(" ", "") and ">" in new
