"""Parse and validate entry points without importing targets."""

from __future__ import annotations

import ast
import configparser
import re
from typing import Any

from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.metadata import dist_info_file, locate_sdist_file
from lupaxa.package_autopsy.models import DiscoveredModule, EntryPoint, Finding
from lupaxa.package_autopsy.safety import sanitize_text

_EP_RE = re.compile(
    r"^(?P<mod>[A-Za-z_][\w.]*)\s*(?::\s*(?P<obj>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*))?\s*"
    r"(?P<extras>\[[^\]]+\])?\s*$"
)


def parse_entry_points(dist: Distribution) -> tuple[list[EntryPoint], list[Finding]]:
    findings: list[Finding] = []
    points: list[EntryPoint] = []
    text, source = _entry_point_text(dist)
    if text is None:
        return points, findings
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        findings.append(
            Finding(
                "ENTRYPOINT-PARSE-ERROR",
                "entry_points",
                "error",
                f"entry_points.txt could not be parsed: {exc}",
                path=source,
                standard="entry_points.txt",
            )
        )
        return points, findings
    seen: set[tuple[str, str]] = set()
    for group in parser.sections():
        for name, value in parser.items(group):
            raw = sanitize_text(value.strip())
            match = _EP_RE.match(raw)
            extras: tuple[str, ...] = ()
            module = ""
            obj = None
            valid = match is not None
            if match:
                module = match.group("mod")
                obj = match.group("obj")
                extra_text = match.group("extras")
                if extra_text:
                    extras = tuple(part.strip() for part in extra_text.strip("[]").split(",") if part.strip())
            else:
                findings.append(
                    Finding(
                        "ENTRYPOINT-SYNTAX",
                        "entry_points",
                        "error",
                        f"Invalid entry point {name} = {raw!r}.",
                        path=source,
                        field=f"{group}:{name}",
                    )
                )
            key = (group, name)
            if key in seen:
                findings.append(
                    Finding(
                        "ENTRYPOINT-DUPLICATE",
                        "entry_points",
                        "error",
                        f"Duplicate entry point {group}:{name}.",
                        path=source,
                    )
                )
            seen.add(key)
            points.append(
                EntryPoint(
                    name=name,
                    group=group,
                    module=module,
                    object=obj,
                    extras=extras,
                    raw=raw,
                    valid_syntax=valid,
                    module_present=None,
                    object_status="not-checked",
                    source=source or "entry_points.txt",
                )
            )
    points.extend(_pyproject_scripts(dist, findings))
    return points, findings


def _entry_point_text(dist: Distribution) -> tuple[str | None, str | None]:
    path = dist_info_file(dist.archive, "entry_points.txt")
    if path:
        return dist.read(path).decode("utf-8", errors="replace"), path
    if dist.format == "sdist":
        # Static [project.scripts] is handled separately.
        return None, None
    return None, None


def _pyproject_scripts(dist: Distribution, findings: list[Finding]) -> list[EntryPoint]:
    if not dist.pyproject:
        py_path = locate_sdist_file(dist.archive, "pyproject.toml")
        if py_path is None:
            return []
    project = dist.pyproject.get("project") if dist.pyproject else None
    if not isinstance(project, dict):
        return []
    points: list[EntryPoint] = []
    mapping = {
        "scripts": "console_scripts",
        "gui-scripts": "gui_scripts",
        "gui_scripts": "gui_scripts",
    }
    for key, group in mapping.items():
        table = project.get(key)
        if not isinstance(table, dict):
            continue
        for name, value in table.items():
            if not isinstance(value, str):
                findings.append(
                    Finding(
                        "ENTRYPOINT-SYNTAX",
                        "entry_points",
                        "error",
                        f"pyproject {key}.{name} is not a string.",
                        path="pyproject.toml",
                    )
                )
                continue
            match = _EP_RE.match(value.strip())
            points.append(
                EntryPoint(
                    name=str(name),
                    group=group,
                    module=match.group("mod") if match else "",
                    object=match.group("obj") if match else None,
                    extras=(),
                    raw=value.strip(),
                    valid_syntax=match is not None,
                    module_present=None,
                    object_status="not-checked",
                    source="pyproject.toml",
                )
            )
    entry_tables = project.get("entry-points") or project.get("entry_points")
    if isinstance(entry_tables, dict):
        for group, table in entry_tables.items():
            if not isinstance(table, dict):
                continue
            for name, value in table.items():
                if not isinstance(value, str):
                    continue
                match = _EP_RE.match(value.strip())
                points.append(
                    EntryPoint(
                        name=str(name),
                        group=str(group),
                        module=match.group("mod") if match else "",
                        object=match.group("obj") if match else None,
                        extras=(),
                        raw=value.strip(),
                        valid_syntax=match is not None,
                        module_present=None,
                        object_status="not-checked",
                        source="pyproject.toml",
                    )
                )
    return points


def validate_entry_points(
    dist: Distribution,
    points: list[EntryPoint],
    modules: list[DiscoveredModule],
) -> list[Finding]:
    findings: list[Finding] = []
    import_names = {item.import_path for item in modules}
    path_by_import = {item.import_path: item.archive_path for item in modules}
    for point in points:
        if not point.valid_syntax:
            continue
        present = point.module in import_names or any(name.startswith(f"{point.module}.") for name in import_names)
        # A module `lupaxa.demo.cli` is present if that file exists.
        point.module_present = point.module in import_names
        if not present and point.module not in import_names:
            findings.append(
                Finding(
                    "ENTRYPOINT-MODULE-MISSING",
                    "entry_points",
                    "warning",
                    f"Entry point {point.name} targets module {point.module} which was not found in the distribution.",
                    field=f"{point.group}:{point.name}",
                    confidence="heuristic",
                    suggestion="Confirm the module is packaged, or that it is generated at build time.",
                )
            )
            point.object_status = "module-missing"
            continue
        if point.object is None:
            point.object_status = "module-only"
            continue
        archive_path = path_by_import.get(point.module)
        if archive_path is None:
            point.object_status = "incomplete"
            continue
        if not archive_path.endswith((".py", ".pyw")):
            point.object_status = "incomplete"
            findings.append(
                Finding(
                    "ENTRYPOINT-OBJECT-INCOMPLETE",
                    "entry_points",
                    "informational",
                    f"Target object {point.object} cannot be verified in {archive_path}.",
                    confidence="incomplete",
                )
            )
            continue
        try:
            source = dist.read(archive_path).decode("utf-8")
            parsed = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError, OSError):
            point.object_status = "incomplete"
            continue
        if not isinstance(parsed, ast.Module):
            point.object_status = "incomplete"
            continue
        names = _top_level_names(parsed)
        head = point.object.split(".", 1)[0]
        if head in names:
            point.object_status = "static"
        else:
            point.object_status = "unresolved"
            findings.append(
                Finding(
                    "ENTRYPOINT-OBJECT-UNRESOLVED",
                    "entry_points",
                    "informational",
                    f"Object {point.object} is not a top-level name in {archive_path}; it may be created dynamically.",
                    confidence="heuristic",
                )
            )
    return findings


def _top_level_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ImportFrom) and node.names:
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".", 1)[0])
    return names


def bundled_scripts(dist: Distribution) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    for member in dist.archive.members:
        parts = member.name.split("/")
        if member.is_dir:
            continue
        if any(part.endswith(".data") for part in parts) and "scripts" in parts:
            scripts.append({"path": member.name, "size": member.size, "source": "wheel-data-scripts"})
        if dist.format == "sdist" and (member.name.endswith(".sh") or "/scripts/" in member.name):
            scripts.append({"path": member.name, "size": member.size, "source": "bundled-file"})
    return scripts
