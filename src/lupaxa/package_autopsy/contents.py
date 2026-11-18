"""File inventory, classification, and size analysis."""

from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import ArchiveMember, Confidence
from lupaxa.package_autopsy.safety import normalise_member_name

PYTHON_SOURCE = {".py", ".pyw"}
BYTECODE = {".pyc", ".pyo"}
EXTENSION = {".so", ".pyd", ".abi3.so"}
SHARED = {".dll", ".dylib", ".so"}
EXECUTABLE_EXT = {".exe", ".bin", ".sh", ".bat", ".cmd"}
CONFIG_EXT = {".cfg", ".ini", ".toml", ".yaml", ".yml", ".json"}
DOC_EXT = {".md", ".rst", ".txt", ".html"}
LICENCE_NAMES = {"license", "licence", "copying", "notice", "authors"}
TEST_HINTS = ("/tests/", "/test/", "/testing/", "conftest.py")


def classify_member(member: ArchiveMember) -> tuple[str, Confidence]:
    name = member.name
    lowered = name.lower()
    parts = PurePosixPath(name).parts
    suffix = "".join(PurePosixPath(name).suffixes[-2:]) if PurePosixPath(name).suffixes else ""
    ext = PurePosixPath(name).suffix.lower()

    if any(part.endswith(".dist-info") or part.endswith(".egg-info") for part in parts):
        return "metadata", "certain"
    if any(part.endswith(".data") for part in parts) and "scripts" in parts:
        return "executable", "certain"
    if lowered.endswith(".pyi") or lowered.endswith("-stubs"):
        return "python source", "certain"
    if ext in PYTHON_SOURCE:
        return "python source", "certain"
    if ext in BYTECODE:
        return "python bytecode", "certain"
    if ext == ".so" or ext == ".pyd" or suffix.endswith(".so"):
        if ext == ".pyd" or "cpython" in lowered or ".abi3" in lowered:
            return "native extension", "certain"
        return "shared library", "heuristic"
    if ext in {".dll", ".dylib"}:
        return "shared library", "heuristic"
    if ext in EXECUTABLE_EXT:
        return "executable", "heuristic"
    if any(PurePosixPath(name).name.lower().startswith(item) for item in LICENCE_NAMES):
        return "licence", "heuristic"
    if ext in CONFIG_EXT:
        return "configuration", "heuristic"
    if any(hint in f"/{lowered}/" for hint in TEST_HINTS) or PurePosixPath(name).name.startswith("test_"):
        return "tests", "heuristic"
    if "/docs/" in f"/{lowered}/" or "/doc/" in f"/{lowered}/" or ext in {".md", ".rst"}:
        return "documentation", "heuristic"
    if ext in DOC_EXT:
        return "documentation", "heuristic"
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".dat", ".bin"}:
        return "package data", "heuristic"
    return "unknown", "heuristic"


def annotate(dist: Distribution) -> list[ArchiveMember]:
    members = []
    for member in dist.archive.members:
        category, confidence = classify_member(member)
        member.category = category
        member.category_confidence = confidence
        members.append(member)
    return members


def matches_filters(
    name: str,
    *,
    include: list[str] | None,
    exclude: list[str] | None,
    regex: str | None = None,
) -> bool:
    path = normalise_member_name(name)
    if include and not any(fnmatch.fnmatch(path, pattern) for pattern in include):
        return False
    if exclude and any(fnmatch.fnmatch(path, pattern) for pattern in exclude):
        return False
    return not (regex and re.search(regex, path) is None)


def filtered_members(
    dist: Distribution,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    regex: str | None = None,
) -> list[ArchiveMember]:
    annotate(dist)
    return [
        member
        for member in dist.archive.members
        if matches_filters(member.name, include=include, exclude=exclude, regex=regex)
    ]


def sort_members(members: Iterable[ArchiveMember], sort: str) -> list[ArchiveMember]:
    items = list(members)
    if sort == "size":
        items.sort(key=lambda item: (-item.size, item.name))
    elif sort == "type":
        items.sort(key=lambda item: (item.category, item.name))
    else:
        items.sort(key=lambda item: item.name)
    return items


def tree_lines(members: list[ArchiveMember]) -> list[str]:
    files = [member for member in members if not member.is_dir]
    lines: list[str] = []
    by_dir: dict[str, list[ArchiveMember]] = defaultdict(list)
    for member in files:
        parent = str(PurePosixPath(member.name).parent)
        if parent == ".":
            parent = ""
        by_dir[parent].append(member)
    prefixes = sorted(by_dir)
    for prefix in prefixes:
        if prefix:
            lines.append(f"{prefix}/")
        for member in sorted(by_dir[prefix], key=lambda item: item.name):
            indent = "  " if prefix else ""
            lines.append(f"{indent}{PurePosixPath(member.name).name}  ({member.size} B, {member.category})")
    return lines


def size_report(dist: Distribution, members: list[ArchiveMember]) -> dict[str, Any]:
    files = [member for member in members if not member.is_dir]
    by_type: dict[str, int] = Counter()
    by_dir: dict[str, int] = Counter()
    for member in files:
        by_type[member.category] += member.size
        parent = str(PurePosixPath(member.name).parent)
        by_dir[parent] += member.size
    largest_files = sorted(files, key=lambda item: (-item.size, item.name))[:10]
    largest_dirs = sorted(by_dir.items(), key=lambda item: (-item[1], item[0]))[:10]
    return {
        "archive_size": dist.archive_size,
        "uncompressed_size": sum(item.size for item in files),
        "file_count": len(files),
        "by_type": dict(sorted(by_type.items())),
        "python_source_size": by_type.get("python source", 0),
        "binary_size": by_type.get("native extension", 0) + by_type.get("shared library", 0),
        "documentation_size": by_type.get("documentation", 0),
        "test_size": by_type.get("tests", 0),
        "largest_files": [{"path": item.name, "size": item.size, "category": item.category} for item in largest_files],
        "largest_directories": [{"path": path or ".", "size": size} for path, size in largest_dirs],
        "extension_counts": dict(Counter(PurePosixPath(item.name).suffix.lower() or "<none>" for item in files)),
    }


def member_as_dict(member: ArchiveMember) -> dict[str, Any]:
    return {
        "path": member.name,
        "size": member.size,
        "compressed_size": member.compressed_size,
        "is_dir": member.is_dir,
        "category": member.category,
        "category_confidence": member.category_confidence,
        "mode": member.mode,
    }
