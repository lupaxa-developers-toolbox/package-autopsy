"""Shared data models for Package Autopsy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["error", "warning", "informational", "unknown"]
Confidence = Literal["certain", "heuristic", "incomplete"]
FormatKind = Literal["wheel", "sdist", "malformed", "unsupported", "ordinary_archive"]
VerificationStatus = Literal["passed", "failed", "incomplete", "unsupported"]
ChangeKind = Literal[
    "added",
    "removed",
    "modified",
    "unchanged",
    "metadata-only",
    "indeterminate",
]


@dataclass(frozen=True)
class Finding:
    identifier: str
    category: str
    severity: Severity
    explanation: str
    path: str | None = None
    field: str | None = None
    standard: str | None = None
    suggestion: str | None = None
    confidence: Confidence = "certain"
    evidence: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "category": self.category,
            "severity": self.severity,
            "path": self.path,
            "field": self.field,
            "explanation": self.explanation,
            "standard": self.standard,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class ArchiveMember:
    name: str
    size: int
    compressed_size: int | None = None
    is_dir: bool = False
    crc: int | None = None
    mode: int | None = None
    is_symlink: bool = False
    link_target: str | None = None
    category: str = "unknown"
    category_confidence: Confidence = "heuristic"


@dataclass
class CoreMetadata:
    raw: dict[str, list[str]] = field(default_factory=dict)
    name: str | None = None
    version: str | None = None
    summary: str | None = None
    description: str | None = None
    description_content_type: str | None = None
    author: str | None = None
    author_email: str | None = None
    maintainer: str | None = None
    maintainer_email: str | None = None
    home_page: str | None = None
    project_urls: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    classifiers: list[str] = field(default_factory=list)
    license: str | None = None
    license_expression: str | None = None
    license_files: list[str] = field(default_factory=list)
    requires_python: str | None = None
    requires_dist: list[str] = field(default_factory=list)
    provides_extra: list[str] = field(default_factory=list)
    dynamic: list[str] = field(default_factory=list)
    metadata_version: str | None = None
    source: str | None = None

    def get_all(self, key: str) -> list[str]:
        return list(self.raw.get(key.lower(), []))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "description": self.description,
            "description_content_type": self.description_content_type,
            "author": self.author,
            "author_email": self.author_email,
            "maintainer": self.maintainer,
            "maintainer_email": self.maintainer_email,
            "home_page": self.home_page,
            "project_urls": list(self.project_urls),
            "keywords": list(self.keywords),
            "classifiers": list(self.classifiers),
            "license": self.license,
            "license_expression": self.license_expression,
            "license_files": list(self.license_files),
            "requires_python": self.requires_python,
            "requires_dist": list(self.requires_dist),
            "provides_extra": list(self.provides_extra),
            "dynamic": list(self.dynamic),
            "metadata_version": self.metadata_version,
            "source": self.source,
        }


@dataclass
class WheelFilename:
    distribution: str
    version: str
    build: str | None
    python_tags: list[str]
    abi_tags: list[str]
    platform_tags: list[str]
    raw: str


@dataclass
class Dependency:
    name: str
    normalised: str
    specifier: str
    extras: tuple[str, ...]
    marker: str | None
    extra_group: str | None
    url: str | None
    kind: str
    applicable: bool | None = None
    issues: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "normalised": self.normalised,
            "specifier": self.specifier,
            "extras": list(self.extras),
            "marker": self.marker,
            "extra_group": self.extra_group,
            "url": self.url,
            "kind": self.kind,
            "applicable": self.applicable,
            "issues": list(self.issues),
        }


@dataclass
class EntryPoint:
    name: str
    group: str
    module: str
    object: str | None
    extras: tuple[str, ...]
    raw: str
    valid_syntax: bool
    module_present: bool | None
    object_status: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "group": self.group,
            "module": self.module,
            "object": self.object,
            "extras": list(self.extras),
            "raw": self.raw,
            "valid_syntax": self.valid_syntax,
            "module_present": self.module_present,
            "object_status": self.object_status,
            "source": self.source,
        }


@dataclass
class DiscoveredModule:
    import_path: str
    archive_path: str
    kind: str
    size: int
    package: str | None
    cli_target: bool
    native: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "import_path": self.import_path,
            "archive_path": self.archive_path,
            "kind": self.kind,
            "size": self.size,
            "package": self.package,
            "cli_target": self.cli_target,
            "native": self.native,
        }


@dataclass
class BinaryInfo:
    path: str
    format: str
    architecture: str | None
    size: int
    library_type: str
    libraries: list[str]
    notes: list[str]
    confidence: Confidence = "heuristic"

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "architecture": self.architecture,
            "size": self.size,
            "library_type": self.library_type,
            "libraries": list(self.libraries),
            "notes": list(self.notes),
            "confidence": self.confidence,
        }
