"""Load a wheel or source distribution without installing or executing it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from lupaxa.package_autopsy.archive import SafeArchive, open_archive, sniff_magic
from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.errors import (
    InvalidDistributionError,
    ResourceLimitError,
    UnsupportedError,
)
from lupaxa.package_autopsy.metadata import (
    build_backend_from_pyproject,
    dist_info_file,
    dynamic_fields_from_pyproject,
    find_dist_info,
    locate_sdist_file,
    parse_core_metadata,
    parse_pyproject,
    parse_sdist_name,
    parse_setup_cfg,
    parse_wheel_name,
    sdist_root,
    validate_identity,
)
from lupaxa.package_autopsy.models import CoreMetadata, Finding, FormatKind, WheelFilename
from lupaxa.package_autopsy.safety import normalise_member_name

WHEEL_FILES = ("METADATA", "WHEEL", "RECORD")


@dataclass
class Distribution:
    path: Path
    filename: str
    format: FormatKind
    archive_size: int
    archive: SafeArchive
    findings: list[Finding] = field(default_factory=list)
    metadata: CoreMetadata | None = None
    wheel_name: WheelFilename | None = None
    wheel_file: dict[str, list[str]] = field(default_factory=dict)
    dist_info: str | None = None
    sdist_root: str = ""
    pyproject: dict[str, Any] = field(default_factory=dict)
    setup_cfg: dict[str, Any] = field(default_factory=dict)
    has_setup_py: bool = False
    has_manifest_in: bool = False
    build_backend: str | None = None
    dynamic_fields: list[str] = field(default_factory=list)
    misleading_extension: bool = False
    top_level: list[str] = field(default_factory=list)

    def close(self) -> None:
        self.archive.close()

    def __enter__(self) -> Distribution:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def file_count(self) -> int:
        return sum(1 for member in self.archive.members if not member.is_dir)

    @property
    def uncompressed_size(self) -> int:
        return sum(member.size for member in self.archive.members if not member.is_dir)

    def read(self, name: str, *, limit: int | None = None) -> bytes:
        return self.archive.read(name, limit=limit)

    def names(self) -> list[str]:
        return self.archive.names()

    def has(self, name: str) -> bool:
        return normalise_member_name(name) in set(self.archive.names())

    def errors(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "error"]

    def warnings(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "warning"]


def load_distribution(path: Path, limits: Limits | None = None) -> Distribution:
    limits = limits or Limits()
    resolved = path.expanduser()
    if not resolved.is_file():
        raise InvalidDistributionError(f"not a file: {path}")
    try:
        archive = open_archive(resolved, limits)
    except ResourceLimitError:
        raise
    except InvalidDistributionError:
        raise
    except OSError as exc:
        raise InvalidDistributionError(f"cannot read {path}: {exc}") from exc

    filename = resolved.name
    magic = sniff_magic(resolved)
    fmt, misleading, extra = _detect_format(filename, magic, archive)
    findings = list(archive.findings) + extra
    dist = Distribution(
        path=resolved,
        filename=filename,
        format=fmt,
        archive_size=archive.size,
        archive=archive,
        findings=findings,
        misleading_extension=misleading,
    )
    if fmt == "wheel":
        _load_wheel(dist, limits)
    elif fmt == "sdist":
        _load_sdist(dist, limits)
    elif fmt == "ordinary_archive":
        dist.findings.append(
            Finding(
                "FORMAT-NOT-DISTRIBUTION",
                "format",
                "informational",
                "Archive is readable but is not a Python wheel or source distribution.",
                path=filename,
            )
        )
    elif fmt == "malformed":
        dist.findings.append(
            Finding(
                "FORMAT-MALFORMED",
                "format",
                "error",
                "Archive looks like a Python distribution but is structurally malformed.",
                path=filename,
            )
        )
    return dist


def _detect_format(
    filename: str,
    magic: str,
    archive: SafeArchive,
) -> tuple[FormatKind, bool, list[Finding]]:
    findings: list[Finding] = []
    lower = filename.lower()
    names = archive.names()
    has_dist_info = any(".dist-info/" in f"{name}/" or name.endswith(".dist-info") for name in names)
    has_pkg_info = any(name.endswith("PKG-INFO") for name in names)
    has_pyproject = any(name.endswith("pyproject.toml") for name in names)
    looks_wheel = has_dist_info and any(
        name.endswith(".dist-info/METADATA") or name.endswith(".dist-info/WHEEL") for name in names
    )
    looks_sdist = has_pkg_info or has_pyproject
    misleading = False

    if lower.endswith(".whl"):
        if magic != "zip":
            findings.append(
                Finding(
                    "FORMAT-MISLEADING-EXTENSION",
                    "format",
                    "error",
                    "File uses a .whl extension but is not a ZIP archive.",
                    path=filename,
                )
            )
            return "malformed", True, findings
        if looks_wheel:
            return "wheel", False, findings
        findings.append(
            Finding(
                "FORMAT-WHEEL-STRUCTURE",
                "format",
                "error",
                "ZIP file uses a .whl extension but lacks wheel metadata.",
                path=filename,
                standard="PEP 427",
            )
        )
        return "malformed", False, findings

    if lower.endswith((".tar.gz", ".tgz", ".zip", ".tar")):
        expected_magic = "zip" if lower.endswith(".zip") else magic
        if lower.endswith(".zip") and magic != "zip":
            misleading = True
            findings.append(
                Finding(
                    "FORMAT-MISLEADING-EXTENSION",
                    "format",
                    "warning",
                    "File uses a .zip extension but is not a ZIP archive.",
                    path=filename,
                )
            )
        if lower.endswith((".tar.gz", ".tgz")) and magic != "gzip":
            misleading = True
            findings.append(
                Finding(
                    "FORMAT-MISLEADING-EXTENSION",
                    "format",
                    "warning",
                    "File uses a gzip tarball extension but the signature is not gzip.",
                    path=filename,
                )
            )
        if looks_sdist or looks_wheel:
            if looks_wheel and expected_magic == "zip" and not looks_sdist:
                return "wheel", misleading, findings
            return "sdist", misleading, findings
        if magic in {"zip", "gzip", "bzip2", "tar"}:
            return "ordinary_archive", misleading, findings
        return "unsupported", misleading, findings

    if looks_wheel:
        findings.append(
            Finding(
                "FORMAT-MISLEADING-EXTENSION",
                "format",
                "warning",
                "Archive contains wheel metadata but does not use a .whl filename.",
                path=filename,
            )
        )
        return "wheel", True, findings
    if looks_sdist:
        findings.append(
            Finding(
                "FORMAT-MISLEADING-EXTENSION",
                "format",
                "warning",
                "Archive contains source-distribution metadata but not a standard sdist name.",
                path=filename,
            )
        )
        return "sdist", True, findings
    if magic in {"zip", "gzip", "bzip2", "tar"}:
        return "ordinary_archive", False, findings
    return "unsupported", False, findings


def _load_wheel(dist: Distribution, limits: Limits) -> None:
    parsed, findings = parse_wheel_name(dist.filename)
    dist.findings.extend(findings)
    dist.wheel_name = parsed
    dist.dist_info = find_dist_info(dist.archive)
    if dist.dist_info is None:
        dist.findings.append(
            Finding(
                "WHEEL-DIST-INFO-MISSING",
                "wheel",
                "error",
                "Wheel has no .dist-info directory.",
                standard="PEP 427",
            )
        )
        return
    meta_name = dist_info_file(dist.archive, "METADATA")
    if meta_name:
        meta, extra = parse_core_metadata(dist.read(meta_name, limit=limits.max_scan_size), source=meta_name)
        dist.metadata = meta
        dist.findings.extend(extra)
        dist.findings.extend(validate_identity(meta))
    else:
        dist.findings.append(
            Finding(
                "WHEEL-METADATA-MISSING",
                "wheel",
                "error",
                "Wheel is missing METADATA.",
                path=f"{dist.dist_info}/METADATA",
                standard="PEP 427",
            )
        )
    wheel_name = dist_info_file(dist.archive, "WHEEL")
    if wheel_name:
        dist.wheel_file = _rfc822_headers(dist.read(wheel_name, limit=limits.max_scan_size))
    else:
        dist.findings.append(
            Finding(
                "WHEEL-WHEEL-FILE-MISSING",
                "wheel",
                "error",
                "Wheel is missing the WHEEL file.",
                path=f"{dist.dist_info}/WHEEL",
                standard="PEP 427",
            )
        )
    if dist_info_file(dist.archive, "RECORD") is None:
        dist.findings.append(
            Finding(
                "WHEEL-RECORD-MISSING",
                "wheel",
                "error",
                "Wheel is missing RECORD.",
                path=f"{dist.dist_info}/RECORD",
                standard="PEP 376",
            )
        )
    top = dist_info_file(dist.archive, "top_level.txt")
    if top:
        text = dist.read(top, limit=limits.max_scan_size).decode("utf-8", errors="replace")
        dist.top_level = [line.strip() for line in text.splitlines() if line.strip()]
        dist.findings.append(
            Finding(
                "WHEEL-TOP-LEVEL-PRESENT",
                "modules",
                "informational",
                "top_level.txt is present but is not an authoritative module inventory.",
                path=top,
                confidence="heuristic",
            )
        )
    if parsed and dist.metadata:
        _check_name_version(dist, parsed.distribution, parsed.version)


def _load_sdist(dist: Distribution, limits: Limits) -> None:
    parsed, findings = parse_sdist_name(dist.filename)
    dist.findings.extend(findings)
    dist.sdist_root = sdist_root(dist.archive)
    pkg = locate_sdist_file(dist.archive, "PKG-INFO")
    if pkg:
        meta, extra = parse_core_metadata(dist.read(pkg, limit=limits.max_scan_size), source=pkg)
        dist.metadata = meta
        dist.findings.extend(extra)
        dist.findings.extend(validate_identity(meta))
    pyproject_path = locate_sdist_file(dist.archive, "pyproject.toml")
    if pyproject_path:
        dist.pyproject, extra = parse_pyproject(dist.read(pyproject_path, limit=limits.max_scan_size))
        dist.findings.extend(extra)
        dist.build_backend = build_backend_from_pyproject(dist.pyproject)
        dist.dynamic_fields = dynamic_fields_from_pyproject(dist.pyproject)
        if dist.dynamic_fields:
            dist.findings.append(
                Finding(
                    "SDIST-DYNAMIC-METADATA",
                    "metadata",
                    "informational",
                    "Source distribution declares dynamic metadata that cannot be materialised "
                    "without executing a build backend.",
                    field="dynamic",
                    standard="PEP 621",
                    confidence="incomplete",
                )
            )
    setup_cfg_path = locate_sdist_file(dist.archive, "setup.cfg")
    if setup_cfg_path:
        parser = parse_setup_cfg(dist.read(setup_cfg_path, limit=limits.max_scan_size))
        dist.setup_cfg = {section: dict(parser.items(section)) for section in parser.sections()}
    dist.has_setup_py = locate_sdist_file(dist.archive, "setup.py") is not None
    dist.has_manifest_in = locate_sdist_file(dist.archive, "MANIFEST.in") is not None
    if dist.metadata is None and dist.pyproject:
        project = dist.pyproject.get("project")
        if isinstance(project, dict):
            dist.metadata = CoreMetadata(
                name=str(project["name"]) if "name" in project else None,
                version=str(project["version"]) if "version" in project else None,
                summary=str(project["description"]) if "description" in project else None,
                requires_python=str(project["requires-python"]) if "requires-python" in project else None,
                source="pyproject.toml",
                dynamic=list(dist.dynamic_fields),
            )
            dist.findings.extend(validate_identity(dist.metadata))
    if dist.metadata is None:
        dist.findings.append(
            Finding(
                "SDIST-METADATA-MISSING",
                "sdist",
                "warning",
                "No PKG-INFO or static pyproject project table was found.",
                standard="PEP 643",
                confidence="incomplete",
            )
        )
    if parsed and dist.metadata:
        _check_name_version(dist, parsed[0], parsed[1])
    system = dist.pyproject.get("build-system") if dist.pyproject else None
    if isinstance(system, dict) and "requires" in system:
        dist.build_backend = dist.build_backend or build_backend_from_pyproject(dist.pyproject)


def _safe_canonical_name(value: str) -> str | None:
    try:
        return canonicalize_name(value)
    except InvalidName:
        return None


def _safe_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _check_name_version(dist: Distribution, filename_name: str, filename_version: str) -> None:
    meta = dist.metadata
    if meta is None:
        return
    if meta.name:
        meta_name = _safe_canonical_name(meta.name)
        file_name = _safe_canonical_name(str(filename_name).replace("_", "-"))
        if meta_name is not None and file_name is not None and meta_name != file_name:
            dist.findings.append(
                Finding(
                    "IDENTITY-NAME-MISMATCH",
                    "metadata",
                    "error",
                    f"Filename name {filename_name!r} does not match metadata name {meta.name!r}.",
                    field="Name",
                    standard="PEP 427 / PEP 625",
                )
            )
    if meta.version:
        meta_version = _safe_version(meta.version)
        file_version = _safe_version(str(filename_version))
        if meta_version is not None and file_version is not None and meta_version != file_version:
            dist.findings.append(
                Finding(
                    "IDENTITY-VERSION-MISMATCH",
                    "metadata",
                    "error",
                    f"Filename version {filename_version} does not match metadata version {meta.version}.",
                    field="Version",
                    standard="PEP 440",
                )
            )


def _rfc822_headers(data: bytes) -> dict[str, list[str]]:
    meta, _ = parse_core_metadata(data, source="WHEEL")
    return meta.raw


def require_python_distribution(dist: Distribution) -> None:
    if dist.format == "unsupported":
        raise UnsupportedError(f"unsupported archive: {dist.filename}")
    if dist.format == "ordinary_archive":
        raise UnsupportedError(f"{dist.filename} is not a Python distribution")
    if dist.format == "malformed":
        raise InvalidDistributionError(f"{dist.filename} is not a valid Python distribution")


def importable_roots(dist: Distribution) -> list[str]:
    """Return archive prefixes that contain importable files."""

    if dist.format != "wheel":
        root = dist.sdist_root
        return [root] if root else [""]
    prefixes = [""]
    for member in dist.archive.members:
        parts = PurePosixPath(member.name).parts
        if len(parts) >= 2 and parts[0].endswith(".data") and parts[1] in {"purelib", "platlib"}:
            prefixes.append(f"{parts[0]}/{parts[1]}")
    return prefixes
