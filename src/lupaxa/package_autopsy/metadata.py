"""Core Metadata, wheel, and source-distribution metadata parsing."""

from __future__ import annotations

import ast
import configparser
import re
from email.parser import BytesParser
from email.policy import EmailPolicy
from pathlib import PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import (
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from lupaxa.package_autopsy.archive import SafeArchive
from lupaxa.package_autopsy.models import CoreMetadata, Finding, WheelFilename
from lupaxa.package_autopsy.safety import normalise_member_name, sanitize_text

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

SINGLETON_FIELDS = frozenset(
    {
        "metadata-version",
        "name",
        "version",
        "summary",
        "description",
        "description-content-type",
        "home-page",
        "author",
        "author-email",
        "maintainer",
        "maintainer-email",
        "license",
        "license-expression",
        "keywords",
        "requires-python",
        "download-url",
    }
)

_WHEEL_NAME_RE = re.compile(
    r"^(?P<name>[\w.]+)-(?P<ver>[^-]+)"
    r"(?:-(?P<build>\d[\w.]*))?-"
    r"(?P<py>[\w.]+)-(?P<abi>[\w.]+)-(?P<plat>[\w.]+)\.whl$",
    re.IGNORECASE,
)


def parse_core_metadata(data: bytes, *, source: str) -> tuple[CoreMetadata, list[Finding]]:
    findings: list[Finding] = []
    try:
        message = BytesParser(policy=EmailPolicy(utf8=True)).parsebytes(data)
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                "METADATA-PARSE-ERROR",
                "metadata",
                "error",
                f"Metadata could not be parsed as Core Metadata: {exc}",
                path=source,
                standard="PyPA Core Metadata",
            )
        )
        return CoreMetadata(source=source), findings
    raw: dict[str, list[str]] = {}
    for key, value in message.items():
        lowered = key.lower()
        raw.setdefault(lowered, []).append(str(value))
        if lowered in SINGLETON_FIELDS and len(raw[lowered]) > 1:
            findings.append(
                Finding(
                    "METADATA-DUPLICATE-FIELD",
                    "metadata",
                    "error",
                    f"Singleton field {key} appears more than once.",
                    field=key,
                    path=source,
                    standard="PyPA Core Metadata",
                )
            )
    body = message.get_payload()
    description = body if isinstance(body, str) and body.strip() else _first(raw, "description")
    keywords_raw = _first(raw, "keywords")
    keywords = []
    if keywords_raw:
        keywords = [part.strip() for part in re.split(r"[,\s]+", keywords_raw) if part.strip()]
    meta = CoreMetadata(
        raw=raw,
        name=_first(raw, "name"),
        version=_first(raw, "version"),
        summary=_first(raw, "summary"),
        description=description,
        description_content_type=_first(raw, "description-content-type"),
        author=_first(raw, "author"),
        author_email=_first(raw, "author-email"),
        maintainer=_first(raw, "maintainer"),
        maintainer_email=_first(raw, "maintainer-email"),
        home_page=_first(raw, "home-page"),
        project_urls=list(raw.get("project-url", [])),
        keywords=keywords,
        classifiers=list(raw.get("classifier", [])),
        license=_first(raw, "license"),
        license_expression=_first(raw, "license-expression"),
        license_files=list(raw.get("license-file", [])),
        requires_python=_first(raw, "requires-python"),
        requires_dist=list(raw.get("requires-dist", [])),
        provides_extra=list(raw.get("provides-extra", [])),
        dynamic=list(raw.get("dynamic", [])),
        metadata_version=_first(raw, "metadata-version"),
        source=source,
    )
    return meta, findings


def _first(raw: dict[str, list[str]], key: str) -> str | None:
    values = raw.get(key)
    if not values:
        return None
    return sanitize_text(values[0])


def parse_wheel_name(filename: str) -> tuple[WheelFilename | None, list[Finding]]:
    findings: list[Finding] = []
    try:
        name, version, build, tags = parse_wheel_filename(filename)
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                "WHEEL-FILENAME-INVALID",
                "wheel",
                "error",
                f"Wheel filename is not valid: {exc}",
                path=filename,
                standard="PEP 427",
            )
        )
        return None, findings
    python_tags = sorted({tag.interpreter for tag in tags})
    abi_tags = sorted({tag.abi for tag in tags})
    platform_tags = sorted({tag.platform for tag in tags})
    build_tag = None
    if build is not None:
        build_tag = "".join(str(part) for part in build) if not isinstance(build, str) else build
    parsed = WheelFilename(
        distribution=str(name),
        version=str(version),
        build=build_tag,
        python_tags=python_tags,
        abi_tags=abi_tags,
        platform_tags=platform_tags,
        raw=filename,
    )
    if not _WHEEL_NAME_RE.match(filename):
        findings.append(
            Finding(
                "WHEEL-FILENAME-UNUSUAL",
                "wheel",
                "warning",
                "Wheel filename parsed but does not match the usual tag pattern.",
                path=filename,
                standard="PEP 427",
                confidence="heuristic",
            )
        )
    return parsed, findings


def parse_sdist_name(filename: str) -> tuple[tuple[str, str] | None, list[Finding]]:
    findings: list[Finding] = []
    try:
        name, version = parse_sdist_filename(filename)
        return (str(name), str(version)), findings
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                "SDIST-FILENAME-INVALID",
                "sdist",
                "warning",
                f"Source distribution filename is not standards-compliant: {exc}",
                path=filename,
                standard="PyPA source distribution",
                confidence="heuristic",
            )
        )
        return None, findings


def validate_identity(meta: CoreMetadata) -> list[Finding]:
    findings: list[Finding] = []
    if not meta.name:
        findings.append(
            Finding(
                "METADATA-NAME-MISSING",
                "metadata",
                "error",
                "Distribution name is missing.",
                field="Name",
                standard="PyPA Core Metadata",
                suggestion="Set a valid Name field.",
            )
        )
    else:
        try:
            canonicalize_name(meta.name)
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    "METADATA-NAME-INVALID",
                    "metadata",
                    "error",
                    f"Distribution name is invalid: {exc}",
                    field="Name",
                    standard="PEP 503",
                )
            )
    if not meta.version:
        findings.append(
            Finding(
                "METADATA-VERSION-MISSING",
                "metadata",
                "error",
                "Distribution version is missing.",
                field="Version",
                standard="PEP 440",
            )
        )
    else:
        try:
            Version(meta.version)
        except InvalidVersion as exc:
            findings.append(
                Finding(
                    "METADATA-VERSION-INVALID",
                    "metadata",
                    "error",
                    f"Version is not a PEP 440 identifier: {exc}",
                    field="Version",
                    standard="PEP 440",
                )
            )
    if meta.requires_python:
        try:
            SpecifierSet(meta.requires_python)
        except InvalidSpecifier as exc:
            findings.append(
                Finding(
                    "METADATA-REQUIRES-PYTHON-INVALID",
                    "metadata",
                    "error",
                    f"Requires-Python is not a valid specifier: {exc}",
                    field="Requires-Python",
                    standard="PEP 345",
                )
            )
    for extra in meta.provides_extra:
        try:
            canonicalize_name(extra)
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    "METADATA-EXTRA-INVALID",
                    "metadata",
                    "error",
                    f"Provides-Extra is invalid: {exc}",
                    field="Provides-Extra",
                    standard="PEP 685",
                )
            )
    if meta.metadata_version:
        try:
            major = int(meta.metadata_version.split(".", 1)[0])
        except ValueError:
            major = 0
            findings.append(
                Finding(
                    "METADATA-VERSION-FIELD-INVALID",
                    "metadata",
                    "error",
                    f"Metadata-Version {meta.metadata_version!r} is not numeric.",
                    field="Metadata-Version",
                )
            )
        if major > 2:
            findings.append(
                Finding(
                    "METADATA-VERSION-UNSUPPORTED",
                    "metadata",
                    "warning",
                    f"Metadata-Version {meta.metadata_version} is newer than this tool fully models.",
                    field="Metadata-Version",
                    confidence="incomplete",
                )
            )
    return findings


def parse_requirements(values: list[str]) -> tuple[list[Requirement], list[Finding]]:
    parsed: list[Requirement] = []
    findings: list[Finding] = []
    for raw in values:
        try:
            parsed.append(Requirement(raw))
        except InvalidRequirement as exc:
            findings.append(
                Finding(
                    "DEPENDENCY-INVALID",
                    "dependencies",
                    "error",
                    f"Invalid PEP 508 requirement {raw!r}: {exc}",
                    field="Requires-Dist",
                    standard="PEP 508",
                )
            )
    return parsed, findings


def find_dist_info(archive: SafeArchive) -> str | None:
    dirs = {
        PurePosixPath(member.name).parts[0]
        for member in archive.members
        if member.name.endswith(".dist-info")
        or "/.dist-info/" in f"/{member.name}/"
        or member.name.endswith(".dist-info/")
    }
    names = sorted(
        {member.name.split("/")[0] for member in archive.members if ".dist-info" in PurePosixPath(member.name).parts[0]}
    )
    if names:
        return names[0]
    if dirs:
        return sorted(dirs)[0]
    return None


def dist_info_file(archive: SafeArchive, filename: str) -> str | None:
    directory = find_dist_info(archive)
    if directory is None:
        return None
    candidate = f"{directory}/{filename}"
    names = set(archive.names())
    if candidate in names:
        return candidate
    for name in names:
        if name.endswith(f".dist-info/{filename}"):
            return name
    return None


def sdist_root(archive: SafeArchive) -> str:
    prefixes = []
    for member in archive.members:
        parts = PurePosixPath(member.name).parts
        if parts:
            prefixes.append(parts[0])
    if not prefixes:
        return ""
    first = prefixes[0]
    if all(item == first for item in prefixes):
        return first
    return ""


def locate_sdist_file(archive: SafeArchive, *relative: str) -> str | None:
    names = set(archive.names())
    root = sdist_root(archive)
    candidates = []
    for rel in relative:
        rel = normalise_member_name(rel)
        candidates.append(rel)
        if root:
            candidates.append(f"{root}/{rel}")
    for candidate in candidates:
        if candidate in names:
            return candidate
    lowered = {name.lower(): name for name in names}
    for candidate in candidates:
        hit = lowered.get(candidate.lower())
        if hit:
            return hit
    return None


def parse_pyproject(data: bytes) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        findings.append(
            Finding(
                "PYPROJECT-INVALID",
                "sdist",
                "error",
                f"pyproject.toml is not valid TOML: {exc}",
                path="pyproject.toml",
                standard="PEP 518",
            )
        )
        return {}, findings
    return parsed, findings


def build_backend_from_pyproject(data: dict[str, Any]) -> str | None:
    system = data.get("build-system")
    if isinstance(system, dict):
        backend = system.get("build-backend")
        if isinstance(backend, str):
            return backend
    return None


def dynamic_fields_from_pyproject(data: dict[str, Any]) -> list[str]:
    project = data.get("project")
    if isinstance(project, dict):
        dynamic = project.get("dynamic")
        if isinstance(dynamic, list):
            return [str(item) for item in dynamic]
    return []


def parse_setup_cfg(data: bytes) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    text = data.decode("utf-8", errors="replace")
    parser.read_string(text)
    return parser


def setup_py_present_only(data: bytes) -> bool:
    """Return True if setup.py parses as Python. Never execute it."""

    try:
        ast.parse(data.decode("utf-8", errors="replace"))
    except SyntaxError:
        return False
    return True
