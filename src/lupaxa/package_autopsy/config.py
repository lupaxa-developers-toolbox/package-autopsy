"""TOML configuration, resource limits, and CLI precedence."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from lupaxa.package_autopsy.errors import ResourceLimitError, UsageError

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


_SIZE_RE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)?\s*$",
    re.IGNORECASE,
)
_SIZE_UNITS = {
    "B": 1,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KIB": 1024,
    "MIB": 1024**2,
    "GIB": 1024**3,
    "TIB": 1024**4,
}

KNOWN_ROOT_KEYS = frozenset(
    {
        "general",
        "limits",
        "policy",
        "audit",
        "report",
        "logging",
        "suppress",
    }
)


def parse_size(value: str | int) -> int:
    if isinstance(value, int):
        return value
    match = _SIZE_RE.match(str(value))
    if not match:
        raise UsageError(f"invalid size value: {value!r}")
    number = float(match.group(1))
    unit = (match.group(2) or "B").upper()
    return int(number * _SIZE_UNITS[unit])


def format_size(n: int) -> str:
    if n < 0:
        return str(n)
    units = (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024), ("B", 1))
    for label, size in units:
        if n >= size or size == 1:
            if size == 1:
                return f"{n} B"
            value = n / size
            text = f"{value:.1f}".rstrip("0").rstrip(".")
            return f"{text} {label}"
    return f"{n} B"


@dataclass
class Limits:
    max_archive_size: int = 2 * 1024**3
    max_members: int = 100_000
    max_decompressed: int = 4 * 1024**3
    max_member_size: int = 1 * 1024**3
    max_scan_size: int = 10 * 1024**2
    max_temp_storage: int = 2 * 1024**3
    max_nested_depth: int = 0
    timeout: float | None = None
    workers: int = 1
    hash_algorithms: tuple[str, ...] = ("sha256",)

    def check_archive_size(self, size: int) -> None:
        if size > self.max_archive_size:
            raise ResourceLimitError(
                f"archive size {format_size(size)} exceeds limit {format_size(self.max_archive_size)}"
            )


@dataclass
class Settings:
    colour: bool = True
    default_format: str = "text"
    limits: Limits = field(default_factory=Limits)
    allowed_formats: tuple[str, ...] = ("wheel", "sdist")
    policy: dict[str, Any] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)
    suppress: list[dict[str, Any]] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)
    temp_dir: str | None = None
    user_config_path: Path | None = None
    explicit_config_path: Path | None = None
    unknown_keys: list[str] = field(default_factory=list)


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise UsageError(f"{where} must be a table")
    return value


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_bytes().decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UsageError(f"configuration is not valid UTF-8: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise UsageError(f"invalid TOML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"configuration root must be a table: {path}")
    return data


def _user_config_path() -> Path | None:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidate = Path(xdg) / "package-autopsy" / "package-autopsy.toml"
    else:
        candidate = Path.home() / ".config" / "package-autopsy" / "package-autopsy.toml"
    return candidate if candidate.is_file() else None


def _apply_table(settings: Settings, data: dict[str, Any], *, strict: bool) -> Settings:
    unknown: list[str] = list(settings.unknown_keys)
    for key in data:
        if key not in KNOWN_ROOT_KEYS:
            unknown.append(key)
            if strict:
                raise UsageError(f"unknown configuration key: {key}")
    general = _mapping(data.get("general"), "general")
    limits_table = _mapping(data.get("limits"), "limits")
    colour = settings.colour
    if "colour" in general:
        colour = bool(general["colour"])
    elif "color" in general:
        colour = bool(general["color"])
    default_format = str(general.get("default_format", settings.default_format))
    allowed = general.get("allowed_formats")
    allowed_formats = tuple(str(item) for item in allowed) if allowed else settings.allowed_formats
    temp_dir = general.get("temp_dir", settings.temp_dir)
    limits = settings.limits
    mapping = {
        "max_archive_size": "max_archive_size",
        "max_members": "max_members",
        "max_decompressed_bytes": "max_decompressed",
        "max_member_size": "max_member_size",
        "max_content_scan_size": "max_scan_size",
        "max_temporary_storage": "max_temp_storage",
        "max_nested_archive_depth": "max_nested_depth",
        "timeout": "timeout",
        "workers": "workers",
    }
    updates: dict[str, Any] = {}
    for src, dest in mapping.items():
        if src in limits_table:
            raw = limits_table[src]
            if dest in {
                "max_archive_size",
                "max_decompressed",
                "max_member_size",
                "max_scan_size",
                "max_temp_storage",
            }:
                updates[dest] = parse_size(raw)
            else:
                updates[dest] = raw
    hashes = limits_table.get("hash_algorithms")
    if hashes:
        updates["hash_algorithms"] = tuple(str(item) for item in hashes)
    limits = replace(limits, **updates)
    suppress = data.get("suppress", settings.suppress)
    if isinstance(suppress, dict):
        suppress = [suppress]
    return Settings(
        colour=colour,
        default_format=default_format,
        limits=limits,
        allowed_formats=allowed_formats,
        policy=_mapping(data.get("policy"), "policy") or dict(settings.policy),
        audit=_mapping(data.get("audit"), "audit") or dict(settings.audit),
        suppress=list(suppress) if suppress else list(settings.suppress),
        report=_mapping(data.get("report"), "report") or dict(settings.report),
        temp_dir=str(temp_dir) if temp_dir else None,
        user_config_path=settings.user_config_path,
        explicit_config_path=settings.explicit_config_path,
        unknown_keys=unknown,
    )


def load_settings(
    *,
    config_path: Path | None = None,
    strict: bool = False,
) -> Settings:
    settings = Settings()
    user = _user_config_path()
    if user is not None:
        settings = _apply_table(settings, _load_toml(user), strict=strict)
        settings.user_config_path = user
    if config_path is not None:
        if not config_path.is_file():
            raise UsageError(f"configuration file not found: {config_path}")
        settings = _apply_table(settings, _load_toml(config_path), strict=strict)
        settings.explicit_config_path = config_path
    return settings
