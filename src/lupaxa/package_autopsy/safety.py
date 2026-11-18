"""Output sanitisation, secret redaction, and path safety."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MAX_FIELD = 8_192
REDACTED = "***REDACTED***"

_SECRET_VALUE_RES = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+"),
)


def sanitize_text(value: str, *, max_length: int = MAX_FIELD) -> str:
    text = ANSI_RE.sub("", value)
    text = CONTROL_RE.sub("", text)
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else "\ufffd" for ch in text)
    if len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


def redact(value: str) -> str:
    text = value
    for pattern in _SECRET_VALUE_RES:
        text = pattern.sub(REDACTED, text)
    return text


def safe_display(value: str, *, max_length: int = MAX_FIELD) -> str:
    return sanitize_text(redact(value), max_length=max_length)


def html_escape(value: str) -> str:
    return sanitize_text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def normalise_member_name(name: str) -> str:
    path = name.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def member_is_safe(name: str) -> bool:
    path = normalise_member_name(name)
    if not path or path == ".":
        return True
    if path.startswith("/") or path.startswith("\\"):
        return False
    if re.match(r"^[A-Za-z]:/", path):
        return False
    posix = PurePosixPath(path)
    return ".." not in posix.parts
