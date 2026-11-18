"""Safe ZIP and TAR reading with resource limits."""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.errors import InvalidDistributionError, ResourceLimitError
from lupaxa.package_autopsy.models import ArchiveMember, Finding
from lupaxa.package_autopsy.safety import member_is_safe, normalise_member_name

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"


@dataclass
class SafeArchive:
    path: Path
    kind: str
    size: int
    members: list[ArchiveMember]
    findings: list[Finding] = field(default_factory=list)
    _zip: zipfile.ZipFile | None = None
    _tar: tarfile.TarFile | None = None
    _handle: BinaryIO | None = None
    _seen: int = 0
    _limits: Limits = field(default_factory=Limits)

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None
        if self._tar is not None:
            self._tar.close()
            self._tar = None
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> SafeArchive:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def member_map(self) -> dict[str, ArchiveMember]:
        return {item.name: item for item in self.members}

    def names(self) -> list[str]:
        return [item.name for item in self.members if not item.is_dir]

    def read(self, name: str, *, limit: int | None = None) -> bytes:
        name = normalise_member_name(name)
        member = self.member_map().get(name)
        if member is None:
            raise KeyError(name)
        max_bytes = limit if limit is not None else self._limits.max_member_size
        if member.size > max_bytes:
            raise ResourceLimitError(f"member {name} is {member.size} bytes; exceeds read limit {max_bytes}")
        if self._seen + member.size > self._limits.max_decompressed:
            raise ResourceLimitError("decompressed byte limit exceeded")
        data = self._read_raw(name, member.size)
        self._seen += len(data)
        if len(data) > max_bytes:
            raise ResourceLimitError(f"member {name} expanded beyond read limit")
        return data

    def read_capped(self, name: str, cap: int) -> bytes:
        name = normalise_member_name(name)
        member = self.member_map().get(name)
        if member is None:
            raise KeyError(name)
        remaining = self._limits.max_decompressed - self._seen
        take = min(member.size, cap, remaining if remaining > 0 else 0)
        if take <= 0:
            raise ResourceLimitError("decompressed byte limit exceeded")
        data = self._read_raw(name, take)
        self._seen += len(data)
        return data

    def iter_files(self) -> Iterator[ArchiveMember]:
        for member in self.members:
            if not member.is_dir:
                yield member

    def _read_raw(self, name: str, nbytes: int) -> bytes:
        if self._zip is not None:
            with self._zip.open(name) as handle:
                return handle.read(nbytes)
        if self._tar is not None:
            extracted = self._tar.extractfile(name)
            if extracted is None:
                return b""
            with extracted:
                return extracted.read(nbytes)
        raise InvalidDistributionError("archive is not open")


def sniff_magic(path: Path) -> str:
    with path.open("rb") as handle:
        header = handle.read(8)
    if header.startswith(ZIP_MAGIC):
        return "zip"
    if header.startswith(GZIP_MAGIC):
        return "gzip"
    if header.startswith(BZ2_MAGIC):
        return "bzip2"
    if header[257:262] == b"ustar":
        return "tar"
    return "unknown"


def open_archive(path: Path, limits: Limits) -> SafeArchive:
    size = path.stat().st_size
    limits.check_archive_size(size)
    magic = sniff_magic(path)
    suffix = path.name.lower()
    if magic == "zip" or suffix.endswith(".whl") or suffix.endswith(".zip"):
        return _open_zip(path, size, limits, magic)
    if magic in {"gzip", "bzip2", "tar"} or suffix.endswith((".tar.gz", ".tgz", ".tar")):
        return _open_tar(path, size, limits, magic)
    raise InvalidDistributionError(f"unrecognised archive format: {path.name}")


def _open_zip(path: Path, size: int, limits: Limits, magic: str) -> SafeArchive:
    findings: list[Finding] = []
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise InvalidDistributionError(f"malformed ZIP archive: {exc}") from exc
    if magic != "zip":
        findings.append(
            Finding(
                "ARCHIVE-MISLEADING-EXTENSION",
                "format",
                "warning",
                "Filename extension does not match the ZIP signature.",
                path=path.name,
                confidence="certain",
            )
        )
    infos = zf.infolist()
    if len(infos) > limits.max_members:
        zf.close()
        raise ResourceLimitError(f"archive has {len(infos)} members; limit is {limits.max_members}")
    members: list[ArchiveMember] = []
    seen: set[str] = set()
    for info in infos:
        name = normalise_member_name(info.filename)
        if not member_is_safe(info.filename):
            findings.append(
                Finding(
                    "ARCHIVE-UNSAFE-PATH",
                    "security",
                    "error",
                    "Archive member path is absolute or contains parent-directory segments.",
                    path=info.filename,
                    standard="archive safety",
                    suggestion="Rebuild the distribution without traversal paths.",
                )
            )
            continue
        if name in seen:
            findings.append(
                Finding(
                    "ARCHIVE-DUPLICATE-PATH",
                    "structure",
                    "error",
                    "Duplicate archive member path.",
                    path=name,
                )
            )
        seen.add(name)
        is_dir = info.is_dir() or name.endswith("/")
        if info.file_size > limits.max_member_size and not is_dir:
            zf.close()
            raise ResourceLimitError(f"member {name} is {info.file_size} bytes; exceeds member limit")
        members.append(
            ArchiveMember(
                name=name.rstrip("/"),
                size=0 if is_dir else info.file_size,
                compressed_size=info.compress_size,
                is_dir=is_dir,
                crc=info.CRC,
                mode=(info.external_attr >> 16) & 0xFFFF,
            )
        )
    members.sort(key=lambda item: item.name)
    return SafeArchive(
        path=path,
        kind="zip",
        size=size,
        members=members,
        findings=findings,
        _zip=zf,
        _limits=limits,
    )


def _open_tar(path: Path, size: int, limits: Limits, magic: str) -> SafeArchive:
    findings: list[Finding] = []
    try:
        tf = tarfile.open(path, mode="r:*")  # noqa: SIM115 — handle owned by SafeArchive
    except tarfile.TarError as exc:
        raise InvalidDistributionError(f"malformed TAR archive: {exc}") from exc
    members: list[ArchiveMember] = []
    seen: set[str] = set()
    count = 0
    try:
        while True:
            info = tf.next()
            if info is None:
                break
            count += 1
            if count > limits.max_members:
                tf.close()
                raise ResourceLimitError(f"archive has more than {limits.max_members} members")
            name = normalise_member_name(info.name)
            if not member_is_safe(info.name):
                findings.append(
                    Finding(
                        "ARCHIVE-UNSAFE-PATH",
                        "security",
                        "error",
                        "Archive member path is absolute or contains parent-directory segments.",
                        path=info.name,
                        standard="archive safety",
                    )
                )
                continue
            if info.issym() or info.islnk():
                findings.append(
                    Finding(
                        "ARCHIVE-SYMLINK",
                        "security",
                        "warning",
                        "Archive contains a symbolic or hard link; the link is not followed.",
                        path=name,
                    )
                )
            if name in seen:
                findings.append(
                    Finding(
                        "ARCHIVE-DUPLICATE-PATH",
                        "structure",
                        "error",
                        "Duplicate archive member path.",
                        path=name,
                    )
                )
            seen.add(name)
            file_size = int(info.size or 0)
            if file_size > limits.max_member_size and info.isfile():
                tf.close()
                raise ResourceLimitError(f"member {name} is {file_size} bytes; exceeds member limit")
            members.append(
                ArchiveMember(
                    name=name.rstrip("/"),
                    size=0 if info.isdir() else file_size,
                    compressed_size=None,
                    is_dir=info.isdir(),
                    mode=info.mode,
                    is_symlink=info.issym() or info.islnk(),
                    link_target=info.linkname or None,
                )
            )
    except tarfile.TarError as exc:
        tf.close()
        raise InvalidDistributionError(f"malformed TAR archive: {exc}") from exc
    members.sort(key=lambda item: item.name)
    return SafeArchive(
        path=path,
        kind="tar",
        size=size,
        members=members,
        findings=findings,
        _tar=tf,
        _limits=limits,
    )


def truncated_zip(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            handle.seek(0, io.SEEK_END)
            if handle.tell() < 22:
                return True
        with zipfile.ZipFile(path) as zf:
            zf.testzip()
    except (OSError, zipfile.BadZipFile):
        return True
    return False
