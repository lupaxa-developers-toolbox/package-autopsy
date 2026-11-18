"""Identify native extensions and bundled binaries without executing them."""

from __future__ import annotations

import struct

from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import BinaryInfo, Finding

ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    0xFEEDFACE,
    0xFEEDFACF,
    0xCEFAEDFE,
    0xCFFAEDFE,
    0xCAFEBABE,
    0xBEBAFECA,
}
PE_MAGIC = b"MZ"


def inspect_binaries(dist: Distribution, limits: Limits) -> tuple[list[BinaryInfo], list[Finding]]:
    findings: list[Finding] = []
    results: list[BinaryInfo] = []
    for member in dist.archive.members:
        if member.is_dir or member.size == 0:
            continue
        if not _maybe_binary(member.name, member.size):
            continue
        cap = min(member.size, limits.max_scan_size, 1_048_576)
        try:
            data = dist.archive.read_capped(member.name, cap)
        except Exception:
            continue
        info = parse_binary(member.name, member.size, data)
        if info is None:
            continue
        results.append(info)
        if info.format in {"ELF", "Mach-O", "PE"}:
            findings.append(
                Finding(
                    "BINARY-PRESENT",
                    "binaries",
                    "informational",
                    f"{member.name} is a {info.format} {info.library_type}.",
                    path=member.name,
                    confidence=info.confidence,
                )
            )
    results.sort(key=lambda item: item.path)
    return results, findings


def _maybe_binary(name: str, size: int) -> bool:
    lowered = name.lower()
    if lowered.endswith((".py", ".pyi", ".txt", ".md", ".rst", ".toml", ".cfg", ".json", ".xml")):
        return False
    if lowered.endswith((".so", ".dylib", ".dll", ".pyd", ".exe", ".bin", ".o")):
        return True
    return size >= 16


def parse_binary(path: str, size: int, data: bytes) -> BinaryInfo | None:
    if data.startswith(ELF_MAGIC):
        return _parse_elf(path, size, data)
    if data.startswith(PE_MAGIC):
        return _parse_pe(path, size, data)
    if len(data) >= 4:
        magic = struct.unpack(">I", data[:4])[0]
        if magic in MACHO_MAGICS:
            return _parse_macho(path, size, data, magic)
    return None


def _parse_elf(path: str, size: int, data: bytes) -> BinaryInfo:
    ei_class = data[4] if len(data) > 4 else 0
    ei_data = data[5] if len(data) > 5 else 0
    endian = "<" if ei_data == 1 else ">"
    arch = {1: "32-bit", 2: "64-bit"}.get(ei_class, "unknown")
    machine = None
    libraries: list[str] = []
    notes: list[str] = []
    try:
        e_type = struct.unpack(endian + "H", data[16:18])[0] if len(data) >= 18 else 0
        e_machine = struct.unpack(endian + "H", data[18:20])[0] if len(data) >= 20 else 0
        machine = {
            3: "x86",
            62: "x86_64",
            40: "arm",
            183: "aarch64",
            243: "riscv",
        }.get(e_machine, f"machine-{e_machine}")
        kind = {2: "executable", 3: "shared-object"}.get(e_type, "elf")
        libraries = _elf_needed(data, endian, ei_class)
    except struct.error:
        kind = "elf"
        notes.append("ELF header truncated")
    if path.endswith(".so") or ".so." in path or "cpython" in path:
        kind = "python-extension" if "cpython" in path or path.endswith(".pyd") else kind
    return BinaryInfo(
        path=path,
        format="ELF",
        architecture=f"{arch} {machine}".strip() if machine else arch,
        size=size,
        library_type=kind,
        libraries=libraries,
        notes=notes,
        confidence="certain" if machine else "heuristic",
    )


def _elf_needed(data: bytes, endian: str, ei_class: int) -> list[str]:
    """Best-effort DT_NEEDED names from a bounded slice. Never maps the file."""

    names: list[str] = []
    # Heuristic: look for lib*.so ASCII strings after the header.
    text = data[64 : min(len(data), 64_000)]
    for match in _extract_ascii(text, prefix=b"lib"):
        if b".so" in match:
            names.append(match.decode("ascii", errors="ignore"))
    return sorted(set(names))[:32]


def _parse_macho(path: str, size: int, data: bytes, magic: int) -> BinaryInfo:
    swap = magic in {0xCEFAEDFE, 0xCFFAEDFE, 0xBEBAFECA}
    fmt = "<I" if swap else ">I"
    cpu = None
    kind = "mach-o"
    notes: list[str] = []
    libraries: list[str] = []
    try:
        if magic in {0xCAFEBABE, 0xBEBAFECA}:
            kind = "mach-o-fat"
            notes.append("fat/universal binary")
        else:
            cpu_type = struct.unpack(fmt, data[4:8])[0]
            cpu = {
                7: "x86",
                0x01000007: "x86_64",
                12: "arm",
                0x0100000C: "arm64",
            }.get(cpu_type, f"cpu-{cpu_type}")
        libraries = [
            item.decode("ascii", errors="ignore")
            for item in _extract_ascii(data[32 : min(len(data), 64_000)], prefix=b"/usr/lib/")
        ][:16]
    except struct.error:
        notes.append("Mach-O header truncated")
    if path.endswith(".so") or path.endswith(".dylib") or "cpython" in path:
        kind = "python-extension" if "cpython" in path else "shared-library"
    return BinaryInfo(
        path=path,
        format="Mach-O",
        architecture=cpu,
        size=size,
        library_type=kind,
        libraries=libraries,
        notes=notes,
        confidence="certain",
    )


def _parse_pe(path: str, size: int, data: bytes) -> BinaryInfo | None:
    if len(data) < 64:
        return None
    e_lfanew = struct.unpack_from("<I", data, 60)[0]
    if e_lfanew + 6 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        # DOS stub without a PE header in the scanned window.
        if path.lower().endswith((".exe", ".dll", ".pyd")):
            return BinaryInfo(
                path=path,
                format="PE",
                architecture=None,
                size=size,
                library_type="pe",
                libraries=[],
                notes=["PE header not in scanned window"],
                confidence="heuristic",
            )
        return None
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    arch = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C0: "arm"}.get(machine, f"machine-{machine}")
    kind = "python-extension" if path.lower().endswith(".pyd") else "pe"
    if path.lower().endswith(".dll"):
        kind = "shared-library"
    if path.lower().endswith(".exe"):
        kind = "executable"
    libraries = [
        item.decode("ascii", errors="ignore")
        for item in _extract_ascii(data[e_lfanew : min(len(data), e_lfanew + 32_000)], suffix=b".dll")
    ][:16]
    return BinaryInfo(
        path=path,
        format="PE",
        architecture=arch,
        size=size,
        library_type=kind,
        libraries=libraries,
        notes=[],
        confidence="certain",
    )


def _extract_ascii(data: bytes, *, prefix: bytes | None = None, suffix: bytes | None = None) -> list[bytes]:
    found: list[bytes] = []
    start = None
    for index, byte in enumerate(data):
        if 32 <= byte < 127:
            if start is None:
                start = index
        else:
            if start is not None and index - start >= 4:
                chunk = data[start:index]
                if (prefix is None or chunk.startswith(prefix)) and (suffix is None or chunk.endswith(suffix)):
                    found.append(chunk)
            start = None
    return found
