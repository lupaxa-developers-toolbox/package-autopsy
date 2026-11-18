"""Wheel loading, validation, and RECORD verification."""

from __future__ import annotations

import zipfile
from pathlib import Path

from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.load import load_distribution
from lupaxa.package_autopsy.modules import discover_modules
from lupaxa.package_autopsy.validate import validate_distribution
from lupaxa.package_autopsy.verify import verify_distribution
from tests.conftest import build_wheel


def test_pure_python_wheel(loaded_wheel) -> None:
    assert loaded_wheel.format == "wheel"
    assert loaded_wheel.metadata is not None
    assert loaded_wheel.metadata.name == "lupaxa-demo"
    modules = {item.import_path for item in discover_modules(loaded_wheel)}
    assert "lupaxa.demo" in modules
    assert "lupaxa.demo.cli" in modules
    # Implicit namespace: lupaxa has no __init__.py
    assert "lupaxa" in modules


def test_missing_metadata(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(tmp_path, metadata=False, filename="broken-1.0.0-py3-none-any.whl")
    dist = load_distribution(path, limits)
    try:
        ids = {item.identifier for item in dist.findings}
        assert "WHEEL-METADATA-MISSING" in ids
    finally:
        dist.close()


def test_missing_wheel_file(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(tmp_path, wheel_file=False)
    dist = load_distribution(path, limits)
    try:
        assert any(item.identifier == "WHEEL-WHEEL-FILE-MISSING" for item in dist.findings)
    finally:
        dist.close()


def test_missing_record(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(tmp_path, record=False)
    dist = load_distribution(path, limits)
    try:
        payload, findings = verify_distribution(dist)
        assert payload["record"] == "failed"
        assert any(item.identifier == "RECORD-MISSING" for item in findings)
    finally:
        dist.close()


def test_invalid_record_hash(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(tmp_path)
    with zipfile.ZipFile(path, "a") as zf:
        # Overwrite a packaged file without updating RECORD.
        zf.writestr("lupaxa/demo/core.py", b"VALUE = 99\n")
    dist = load_distribution(path, limits)
    try:
        payload, findings = verify_distribution(dist)
        assert payload["status"] == "failed"
        assert any(item.identifier == "RECORD-HASH-MISMATCH" for item in findings)
    finally:
        dist.close()


def test_invalid_wheel_filename(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(tmp_path, filename="not-a-wheel.whl")
    dist = load_distribution(path, limits)
    try:
        assert any(item.identifier == "WHEEL-FILENAME-INVALID" for item in dist.findings)
    finally:
        dist.close()


def test_namespace_package_not_an_error(loaded_wheel) -> None:
    payload, findings = validate_distribution(loaded_wheel)
    assert not any("namespace" in item.identifier.lower() and item.severity == "error" for item in findings)
    modules = discover_modules(loaded_wheel)
    lupaxa = next(item for item in modules if item.import_path == "lupaxa")
    assert lupaxa.kind == "namespace"


def test_native_extension_wheel(tmp_path: Path, limits: Limits) -> None:
    elf = b"\x7fELF" + bytes(12) + b"\x03\x00>\x00" + b"\x00" * 40
    path = build_wheel(tmp_path, files={"lupaxa/demo/native.cpython-311-x86_64-linux-gnu.so": elf})
    dist = load_distribution(path, limits)
    try:
        modules = discover_modules(dist)
        assert any(item.native for item in modules)
    finally:
        dist.close()
