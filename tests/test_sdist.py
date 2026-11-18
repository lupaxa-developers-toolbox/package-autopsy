"""Source distribution inspection without executing setup.py."""

from __future__ import annotations

from pathlib import Path

from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.load import load_distribution
from lupaxa.package_autopsy.modules import discover_modules
from lupaxa.package_autopsy.validate import validate_distribution
from tests.conftest import build_sdist


def test_modern_sdist(sdist_path: Path, limits: Limits) -> None:
    dist = load_distribution(sdist_path, limits)
    try:
        assert dist.format == "sdist"
        assert dist.metadata is not None
        assert dist.build_backend == "hatchling.build"
        assert dist.has_setup_py is False
        modules = {item.import_path for item in discover_modules(dist)}
        assert "lupaxa.demo" in modules
    finally:
        dist.close()


def test_dynamic_metadata(tmp_path: Path, limits: Limits) -> None:
    path = build_sdist(tmp_path, dynamic=True)
    dist = load_distribution(path, limits)
    try:
        assert "version" in dist.dynamic_fields
        assert any(item.identifier == "SDIST-DYNAMIC-METADATA" for item in dist.findings)
    finally:
        dist.close()


def test_setup_py_is_not_executed(tmp_path: Path, limits: Limits) -> None:
    bomb = b"raise SystemExit('executed')\n"
    path = build_sdist(tmp_path, extra_files={"setup.py": bomb})
    dist = load_distribution(path, limits)
    try:
        assert dist.has_setup_py is True
        payload, _ = validate_distribution(dist)
        assert payload["status"] in {"passed", "failed"}
    finally:
        dist.close()
