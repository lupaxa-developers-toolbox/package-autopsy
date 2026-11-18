"""Metadata, modules, entry points, dependencies, audit, and comparison."""

from __future__ import annotations

from pathlib import Path

from lupaxa.package_autopsy.audit import audit_distribution
from lupaxa.package_autopsy.config import Limits, Settings
from lupaxa.package_autopsy.dependencies import MarkerContext, analyse_dependencies
from lupaxa.package_autopsy.diff import compare_distributions, consistency_report
from lupaxa.package_autopsy.entrypoints import parse_entry_points, validate_entry_points
from lupaxa.package_autopsy.licences import validate_spdx
from lupaxa.package_autopsy.load import load_distribution
from lupaxa.package_autopsy.modules import discover_modules
from lupaxa.package_autopsy.safety import redact
from tests.conftest import build_sdist, build_wheel


def test_entry_points(loaded_wheel) -> None:
    points, _ = parse_entry_points(loaded_wheel)
    names = {item.name for item in points}
    assert "lupaxa-demo" in names
    modules = discover_modules(loaded_wheel, points)
    findings = validate_entry_points(loaded_wheel, points, modules)
    demo = next(item for item in points if item.name == "lupaxa-demo")
    assert demo.module_present is True
    assert demo.object_status == "static"
    assert not any(item.identifier == "ENTRYPOINT-MODULE-MISSING" for item in findings)


def test_missing_entry_point_module(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(
        tmp_path,
        files={},
    )
    # Default wheel already has lupaxa.demo.cli. Build one with a bad target via extra entry file.
    dist = load_distribution(path, limits)
    try:
        points, _ = parse_entry_points(dist)
        points[0].module = "does.not.exist"
        points[0].object = "main"
        findings = validate_entry_points(dist, points, discover_modules(dist, points))
        assert any(item.identifier == "ENTRYPOINT-MODULE-MISSING" for item in findings)
    finally:
        dist.close()


def test_environment_markers(loaded_wheel) -> None:
    deps, _ = analyse_dependencies(
        loaded_wheel,
        extras="all",
        context=MarkerContext(python_version="3.12", platform="linux"),
    )
    names = {item.normalised for item in deps}
    assert "platformdirs" in names
    assert "rich" in names
    extra = [item for item in deps if item.kind == "extra"]
    assert extra and extra[0].applicable is True


def test_spdx_and_redaction() -> None:
    assert validate_spdx("MIT")[0]
    assert validate_spdx("Apache-2.0 OR MIT")[0]
    assert not validate_spdx("MIT AND")[0]
    assert "***REDACTED***" in redact("token=ghp_abcdefghijklmnopqrstuvwxyz012345")


def test_audit_detects_env_and_redacts(tmp_path: Path, limits: Limits) -> None:
    path = build_wheel(
        tmp_path,
        files={".env": b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG\npassword=supersecret\n"},
    )
    dist = load_distribution(path, limits)
    try:
        payload, findings = audit_distribution(dist, Settings())
        ids = {item.identifier for item in findings}
        assert "AUDIT-ENV-FILE" in ids
        text = str(payload)
        assert "supersecret" not in text
        for item in findings:
            if item.evidence:
                assert "supersecret" not in item.evidence
    finally:
        dist.close()


def test_compare_and_consistency(tmp_path: Path, limits: Limits) -> None:
    left = build_wheel(tmp_path, version="1.2.0")
    right = build_wheel(
        tmp_path,
        version="1.3.0",
        files={"lupaxa/demo/cache.py": b"CACHE = 1\n"},
        metadata_extra="Requires-Dist: httpx>=0.27\n",
    )
    sdist = build_sdist(tmp_path)
    a = load_distribution(left, limits)
    b = load_distribution(right, limits)
    src = load_distribution(sdist, limits)
    try:
        payload, _ = compare_distributions(a, b)
        assert "lupaxa.demo.cache" in payload["modules"]["added"]
        consist, _ = consistency_report(src, [a])
        assert consist["wheels"]
    finally:
        a.close()
        b.close()
        src.close()
