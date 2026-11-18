"""CLI smoke tests for every required command."""

from __future__ import annotations

from pathlib import Path

from lupaxa.package_autopsy.cli import COMMANDS, main
from tests.conftest import build_wheel


def test_every_command_has_help() -> None:
    for command in COMMANDS:
        assert main([command, "--help"]) == 0


def test_inspect_wheel(wheel_path: Path, capsys: object) -> None:
    assert main(["inspect", str(wheel_path)]) == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "Package Autopsy" in out
    assert "lupaxa-demo" in out
    assert "1.2.0" in out


def test_inspect_json(wheel_path: Path, capsys: object) -> None:
    assert main(["--json", "inspect", str(wheel_path)]) == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert '"schema_version"' in out
    assert '"wheel"' in out


def test_commands_cover_required_verbs(wheel_path: Path, sdist_path: Path, tmp_path: Path) -> None:
    other = build_wheel(tmp_path, version="1.3.0", files={"lupaxa/demo/cache.py": b"X = 1\n"})
    pairs = [
        (["contents", str(wheel_path)], 0),
        (["contents", str(wheel_path), "--tree"], 0),
        (["modules", str(wheel_path)], 0),
        (["modules", str(wheel_path), "--tree"], 0),
        (["commands", str(wheel_path)], 0),
        (["dependencies", str(wheel_path)], 0),
        (["compatibility", str(wheel_path), "--python-version", "3.12"], 0),
        (["metadata", str(wheel_path)], 0),
        (["licences", str(wheel_path)], 0),
        (["binaries", str(wheel_path)], 0),
        (["validate", str(wheel_path)], 0),
        (["verify", str(wheel_path)], 0),
        (["audit", str(wheel_path)], 0),
        (["graph", str(wheel_path)], 0),
        (["graph", str(wheel_path), "--format", "mermaid"], 0),
        (["report", str(wheel_path), "--format", "markdown"], 0),
        (["check", str(wheel_path)], 0),
        (["formats"], 0),
        (["compare", str(wheel_path), str(other)], 0),
        (["consistency", str(sdist_path), str(wheel_path)], 0),
        (["inspect", str(sdist_path)], 0),
        (["validate", str(sdist_path)], 0),
    ]
    for argv, expected in pairs:
        assert main(argv) == expected, argv


def test_missing_command_is_usage() -> None:
    assert main([]) == 2
