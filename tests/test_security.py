"""Archive safety, resource limits, and output sanitisation."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from lupaxa.package_autopsy.cli import main
from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.errors import InvalidDistributionError, ResourceLimitError
from lupaxa.package_autopsy.load import load_distribution
from lupaxa.package_autopsy.safety import html_escape, sanitize_text


def test_path_traversal_zip(tmp_path: Path, limits: Limits) -> None:
    path = tmp_path / "evil-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("ok-1.0.0.dist-info/METADATA", b"Metadata-Version: 2.1\nName: ok\nVersion: 1.0.0\n")
        zf.writestr("../evil.py", b"print('nope')\n")
    dist = load_distribution(path, limits)
    try:
        names = set(dist.names())
        assert "../evil.py" not in names
        assert any(item.identifier == "ARCHIVE-UNSAFE-PATH" for item in dist.findings)
    finally:
        dist.close()


def test_member_limit(tmp_path: Path) -> None:
    path = tmp_path / "bomb-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as zf:
        for index in range(20):
            zf.writestr(f"f{index}.txt", b"x")
    tiny = Limits(max_members=5, max_archive_size=10_000_000, max_decompressed=10_000_000)
    with pytest.raises(ResourceLimitError):
        load_distribution(path, tiny)


def test_html_and_ansi_injection() -> None:
    text = sanitize_text("ok\x1b[31mRED\x07")
    assert "\x1b" not in text
    escaped = html_escape("<script>alert(1)</script>")
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped


def test_malformed_tar(tmp_path: Path, limits: Limits) -> None:
    path = tmp_path / "broken.tar.gz"
    path.write_bytes(b"\x1f\x8bnot-gzip-payload")
    with pytest.raises(InvalidDistributionError):
        load_distribution(path, limits)


def test_ordinary_zip_is_not_a_distribution(tmp_path: Path) -> None:
    path = tmp_path / "notes.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", b"hello")
    assert main(["inspect", str(path)]) == 6
