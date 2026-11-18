"""Synthetic wheel and sdist fixtures. No network."""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from lupaxa.package_autopsy.config import Limits
from lupaxa.package_autopsy.load import load_distribution


def _sha256_record(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"


def build_wheel(
    directory: Path,
    *,
    name: str = "lupaxa_demo",
    version: str = "1.2.0",
    files: dict[str, bytes] | None = None,
    metadata_extra: str = "",
    record: bool = True,
    wheel_file: bool = True,
    metadata: bool = True,
    filename: str | None = None,
) -> Path:
    dist_info = f"{name}-{version}.dist-info"
    payload: dict[str, bytes] = {
        "lupaxa/demo/__init__.py": b'"""demo package"""\n',
        "lupaxa/demo/cli.py": b"def main() -> None:\n    pass\n",
        "lupaxa/demo/core.py": b"VALUE = 1\n",
    }
    if files:
        payload.update(files)
    meta_text = (
        "Metadata-Version: 2.4\n"
        f"Name: {name.replace('_', '-')}\n"
        f"Version: {version}\n"
        "Summary: Demo distribution\n"
        "Requires-Python: >=3.11\n"
        "License-Expression: MIT\n"
        "Requires-Dist: platformdirs >=4.0\n"
        "Requires-Dist: rich >=13.0\n"
        "Provides-Extra: extra\n"
        'Requires-Dist: click>=8; extra == "extra"\n'
        f"{metadata_extra}"
    ).encode()
    wheel_text = b"Wheel-Version: 1.0\nGenerator: package-autopsy-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entry_points = b"[console_scripts]\nlupaxa-demo = lupaxa.demo.cli:main\n\n[demo]\nhook = lupaxa.demo.core:VALUE\n"
    members: dict[str, bytes] = dict(payload)
    if metadata:
        members[f"{dist_info}/METADATA"] = meta_text
    if wheel_file:
        members[f"{dist_info}/WHEEL"] = wheel_text
    members[f"{dist_info}/entry_points.txt"] = entry_points
    if record:
        rows = []
        for path, data in sorted(members.items()):
            rows.append(f"{path},{_sha256_record(data)},{len(data)}")
        rows.append(f"{dist_info}/RECORD,,")
        members[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode("utf-8")
    wheel_name = filename or f"{name}-{version}-py3-none-any.whl"
    target = directory / wheel_name
    with zipfile.ZipFile(target, "w") as zf:
        for path, data in members.items():
            zf.writestr(path, data)
    return target


def build_sdist(
    directory: Path,
    *,
    name: str = "lupaxa_demo",
    version: str = "1.2.0",
    extra_files: dict[str, bytes] | None = None,
    dynamic: bool = False,
) -> Path:
    root = f"{name}-{version}"
    pkg_info = (
        "Metadata-Version: 2.3\n"
        f"Name: {name.replace('_', '-')}\n"
        f"Version: {version}\n"
        "Summary: Demo distribution\n"
        "Requires-Python: >=3.11\n"
        "License-Expression: MIT\n"
        "Requires-Dist: platformdirs >=4.0\n"
    ).encode()
    pyproject = (
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
        "\n"
        "[project]\n"
        f'name = "{name.replace("_", "-")}"\n'
        + ('dynamic = ["version"]\n' if dynamic else f'version = "{version}"\n')
        + 'description = "Demo"\n'
        'requires-python = ">=3.11"\n'
        'license = "MIT"\n'
    ).encode("utf-8")
    members = {
        f"{root}/PKG-INFO": pkg_info,
        f"{root}/pyproject.toml": pyproject,
        f"{root}/lupaxa/demo/__init__.py": b'"""demo"""\n',
        f"{root}/lupaxa/demo/cli.py": b"def main() -> None:\n    pass\n",
        f"{root}/lupaxa/demo/core.py": b"VALUE = 1\n",
        f"{root}/tests/test_demo.py": b"def test_ok() -> None:\n    assert True\n",
        f"{root}/LICENCE": b"MIT\n",
    }
    if extra_files:
        members.update({f"{root}/{key}": value for key, value in extra_files.items()})
    target = directory / f"{name}-{version}.tar.gz"
    with tarfile.open(target, "w:gz") as tar:
        for path, data in members.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return target


@pytest.fixture
def wheel_path(tmp_path: Path) -> Path:
    return build_wheel(tmp_path)


@pytest.fixture
def sdist_path(tmp_path: Path) -> Path:
    return build_sdist(tmp_path)


@pytest.fixture
def limits() -> Limits:
    return Limits(
        max_archive_size=10 * 1024 * 1024,
        max_members=1000,
        max_decompressed=20 * 1024 * 1024,
        max_member_size=5 * 1024 * 1024,
        max_scan_size=1 * 1024 * 1024,
    )


@pytest.fixture
def loaded_wheel(wheel_path: Path, limits: Limits):
    dist = load_distribution(wheel_path, limits)
    yield dist
    dist.close()
