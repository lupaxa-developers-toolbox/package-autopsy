"""Python and platform compatibility from tags, Requires-Python, and classifiers."""

from __future__ import annotations

import re
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import Finding

_PY_CLASSIFIER = re.compile(r"^Programming Language :: Python :: (\d+(?:\.\d+)?)$")


def analyse_compatibility(
    dist: Distribution,
    *,
    python_version: str | None = None,
    platform: str | None = None,
    implementation: str | None = None,
    abi: str | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    requires = dist.metadata.requires_python if dist.metadata else None
    classifiers = dist.metadata.classifiers if dist.metadata else []
    classifier_versions = []
    for item in classifiers:
        match = _PY_CLASSIFIER.match(item)
        if match:
            classifier_versions.append(match.group(1))
    tags = {
        "python": list(dist.wheel_name.python_tags) if dist.wheel_name else [],
        "abi": list(dist.wheel_name.abi_tags) if dist.wheel_name else [],
        "platform": list(dist.wheel_name.platform_tags) if dist.wheel_name else [],
    }
    wheel_tags = list(dist.wheel_file.get("tag", []))
    native = any(member.name.endswith((".so", ".pyd")) and not member.is_dir for member in dist.archive.members)
    status = "indeterminate"
    reasons: list[str] = []
    if python_version or platform or implementation or abi:
        status = "compatible"
        if requires and python_version:
            try:
                spec = SpecifierSet(requires)
                full = python_version if python_version.count(".") >= 2 else f"{python_version}.0"
                if Version(full) not in spec:
                    status = "incompatible"
                    reasons.append(f"Requires-Python {requires} excludes {python_version}")
            except (InvalidSpecifier, Exception):
                status = "indeterminate"
                reasons.append("Requires-Python could not be evaluated")
        if dist.wheel_name:
            if python_version and not _python_tag_matches(dist.wheel_name.python_tags, python_version, implementation):
                status = "incompatible"
                reasons.append("wheel Python tags do not match the requested interpreter")
            if platform and not _platform_matches(dist.wheel_name.platform_tags, platform):
                status = "incompatible"
                reasons.append("wheel platform tags do not match the requested platform")
            if abi and abi not in dist.wheel_name.abi_tags and "none" not in dist.wheel_name.abi_tags:
                status = "incompatible"
                reasons.append("wheel ABI tags do not match the requested ABI")
        elif dist.format == "sdist":
            reasons.append("source distributions are not tagged; compatibility is metadata-only")
            if status == "compatible" and not python_version:
                status = "indeterminate"
    findings.extend(_classifier_consistency(requires, classifier_versions, tags["python"]))
    payload = {
        "requires_python": requires,
        "classifiers": classifier_versions,
        "wheel_filename_tags": tags,
        "wheel_file_tags": wheel_tags,
        "native_extensions": native,
        "evaluation": {
            "python_version": python_version,
            "platform": platform,
            "implementation": implementation,
            "abi": abi,
            "status": status,
            "reasons": reasons,
            "note": (
                "Tag and metadata compatibility does not guarantee that the package will function correctly at runtime."
            ),
        },
    }
    return payload, findings


def _python_tag_matches(tags: list[str], python_version: str, implementation: str | None) -> bool:
    impl = (implementation or "cpython").lower()
    compact = python_version.replace(".", "")
    major = python_version.split(".", 1)[0]
    candidates = {"py3", f"py{major}", "py2.py3"}
    if impl in {"cpython", "cp"}:
        candidates.update({f"cp{major}", f"cp{compact[:2] if len(compact) >= 2 else compact}", f"cp{compact}"})
    if impl in {"pypy", "pp"}:
        candidates.update({f"pp{major}", f"pp{compact}"})
    return any(tag.lower() in candidates or tag.lower().startswith(tuple(candidates)) for tag in tags) or any(
        tag.lower() in {"py3", "py2.py3"} for tag in tags
    )


def _platform_matches(tags: list[str], platform: str) -> bool:
    platform = platform.lower()
    if "any" in {tag.lower() for tag in tags}:
        return True
    aliases = {
        "linux": ("linux", "manylinux", "musllinux"),
        "darwin": ("macosx", "darwin"),
        "macos": ("macosx", "darwin"),
        "win32": ("win", "win32", "win_amd64", "win_arm64"),
        "windows": ("win", "win32", "win_amd64", "win_arm64"),
    }
    prefixes = aliases.get(platform, (platform,))
    return any(any(tag.lower().startswith(prefix) for prefix in prefixes) for tag in tags)


def _classifier_consistency(
    requires: str | None,
    classifier_versions: list[str],
    python_tags: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    if requires and classifier_versions:
        try:
            spec = SpecifierSet(requires)
            for version in classifier_versions:
                full = version if version.count(".") >= 1 else version
                try:
                    parsed = Version(full if "." in full else f"{full}.0")
                except Exception:
                    continue
                if parsed not in spec and not any(full.startswith(str(parsed.major)) for _ in [0]):
                    findings.append(
                        Finding(
                            "COMPAT-CLASSIFIER-REQUIRES",
                            "compatibility",
                            "warning",
                            f"Classifier Python {version} is not obviously consistent with Requires-Python {requires}.",
                            field="Classifier",
                            confidence="heuristic",
                        )
                    )
        except InvalidSpecifier:
            pass
    if python_tags and "py2" in {tag.lower() for tag in python_tags} and requires and "3" in requires:
        findings.append(
            Finding(
                "COMPAT-TAG-REQUIRES",
                "compatibility",
                "warning",
                "Wheel Python tags include py2 while Requires-Python appears to target Python 3.",
                confidence="heuristic",
            )
        )
    return findings
