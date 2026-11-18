"""CI policy gate over inspection results."""

from __future__ import annotations

from typing import Any

from lupaxa.package_autopsy.audit import audit_distribution
from lupaxa.package_autopsy.binaries import inspect_binaries
from lupaxa.package_autopsy.config import Settings, parse_size
from lupaxa.package_autopsy.contents import annotate
from lupaxa.package_autopsy.dependencies import analyse_dependencies
from lupaxa.package_autopsy.diff import consistency_report
from lupaxa.package_autopsy.licences import analyse_licences
from lupaxa.package_autopsy.load import Distribution
from lupaxa.package_autopsy.models import Finding
from lupaxa.package_autopsy.validate import validate_distribution
from lupaxa.package_autopsy.verify import verify_distribution


def check_policy(
    dist: Distribution,
    settings: Settings,
    *,
    companions: list[Distribution] | None = None,
) -> tuple[dict[str, Any], list[Finding], str]:
    policy = settings.policy
    findings: list[Finding] = []
    incomplete = False

    annotate(dist)
    validate_payload, extra = validate_distribution(dist)
    findings.extend(extra)
    verify_payload, extra = verify_distribution(dist)
    findings.extend(extra)
    audit_payload, extra = audit_distribution(dist, settings)
    findings.extend(extra)
    licences, extra = analyse_licences(dist)
    findings.extend(extra)
    deps, extra = analyse_dependencies(dist)
    findings.extend(extra)
    binaries, extra = inspect_binaries(dist, settings.limits)
    findings.extend(extra)

    max_dist = policy.get("max_distribution_size")
    if max_dist:
        limit = parse_size(max_dist)
        if dist.archive_size > limit:
            findings.append(
                Finding(
                    "POLICY-MAX-SIZE",
                    "policy",
                    "error",
                    f"Distribution size {dist.archive_size} exceeds {limit}.",
                    path=dist.filename,
                )
            )
    max_file = policy.get("max_file_size") or (policy.get("files") or {}).get("max_file_size")
    if max_file:
        limit = parse_size(max_file)
        for member in dist.archive.members:
            if member.size > limit:
                findings.append(
                    Finding(
                        "POLICY-MAX-FILE-SIZE",
                        "policy",
                        "error",
                        f"{member.name} exceeds the maximum file size.",
                        path=member.name,
                    )
                )
    files_policy = policy.get("files") or {}
    for pattern in files_policy.get("deny", []):
        import fnmatch

        for member in dist.archive.members:
            if fnmatch.fnmatch(member.name, pattern):
                findings.append(
                    Finding(
                        "POLICY-DENIED-FILE",
                        "policy",
                        "error",
                        f"{member.name} matches denied pattern {pattern}.",
                        path=member.name,
                    )
                )
    if policy.get("require_licence") and not (
        licences.get("license_expression") or licences.get("legacy_license") or licences.get("bundled_files")
    ):
        findings.append(
            Finding(
                "POLICY-LICENCE-REQUIRED",
                "policy",
                "error",
                "Policy requires licence metadata or a licence file.",
            )
        )
    if policy.get("require_readme"):
        meta = dist.metadata
        if meta is None or not (meta.description or meta.summary):
            findings.append(
                Finding(
                    "POLICY-README-REQUIRED",
                    "policy",
                    "error",
                    "Policy requires README / description metadata.",
                    field="Description",
                )
            )
    urls_required = policy.get("require_project_urls")
    if urls_required:
        meta = dist.metadata
        if meta is None or not (meta.project_urls or meta.home_page):
            findings.append(
                Finding(
                    "POLICY-URLS-REQUIRED",
                    "policy",
                    "error",
                    "Policy requires project URLs.",
                    field="Project-URL",
                )
            )
    if policy.get("require_valid_record") and dist.format == "wheel" and verify_payload.get("record") != "passed":
        if verify_payload.get("record") == "incomplete":
            incomplete = True
        findings.append(
            Finding(
                "POLICY-RECORD-REQUIRED",
                "policy",
                "error",
                "Policy requires a valid RECORD.",
            )
        )
    dep_policy = policy.get("dependencies") or {}
    if dep_policy.get("allow_direct_urls") is False:
        for dep in deps:
            if dep.url:
                findings.append(
                    Finding(
                        "POLICY-DIRECT-URL",
                        "policy",
                        "error",
                        f"Direct URL dependency {dep.name} is not allowed.",
                    )
                )
    if (policy.get("disallow_secrets", True) is True or policy.get("disallow_secrets")) and any(
        item.category == "secrets" for item in findings
    ):
        findings.append(
            Finding(
                "POLICY-SECRETS",
                "policy",
                "error",
                "Policy forbids suspected secrets.",
            )
        )
    if (policy.get("no_native_binaries") or policy.get("no_unexpected_native_binaries")) and binaries:
        findings.append(
            Finding(
                "POLICY-NATIVE-BINARIES",
                "policy",
                "error",
                "Policy forbids bundled native binaries.",
            )
        )
    min_python = policy.get("min_python") or policy.get("minimum_supported_python")
    if min_python and dist.metadata and dist.metadata.requires_python:
        findings.append(
            Finding(
                "POLICY-PYTHON-DECLARED",
                "policy",
                "informational",
                f"Requires-Python is {dist.metadata.requires_python}; policy minimum is {min_python}.",
            )
        )
    if policy.get("wheel_sdist_consistency") and companions:
        sdist = next((item for item in companions if item.format == "sdist"), None)
        wheels = [item for item in companions if item.format == "wheel"]
        if sdist and wheels:
            _, extra = consistency_report(sdist, wheels)
            findings.extend(extra)
        else:
            incomplete = True
            findings.append(
                Finding(
                    "POLICY-CONSISTENCY-INCOMPLETE",
                    "policy",
                    "warning",
                    "Wheel/sdist consistency was required but both artefacts were not supplied.",
                    confidence="incomplete",
                )
            )

    fail_on = str(policy.get("fail_on", "error")).lower()
    rank = {"informational": 0, "warning": 1, "error": 2, "unknown": 1}
    threshold = rank.get(fail_on, 2)
    violations = [item for item in findings if rank.get(item.severity, 0) >= threshold and item.category == "policy"]
    if not violations:
        violations = [item for item in findings if rank.get(item.severity, 0) >= threshold]
    if incomplete:
        status = "incomplete"
        raise_status = "incomplete"
    elif violations:
        status = "failed"
        raise_status = "failed"
    else:
        status = "passed"
        raise_status = "passed"
    payload = {
        "status": status,
        "fail_on": fail_on,
        "violations": [item.as_dict() for item in violations],
        "validation": validate_payload,
        "audit": audit_payload,
    }
    return payload, findings, raise_status
