"""Terminal, JSON, Markdown, HTML, and CSV reports."""

from __future__ import annotations

import csv
import json
from io import StringIO
from typing import Any

from lupaxa.package_autopsy.config import format_size
from lupaxa.package_autopsy.models import Finding
from lupaxa.package_autopsy.safety import html_escape, safe_display

SCHEMA_VERSION = "1.0"


def wrap_json(payload: dict[str, Any], *, findings: list[Finding] | None = None) -> dict[str, Any]:
    data = dict(payload)
    data.setdefault("schema_version", SCHEMA_VERSION)
    if findings is not None and "findings" not in data:
        data["findings"] = [item.as_dict() for item in findings]
    return data


def dumps_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n"


def dumps_jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(row, sort_keys=True, ensure_ascii=False, default=str) + "\n" for row in rows)


def render_inspect(data: dict[str, Any]) -> str:
    dist = data.get("distribution", {})
    summary = data.get("summary", {})
    lines = [
        "Package Autopsy",
        "",
        f"Distribution: {safe_display(str(dist.get('name') or 'unknown'))}",
        f"Version:      {dist.get('version') or 'unknown'}",
        f"Format:       {_format_label(dist.get('format'))}",
        f"Filename:     {dist.get('filename')}",
        "",
        f"Archive size:       {format_size(int(summary.get('archive_size') or 0))}",
        f"Uncompressed size:  {format_size(int(summary.get('uncompressed_size') or 0))}",
        f"Files:              {summary.get('file_count', 0)}",
        "",
        "Python requirement:",
        f"  {data.get('requires_python') or '(not declared)'}",
        "",
        "Dependencies:",
    ]
    deps = data.get("dependencies") or []
    if deps:
        lines.extend(f"  {item}" for item in deps)
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Entry points:")
    points = data.get("entry_points") or []
    if points:
        lines.extend(f"  {item}" for item in points)
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Python modules:")
    modules = data.get("modules") or []
    if modules:
        lines.extend(f"  {item}" for item in modules)
    else:
        lines.append("  (none)")
    lines.append("")
    native = data.get("native_extensions")
    lines.append(f"Native extensions: {'present' if native else 'None'}")
    lines.append("")
    validation = data.get("validation") or {}
    lines.append("Validation:")
    lines.append(f"  Errors:   {validation.get('errors', 0)}")
    lines.append(f"  Warnings: {validation.get('warnings', 0)}")
    warnings = data.get("warning_messages") or []
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  {item}" for item in warnings)
    return "\n".join(lines) + "\n"


def render_findings(findings: list[Finding], *, verbose: bool = False) -> str:
    if not findings:
        return "No findings.\n"
    lines = []
    for item in findings:
        location = item.path or item.field or ""
        prefix = f"[{item.severity}] {item.identifier}"
        if location:
            prefix += f" ({location})"
        lines.append(prefix)
        lines.append(f"  {safe_display(item.explanation)}")
        if verbose:
            if item.standard:
                lines.append(f"  standard: {item.standard}")
            if item.suggestion:
                lines.append(f"  suggestion: {item.suggestion}")
            if item.evidence:
                lines.append(f"  evidence: {item.evidence}")
            lines.append(f"  confidence: {item.confidence}")
    return "\n".join(lines) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    dist = report.get("distribution", {})
    lines = [
        "# Package Autopsy Report",
        "",
        f"- **Distribution:** {dist.get('name')}",
        f"- **Version:** {dist.get('version')}",
        f"- **Format:** {dist.get('format')}",
        f"- **Filename:** {dist.get('filename')}",
        "",
        "## Summary",
        "",
        f"- Files: {report.get('summary', {}).get('file_count')}",
        f"- Archive size: {report.get('summary', {}).get('archive_size')}",
        "",
        "## Findings",
        "",
    ]
    findings = report.get("findings") or []
    if not findings:
        lines.append("No findings.")
    for item in findings:
        ident = item.get("id") if isinstance(item, dict) else item
        explanation = item.get("explanation") if isinstance(item, dict) else ""
        lines.append(f"- `{ident}`: {explanation}")
    lines += [
        "",
        "## Inspection Limitations",
        "",
        "Package inspection is not equivalent to installing or executing a package.",
        "RECORD hashes prove consistency with this archive, not publisher identity.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    dist = report.get("distribution", {})
    findings = report.get("findings") or []
    rows = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        severity = html_escape(str(item.get("severity") or ""))
        ident = html_escape(str(item.get("id") or ""))
        path = html_escape(str(item.get("path") or item.get("field") or ""))
        explanation = html_escape(str(item.get("explanation") or ""))
        rows.append(
            f"<tr class='{severity}'><td>{severity}</td><td>{ident}</td><td>{path}</td><td>{explanation}</td></tr>"
        )
    table = "\n".join(rows) or "<tr><td colspan='4'>No findings.</td></tr>"
    name = html_escape(str(dist.get("name") or ""))
    version = html_escape(str(dist.get("version") or ""))
    filename = html_escape(str(dist.get("filename") or ""))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Package Autopsy — {name}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; color: #111; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
    tr.error {{ background: #fde8e8; }}
    tr.warning {{ background: #fff4d6; }}
    tr.informational {{ background: #eef6ff; }}
    input {{ margin-bottom: 1rem; width: 20rem; }}
  </style>
</head>
<body>
  <h1>Package Autopsy</h1>
  <p>{name} {version} — {filename}</p>
  <p>Offline report. Inspection is not installation or execution.</p>
  <input type="search" placeholder="Filter table" oninput="filter(this.value)"/>
  <table id="findings">
    <thead><tr><th>Severity</th><th>Id</th><th>Location</th><th>Explanation</th></tr></thead>
    <tbody>
      {table}
    </tbody>
  </table>
  <script>
    function filter(q) {{
      q = q.toLowerCase();
      document.querySelectorAll('#findings tbody tr').forEach(function (row) {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""


def render_csv(rows: list[dict[str, Any]], fieldnames: list[str]) -> str:
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key) for key in fieldnames})
    return buf.getvalue()


def _format_label(value: Any) -> str:
    mapping = {"wheel": "Wheel", "sdist": "Source distribution"}
    return mapping.get(str(value), str(value or "unknown"))
