"""Command-line interface for Package Autopsy.

Every path returns an int. Usage errors raise :class:`UsageExit` instead of
calling ``sys.exit`` from argparse.
"""

from __future__ import annotations

import argparse
import glob
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, NoReturn

from lupaxa.package_autopsy import __version__
from lupaxa.package_autopsy.audit import audit_distribution
from lupaxa.package_autopsy.binaries import inspect_binaries
from lupaxa.package_autopsy.colour import colour_enabled, make_console
from lupaxa.package_autopsy.compatibility import analyse_compatibility
from lupaxa.package_autopsy.config import Limits, Settings, format_size, load_settings, parse_size
from lupaxa.package_autopsy.contents import (
    filtered_members,
    member_as_dict,
    size_report,
    sort_members,
    tree_lines,
)
from lupaxa.package_autopsy.dependencies import (
    MarkerContext,
    analyse_dependencies,
    dependencies_payload,
)
from lupaxa.package_autopsy.diff import compare_distributions, consistency_report
from lupaxa.package_autopsy.entrypoints import (
    bundled_scripts,
    parse_entry_points,
    validate_entry_points,
)
from lupaxa.package_autopsy.errors import (
    EXIT_GENERAL,
    EXIT_INCOMPLETE,
    EXIT_INTEGRITY,
    EXIT_INVALID,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_POLICY,
    EXIT_RESOURCE,
    EXIT_UNSUPPORTED,
    EXIT_USAGE,
    IncompleteError,
    IntegrityError,
    InvalidDistributionError,
    PackageAutopsyError,
    PolicyError,
    ResourceLimitError,
    UnsupportedError,
    UsageError,
    UsageExit,
)
from lupaxa.package_autopsy.graph import dependency_graph, render_dot, render_mermaid, render_tree
from lupaxa.package_autopsy.licences import analyse_licences
from lupaxa.package_autopsy.load import Distribution, load_distribution, require_python_distribution
from lupaxa.package_autopsy.models import Finding
from lupaxa.package_autopsy.modules import discover_modules, module_tree
from lupaxa.package_autopsy.pipeline import full_report, inspect_payload
from lupaxa.package_autopsy.policy import check_policy
from lupaxa.package_autopsy.reports import (
    dumps_json,
    dumps_jsonl,
    render_csv,
    render_findings,
    render_html,
    render_inspect,
    render_markdown,
    wrap_json,
)
from lupaxa.package_autopsy.safety import safe_display
from lupaxa.package_autopsy.validate import validate_distribution
from lupaxa.package_autopsy.verify import verify_distribution

COMMANDS = (
    "inspect",
    "contents",
    "modules",
    "commands",
    "dependencies",
    "compatibility",
    "metadata",
    "licences",
    "binaries",
    "validate",
    "verify",
    "compare",
    "consistency",
    "audit",
    "graph",
    "report",
    "check",
    "formats",
    "version",
)

SINGLE_INPUT = {
    "inspect",
    "contents",
    "modules",
    "commands",
    "dependencies",
    "compatibility",
    "metadata",
    "licences",
    "binaries",
    "validate",
    "verify",
    "audit",
    "graph",
    "report",
    "check",
}


class AutopsyParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self._print_message(f"error: {message}\n", sys.stderr)
        raise UsageExit(EXIT_USAGE)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            self._print_message(message, sys.stderr)
        raise UsageExit(0 if status is None else int(status))


def _add_runtime_options(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    default: object = argparse.SUPPRESS if suppress else None
    flag_default: object = argparse.SUPPRESS if suppress else False
    include_default: object = argparse.SUPPRESS if suppress else []
    parser.add_argument("--config", type=Path, default=default, help="TOML configuration file.")
    parser.add_argument(
        "--no-colour",
        "--no-color",
        action="store_true",
        default=flag_default,
        help="Disable ANSI colour.",
    )
    parser.add_argument("--verbose", action="store_true", default=flag_default)
    parser.add_argument("--quiet", action="store_true", default=flag_default)
    parser.add_argument("--json", action="store_true", default=flag_default, help="Shortcut for --format json.")
    parser.add_argument("--format", dest="output_format", default=default)
    parser.add_argument("--output", type=Path, default=default)
    parser.add_argument("--strict", action="store_true", default=flag_default)
    parser.add_argument("--include", action="append", default=include_default)
    parser.add_argument("--exclude", action="append", default=include_default)
    parser.add_argument("--severity", default=default)
    parser.add_argument("--fail-on", default=default)
    parser.add_argument("--recursive", action="store_true", default=flag_default)
    parser.add_argument("--max-size", default=default)
    parser.add_argument("--timeout", type=float, default=default)
    parser.add_argument("--python-version", default=default)
    parser.add_argument("--platform", default=default)
    parser.add_argument("--implementation", default=default)
    parser.add_argument("--abi", default=default)
    parser.add_argument("--workers", type=int, default=default)


def build_parser() -> argparse.ArgumentParser:
    parser = AutopsyParser(
        prog="package-autopsy",
        description=(
            "Inspect, validate, compare, and audit Python wheels and source distributions without installing them."
        ),
    )
    parser.add_argument("--version", action="store_true", help="Show version information and exit.")
    _add_runtime_options(parser)
    common = AutopsyParser(add_help=False)
    _add_runtime_options(common, suppress=True)
    sub = parser.add_subparsers(dest="command", parser_class=AutopsyParser)

    def add_paths(cmd: argparse.ArgumentParser, *, nargs: str = "+") -> None:
        cmd.add_argument("paths", nargs=nargs, help="Distribution files, directories, or globs.")

    inspect = sub.add_parser("inspect", parents=[common], help="Display a distribution overview.")
    add_paths(inspect)
    contents = sub.add_parser("contents", parents=[common], help="List packaged files and directories.")
    add_paths(contents)
    contents.add_argument("--tree", action="store_true")
    contents.add_argument("--sort", choices=("name", "size", "type"), default="name")
    contents.add_argument("--regex")
    modules_cmd = sub.add_parser("modules", parents=[common], help="Identify Python packages and modules.")
    add_paths(modules_cmd)
    modules_cmd.add_argument("--tree", action="store_true")
    commands = sub.add_parser("commands", parents=[common], help="Identify installed entry points.")
    add_paths(commands)
    deps = sub.add_parser("dependencies", parents=[common], help="Analyse declared dependencies.")
    add_paths(deps)
    deps.add_argument("--extras", default="")
    compat = sub.add_parser("compatibility", parents=[common], help="Analyse Python and platform compatibility.")
    add_paths(compat)
    metadata = sub.add_parser("metadata", parents=[common], help="Display distribution metadata.")
    add_paths(metadata)
    licences = sub.add_parser("licences", parents=[common], help="Inspect licence declarations and files.")
    add_paths(licences)
    binaries = sub.add_parser("binaries", parents=[common], help="Identify compiled extensions and bundled binaries.")
    add_paths(binaries)
    validate = sub.add_parser("validate", parents=[common], help="Validate distribution structure and metadata.")
    add_paths(validate)
    verify = sub.add_parser("verify", parents=[common], help="Verify archive and recorded file integrity.")
    add_paths(verify)
    compare = sub.add_parser("compare", parents=[common], help="Compare two distributions.")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--context", type=int, default=3)
    compare.add_argument("--ignore-whitespace", action="store_true")
    consistency = sub.add_parser("consistency", parents=[common], help="Compare wheel and sdist contents.")
    add_paths(consistency)
    audit = sub.add_parser("audit", parents=[common], help="Detect packaging issues and unexpected files.")
    add_paths(audit)
    graph = sub.add_parser("graph", parents=[common], help="Display declared dependency relationships.")
    add_paths(graph)
    report = sub.add_parser("report", parents=[common], help="Generate detailed reports.")
    add_paths(report)
    check = sub.add_parser("check", parents=[common], help="Enforce configurable packaging policies.")
    add_paths(check)
    sub.add_parser("formats", parents=[common], help="Display supported formats and capabilities.")
    sub.add_parser("version", parents=[common], help="Display application version.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageExit as exc:
        return _usage_exit_code(exc)
    _fill_option_defaults(args)
    if args.version or args.command == "version":
        print(f"package-autopsy {__version__}")
        return EXIT_OK
    if not args.command:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        settings = load_settings(config_path=args.config, strict=args.strict)
        settings = _apply_cli_limits(settings, args)
        return _dispatch(args, settings)
    except UsageExit as exc:
        return _usage_exit_code(exc)
    except UsageError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return EXIT_USAGE
    except ResourceLimitError as exc:
        return _fail(exc, args, EXIT_RESOURCE)
    except InvalidDistributionError as exc:
        return _fail(exc, args, EXIT_INVALID)
    except UnsupportedError as exc:
        return _fail(exc, args, EXIT_UNSUPPORTED)
    except IntegrityError as exc:
        return _fail(exc, args, EXIT_INTEGRITY)
    except PolicyError as exc:
        return _fail(exc, args, EXIT_POLICY)
    except IncompleteError as exc:
        return _fail(exc, args, EXIT_INCOMPLETE)
    except PackageAutopsyError as exc:
        return _fail(exc, args, exc.exit_code)
    except BrokenPipeError:
        return EXIT_OK


def _fill_option_defaults(args: argparse.Namespace) -> None:
    defaults: dict[str, Any] = {
        "config": None,
        "no_colour": False,
        "verbose": False,
        "quiet": False,
        "json": False,
        "output_format": None,
        "output": None,
        "strict": False,
        "include": [],
        "exclude": [],
        "severity": None,
        "fail_on": None,
        "recursive": False,
        "max_size": None,
        "timeout": None,
        "python_version": None,
        "platform": None,
        "implementation": None,
        "abi": None,
        "workers": None,
        "tree": False,
        "sort": "name",
        "regex": None,
        "extras": "",
        "context": 3,
        "ignore_whitespace": False,
    }
    for key, value in defaults.items():
        if not hasattr(args, key):
            setattr(args, key, value)


def _usage_exit_code(exc: UsageExit) -> int:
    code = exc.code
    if code is None:
        return EXIT_USAGE
    return int(code)


def _apply_cli_limits(settings: Settings, args: argparse.Namespace) -> Settings:
    limits = settings.limits
    if getattr(args, "max_size", None):
        limits.max_archive_size = parse_size(args.max_size)
    if getattr(args, "timeout", None):
        limits.timeout = args.timeout
    if getattr(args, "workers", None):
        limits.workers = max(1, args.workers)
    settings.limits = limits
    if getattr(args, "no_colour", False):
        settings.colour = False
    if getattr(args, "json", False):
        settings.default_format = "json"
    if getattr(args, "output_format", None):
        settings.default_format = args.output_format
    return settings


def _dispatch(args: argparse.Namespace, settings: Settings) -> int:
    if args.command == "formats":
        return _emit(
            args,
            settings,
            _formats_payload(),
            "Supported formats:\n  wheel (.whl)\n  sdist (.tar.gz, .zip)\n",
        )
    fmt = _format_name(args, settings)
    if args.command == "compare":
        left = _load_one(Path(args.left), settings.limits)
        right = _load_one(Path(args.right), settings.limits)
        try:
            payload, findings = compare_distributions(
                left,
                right,
                context=args.context,
                ignore_whitespace=args.ignore_whitespace,
                include=args.include or None,
                exclude=args.exclude or None,
            )
            text = _compare_text(payload)
            code = _fail_on(findings, args.fail_on)
            return _emit(args, settings, wrap_json(payload, findings=findings), text, code=code)
        finally:
            left.close()
            right.close()
    paths = _resolve_inputs(getattr(args, "paths", []), recursive=args.recursive)
    if args.command == "consistency":
        dists = [_load_one(path, settings.limits) for path in paths]
        try:
            sdists = [item for item in dists if item.format == "sdist"]
            wheels = [item for item in dists if item.format == "wheel"]
            if not sdists or not wheels:
                raise UsageError("consistency requires at least one sdist and one wheel")
            payload, findings = consistency_report(sdists[0], wheels)
            return _emit(args, settings, wrap_json(payload, findings=findings), _consistency_text(payload))
        finally:
            for item in dists:
                item.close()
    if args.command in SINGLE_INPUT and len(paths) != 1 and fmt not in {"jsonl", "json-lines"}:
        if len(paths) > 1 or args.recursive:
            return _batch(args, settings, paths)
        if not paths:
            raise UsageError("a distribution path is required")
    if not paths and args.command not in {"formats", "version"}:
        raise UsageError("a distribution path is required")
    dist = _load_one(paths[0], settings.limits)
    try:
        if args.command in SINGLE_INPUT - {"graph", "check", "report"}:
            require_python_distribution(dist)
        return _run_one(args, settings, dist)
    finally:
        dist.close()


def _run_one(args: argparse.Namespace, settings: Settings, dist: Distribution) -> int:
    context = MarkerContext(
        python_version=args.python_version,
        platform=args.platform,
        implementation=args.implementation,
    )
    command = args.command
    if command == "inspect":
        payload, findings = inspect_payload(dist, settings, context=context)
        return _emit(args, settings, payload, render_inspect(payload), findings=findings)
    if command == "contents":
        members = filtered_members(
            dist,
            include=args.include or None,
            exclude=args.exclude or None,
            regex=getattr(args, "regex", None),
        )
        members = sort_members(members, getattr(args, "sort", "name"))
        files = [member for member in members if not member.is_dir]
        payload = {
            "schema_version": "1.0",
            "files": [member_as_dict(item) for item in files],
            "sizes": size_report(dist, members),
        }
        if getattr(args, "tree", False):
            text = "\n".join(tree_lines(members)) + "\n"
        else:
            text = "\n".join(f"{item.size:10d}  {item.category:16s}  {item.name}" for item in files) + "\n"
        return _emit(args, settings, payload, text)
    if command == "modules":
        points, _ = parse_entry_points(dist)
        modules = discover_modules(dist, points)
        payload = {"schema_version": "1.0", "modules": [item.as_dict() for item in modules]}
        text = "\n".join(
            module_tree(modules) if getattr(args, "tree", False) else (item.import_path for item in modules)
        )
        return _emit(args, settings, payload, text + "\n")
    if command == "commands":
        points, findings = parse_entry_points(dist)
        modules = discover_modules(dist, points)
        findings.extend(validate_entry_points(dist, points, modules))
        scripts = bundled_scripts(dist)
        payload = {
            "schema_version": "1.0",
            "entry_points": [item.as_dict() for item in points],
            "bundled_scripts": scripts,
        }
        lines = [f"{item.group}: {item.name} -> {item.raw}" for item in points] or ["(none)"]
        return _emit(args, settings, payload, "\n".join(lines) + "\n", findings=findings)
    if command == "dependencies":
        deps, findings = analyse_dependencies(dist, extras=getattr(args, "extras", ""), context=context)
        payload = wrap_json(dependencies_payload(deps), findings=findings)
        lines = [
            f"{item.kind}: {item.name} {item.specifier}".strip() + (f" ; {item.marker}" if item.marker else "")
            for item in deps
        ] or ["(none)"]
        return _emit(args, settings, payload, "\n".join(lines) + "\n", findings=findings)
    if command == "compatibility":
        payload, findings = analyse_compatibility(
            dist,
            python_version=args.python_version,
            platform=args.platform,
            implementation=args.implementation,
            abi=args.abi,
        )
        text = _compat_text(payload)
        return _emit(args, settings, wrap_json(payload, findings=findings), text, findings=findings)
    if command == "metadata":
        meta = dist.metadata.as_dict() if dist.metadata else {}
        payload = {
            "schema_version": "1.0",
            "metadata": meta,
            "dynamic": dist.dynamic_fields,
            "build_backend": dist.build_backend,
        }
        lines = [f"{key}: {value}" for key, value in meta.items() if value not in (None, [], "")]
        return _emit(args, settings, payload, "\n".join(lines) + "\n")
    if command == "licences":
        payload, findings = analyse_licences(dist)
        lines = [
            f"License-Expression: {payload.get('license_expression') or '(none)'}",
            f"License: {payload.get('legacy_license') or '(none)'}",
            "Files:",
        ]
        files = payload.get("bundled_files") or []
        if isinstance(files, list) and files:
            lines.extend(f"  {item['path']}" for item in files if isinstance(item, dict) and "path" in item)
        else:
            lines.append("  (none)")
        lines.append(str(payload.get("note")))
        return _emit(
            args,
            settings,
            wrap_json(payload, findings=findings),
            "\n".join(lines) + "\n",
            findings=findings,
        )
    if command == "binaries":
        binaries, findings = inspect_binaries(dist, settings.limits)
        payload = {"schema_version": "1.0", "binaries": [item.as_dict() for item in binaries]}
        lines = [
            f"{item.path}: {item.format} {item.architecture or ''} ({item.library_type})" for item in binaries
        ] or ["(none)"]
        return _emit(args, settings, payload, "\n".join(lines) + "\n", findings=findings)
    if command == "validate":
        payload, findings = validate_distribution(dist, strict=args.strict)
        code = EXIT_INVALID if payload.get("status") == "failed" else EXIT_OK
        return _emit(
            args,
            settings,
            wrap_json(payload, findings=findings),
            render_findings(_filter_findings(findings, args), verbose=args.verbose),
            code=code,
            findings=findings,
        )
    if command == "verify":
        payload, findings = verify_distribution(dist)
        status = payload.get("status")
        code = EXIT_OK
        if status == "failed":
            code = EXIT_INTEGRITY
        elif status == "incomplete":
            code = EXIT_INCOMPLETE
        elif status == "unsupported":
            code = EXIT_UNSUPPORTED
        text = f"Verification: {status}\n" + render_findings(findings, verbose=args.verbose)
        return _emit(
            args,
            settings,
            wrap_json(payload, findings=findings),
            text,
            code=code,
            findings=findings,
        )
    if command == "audit":
        payload, findings = audit_distribution(dist, settings, strict=args.strict)
        return _emit(
            args,
            settings,
            wrap_json(payload, findings=findings),
            render_findings(_filter_findings(findings, args), verbose=args.verbose),
            findings=findings,
        )
    if command == "graph":
        graph = dependency_graph([dist], context=context)
        fmt = _format_name(args, settings)
        if fmt == "mermaid":
            text = render_mermaid(graph) + "\n"
        elif fmt in {"dot", "graphviz"}:
            text = render_dot(graph) + "\n"
        else:
            text = render_tree(graph) + "\n"
        return _emit(args, settings, wrap_json(graph), text)
    if command == "report":
        payload = full_report(dist, settings, settings.limits)
        fmt = _format_name(args, settings)
        if fmt == "html":
            text = render_html(payload)
        elif fmt in {"md", "markdown"}:
            text = render_markdown(payload)
        elif fmt == "csv":
            text = render_csv(payload.get("findings") or [], ["id", "severity", "path", "explanation"])
        else:
            text = render_inspect(payload) + "\n" + render_markdown(payload)
        return _emit(args, settings, payload, text)
    if command == "check":
        payload, findings, status = check_policy(dist, settings)
        code = EXIT_OK
        if status == "failed":
            code = EXIT_POLICY
        elif status == "incomplete":
            code = EXIT_INCOMPLETE
        text = f"Policy: {status}\n" + render_findings(_filter_findings(findings, args), verbose=args.verbose)
        return _emit(
            args,
            settings,
            wrap_json(payload, findings=findings),
            text,
            code=code,
            findings=findings,
        )
    raise UsageError(f"unknown command {command}")


def _batch(args: argparse.Namespace, settings: Settings, paths: list[Path]) -> int:
    workers = settings.limits.workers
    results: list[dict[str, Any]] = []
    failures = 0

    def work(path: Path) -> dict[str, Any]:
        dist = load_distribution(path, settings.limits)
        try:
            payload, findings = inspect_payload(dist, settings)
            payload["path"] = str(path)
            payload["findings"] = [item.as_dict() for item in findings]
            return payload
        except PackageAutopsyError as exc:
            return {"path": str(path), "error": exc.as_dict(), "schema_version": "1.0"}
        finally:
            dist.close()

    ordered = sorted(paths)
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            mapped = list(pool.map(work, ordered))
    else:
        mapped = [work(path) for path in ordered]
    for item in mapped:
        results.append(item)
        if item.get("error") or (item.get("validation") or {}).get("status") == "failed":
            failures += 1
    fmt = _format_name(args, settings)
    text = (
        dumps_jsonl(results)
        if fmt in {"jsonl", "json-lines", "json"}
        else dumps_json({"schema_version": "1.0", "results": results})
    )
    if fmt == "text":
        lines = []
        for item in results:
            name = (item.get("distribution") or {}).get("name") or item.get("path")
            status = (item.get("validation") or {}).get("status") or item.get("error", {}).get("type")
            lines.append(f"{name}: {status}")
        text = "\n".join(lines) + "\n"
    code = EXIT_PARTIAL if failures else EXIT_OK
    return _emit(args, settings, {"schema_version": "1.0", "results": results}, text, code=code)


def _load_one(path: Path, limits: Limits) -> Distribution:
    return load_distribution(path, limits)


def _resolve_inputs(values: Sequence[str], *, recursive: bool) -> list[Path]:
    found: list[Path] = []
    for value in values:
        matches = glob.glob(value)
        candidates = [Path(item) for item in (matches or [value])]
        for candidate in candidates:
            if candidate.is_dir():
                pattern = "**/*" if recursive else "*"
                for child in sorted(candidate.glob(pattern)):
                    if child.is_file() and (
                        child.suffix.lower() in {".whl", ".zip", ".gz", ".tgz"} or str(child).endswith(".tar.gz")
                    ):
                        found.append(child)
            elif candidate.is_file():
                found.append(candidate)
            else:
                raise UsageError(f"path not found: {value}")
    unique = sorted({item.resolve() for item in found})
    return unique


def _format_name(args: argparse.Namespace, settings: Settings) -> str:
    if args.json:
        return "json"
    if args.output_format:
        return str(args.output_format).lower()
    return settings.default_format.lower()


def _emit(
    args: argparse.Namespace,
    settings: Settings,
    payload: dict[str, Any],
    text: str,
    *,
    code: int = EXIT_OK,
    findings: list[Finding] | None = None,
) -> int:
    fmt = _format_name(args, settings)
    if fmt in {"json", "jsonl", "json-lines"}:
        body = dumps_jsonl([payload]) if fmt in {"jsonl", "json-lines"} else dumps_json(payload)
    elif fmt == "html":
        body = render_html(payload) if "distribution" in payload else text
    elif fmt in {"md", "markdown"}:
        body = render_markdown(payload)
    elif fmt == "csv":
        rows = payload.get("files") or payload.get("findings") or []
        fields = list(rows[0].keys()) if rows and isinstance(rows[0], dict) else ["id", "explanation"]
        body = render_csv(rows, fields)
    else:
        body = text
        if args.verbose and findings:
            body += "\n" + render_findings(findings, verbose=True)
    if args.output:
        args.output.write_text(body, encoding="utf-8")
        if not args.quiet:
            print(f"wrote {args.output}", file=sys.stderr)
        return code
    console = make_console(
        no_colour=not colour_enabled(no_colour=args.no_colour or not settings.colour),
        quiet=args.quiet,
    )
    if args.quiet and fmt == "text" and code == EXIT_OK:
        return code
    if fmt == "text":
        console.print(body, end="" if body.endswith("\n") else "\n")
    else:
        sys.stdout.write(body if body.endswith("\n") else body + "\n")
    return code


def _fail(exc: PackageAutopsyError, args: argparse.Namespace, code: int) -> int:
    if getattr(args, "json", False) or getattr(args, "output_format", None) == "json":
        sys.stdout.write(dumps_json({"schema_version": "1.0", "error": exc.as_dict()}))
        return code
    print(f"error: {safe_display(exc.message)}", file=sys.stderr)
    return code


def _filter_findings(findings: list[Finding], args: argparse.Namespace) -> list[Finding]:
    severity = getattr(args, "severity", None)
    if not severity:
        return findings
    wanted = {part.strip() for part in severity.split(",")}
    return [item for item in findings if item.severity in wanted]


def _fail_on(findings: list[Finding], fail_on: str | None) -> int:
    if not fail_on:
        return EXIT_OK
    rank = {"informational": 0, "warning": 1, "error": 2}
    threshold = rank.get(fail_on, 2)
    if any(rank.get(item.severity, 0) >= threshold for item in findings):
        return EXIT_GENERAL
    return EXIT_OK


def _formats_payload() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "formats": [
            {
                "name": "wheel",
                "extensions": [".whl"],
                "capabilities": [
                    "inspect",
                    "validate",
                    "verify",
                    "modules",
                    "entry_points",
                    "RECORD",
                ],
            },
            {
                "name": "sdist",
                "extensions": [".tar.gz", ".zip"],
                "capabilities": ["inspect", "validate", "modules", "pyproject", "PKG-INFO"],
                "limitations": [
                    "setup.py is never executed",
                    "dynamic metadata is not materialised",
                ],
            },
        ],
        "network": False,
        "installs_packages": False,
    }


def _compare_text(payload: dict[str, Any]) -> str:
    version = payload.get("version") or {}
    lines = [
        "Package Comparison",
        "",
        f"Distribution: {(payload.get('distribution') or {}).get('from')}",
        "",
        "Version:",
        f"  {version.get('from')} -> {version.get('to')}",
        "",
        "Modules:",
    ]
    modules = payload.get("modules") or {}
    for item in modules.get("added") or []:
        lines.append(f"  + {item}")
    for item in modules.get("removed") or []:
        lines.append(f"  - {item}")
    if not modules.get("added") and not modules.get("removed"):
        lines.append("  Unchanged")
    lines.append("")
    lines.append("Dependencies:")
    deps = payload.get("dependencies") or {}
    for item in deps.get("added") or []:
        lines.append(f"  + {item}")
    for item in deps.get("removed") or []:
        lines.append(f"  - {item}")
    if not deps.get("added") and not deps.get("removed"):
        lines.append("  Unchanged")
    lines.append("")
    lines.append("Entry points:")
    eps = payload.get("entry_points") or {}
    if not eps.get("added") and not eps.get("removed"):
        lines.append("  Unchanged")
    else:
        for item in eps.get("added") or []:
            lines.append(f"  + {item}")
        for item in eps.get("removed") or []:
            lines.append(f"  - {item}")
    size = payload.get("size") or {}
    lines += [
        "",
        "Distribution size:",
        f"  {format_size(int(size.get('from') or 0))} -> {format_size(int(size.get('to') or 0))}",
        "",
        str(payload.get("note") or ""),
        "",
    ]
    return "\n".join(lines)


def _consistency_text(payload: dict[str, Any]) -> str:
    lines = [f"sdist: {payload.get('sdist')}", ""]
    for wheel in payload.get("wheels") or []:
        lines.append(f"wheel: {wheel.get('wheel')}")
        missing = wheel.get("missing_modules") or []
        extra = wheel.get("extra_modules") or []
        lines.append("  missing modules: " + (", ".join(missing) if missing else "(none)"))
        lines.append("  extra modules: " + (", ".join(extra) if extra else "(none)"))
        lines.append("")
    lines.append(str(payload.get("note") or ""))
    return "\n".join(lines) + "\n"


def _compat_text(payload: dict[str, Any]) -> str:
    evaluation = payload.get("evaluation") or {}
    lines = [
        f"Requires-Python: {payload.get('requires_python') or '(none)'}",
        f"Classifiers: {', '.join(payload.get('classifiers') or []) or '(none)'}",
        f"Tags: {payload.get('wheel_filename_tags')}",
        f"Native extensions: {payload.get('native_extensions')}",
        f"Evaluation: {evaluation.get('status')}",
    ]
    for reason in evaluation.get("reasons") or []:
        lines.append(f"  {reason}")
    lines.append(str(evaluation.get("note") or ""))
    return "\n".join(lines) + "\n"
