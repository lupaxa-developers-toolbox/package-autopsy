"""Discover importable packages and modules without importing them."""

from __future__ import annotations

from pathlib import PurePosixPath

from lupaxa.package_autopsy.load import Distribution, importable_roots
from lupaxa.package_autopsy.models import DiscoveredModule, EntryPoint

NATIVE_SUFFIXES = (".so", ".pyd")
SOURCE_SUFFIXES = (".py", ".pyw")
STUB_SUFFIXES = (".pyi",)


def _strip_root(path: str, roots: list[str]) -> str | None:
    posix = PurePosixPath(path)
    parts = posix.parts
    if not parts:
        return None
    head = parts[0]
    if head.endswith(".dist-info") or head.endswith(".egg-info"):
        return None
    if head.endswith(".data"):
        if len(parts) < 3:
            return None
        if parts[1] not in {"purelib", "platlib"}:
            return None
        return str(PurePosixPath(*parts[2:]))
    for root in roots:
        if root and path == root:
            return None
        if root and (path == f"{root}" or path.startswith(f"{root}/")):
            return path[len(root) + 1 :]
    if roots == [""] or (len(roots) == 1 and roots[0] == ""):
        return path
    if not any(roots):
        return path
    # sdist with a single wrapping directory already stripped via roots
    if len(roots) == 1 and roots[0] and not path.startswith(f"{roots[0]}/"):
        return None
    return path if not roots[0] else None


def _module_from_relative(relative: str) -> tuple[str, str] | None:
    posix = PurePosixPath(relative)
    name = posix.name
    if name == "__init__.py" or name == "__init__.pyi":
        if len(posix.parts) == 1:
            return None
        import_path = ".".join(posix.parts[:-1])
        return import_path, "package"
    if name.startswith("."):
        return None
    if name.endswith(".so") or name.endswith(".pyd"):
        stem = name.split(".", 1)[0]
        return ".".join((*posix.parts[:-1], stem)), "extension"
    if name.endswith(".pyi"):
        stem = name[: -len(".pyi")]
        return ".".join((*posix.parts[:-1], stem)), "stub"
    for suffix in SOURCE_SUFFIXES:
        if name.endswith(suffix):
            stem = name[: -len(suffix)]
            return ".".join((*posix.parts[:-1], stem)), "module"
    return None


def discover_modules(dist: Distribution, entry_points: list[EntryPoint] | None = None) -> list[DiscoveredModule]:
    roots = importable_roots(dist)
    cli_modules = {item.module for item in entry_points or [] if item.module}
    found: dict[str, DiscoveredModule] = {}
    files = [member for member in dist.archive.members if not member.is_dir]
    relative_files: list[tuple[str, str, int]] = []
    for member in files:
        relative = _strip_root(member.name, roots)
        if relative is None or relative == "":
            continue
        if dist.format == "sdist":
            lowered = relative.lower()
            if (
                lowered.startswith("tests/")
                or lowered.startswith("test/")
                or lowered.startswith("docs/")
                or lowered.startswith("doc/")
            ):
                # Still discoverable, but tagged via kind below.
                pass
        relative_files.append((member.name, relative, member.size))

    packages: set[str] = set()
    namespace_dirs: set[str] = set()
    for _archive_path, relative, _size in relative_files:
        posix = PurePosixPath(relative)
        if posix.name in {"__init__.py", "__init__.pyi"}:
            packages.add(".".join(posix.parts[:-1]))

    dirs_with_py: set[str] = set()
    dirs_with_init: set[str] = set()
    for _, relative, _ in relative_files:
        posix = PurePosixPath(relative)
        if posix.suffix in SOURCE_SUFFIXES + STUB_SUFFIXES + NATIVE_SUFFIXES or posix.name.endswith(".so"):
            parent = ".".join(posix.parts[:-1])
            if parent:
                dirs_with_py.add(parent)
        if posix.name in {"__init__.py", "__init__.pyi"}:
            dirs_with_init.add(".".join(posix.parts[:-1]))

    for directory in dirs_with_py | dirs_with_init:
        parts = directory.split(".")
        for index in range(1, len(parts) + 1):
            ancestor = ".".join(parts[:index])
            if ancestor and ancestor not in dirs_with_init:
                namespace_dirs.add(ancestor)
    for directory in dirs_with_py:
        if directory and directory not in dirs_with_init:
            namespace_dirs.add(directory)

    for archive_path, relative, size in relative_files:
        parsed = _module_from_relative(relative)
        if parsed is None:
            continue
        import_path, kind = parsed
        if dist.format == "sdist":
            first = import_path.split(".", 1)[0]
            if first in {"tests", "test", "docs", "doc", "examples", "example"}:
                kind = f"{kind}-noninstall"
        native = kind == "extension"
        package_name: str | None = import_path.rpartition(".")[0] or None
        if kind == "package" and import_path in namespace_dirs:
            kind = "namespace"
        module = DiscoveredModule(
            import_path=import_path,
            archive_path=archive_path,
            kind=kind,
            size=size,
            package=package_name,
            cli_target=import_path in cli_modules,
            native=native,
        )
        found[import_path] = module

    for directory in sorted(namespace_dirs):
        if directory not in found:
            found[directory] = DiscoveredModule(
                import_path=directory,
                archive_path=_archive_dir(dist, directory, roots),
                kind="namespace",
                size=0,
                package=directory.rpartition(".")[0] or None,
                cli_target=directory in cli_modules,
                native=False,
            )
        elif found[directory].kind == "package":
            pass
        else:
            found[directory].kind = "namespace"

    return [found[key] for key in sorted(found)]


def _archive_dir(dist: Distribution, import_path: str, roots: list[str]) -> str:
    rel = import_path.replace(".", "/")
    for root in roots:
        candidate = f"{root}/{rel}" if root else rel
        for member in dist.archive.members:
            if member.name == candidate or member.name.startswith(f"{candidate}/"):
                return candidate
    return rel


def module_tree(modules: list[DiscoveredModule]) -> list[str]:
    lines: list[str] = []
    for module in modules:
        depth = module.import_path.count(".")
        indent = "  " * depth
        lines.append(f"{indent}{module.import_path}  ({module.kind})")
    return lines
