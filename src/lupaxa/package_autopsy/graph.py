"""Declared-dependency graphs. Missing nodes stay unresolved."""

from __future__ import annotations

from typing import Any

from lupaxa.package_autopsy.dependencies import MarkerContext, analyse_dependencies
from lupaxa.package_autopsy.load import Distribution


def dependency_graph(
    distributions: list[Distribution],
    *,
    context: MarkerContext | None = None,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    known = {}
    for dist in distributions:
        name = dist.metadata.name if dist.metadata and dist.metadata.name else dist.filename
        known[name] = dist
        nodes[name] = {
            "id": name,
            "resolved": True,
            "version": dist.metadata.version if dist.metadata else None,
            "format": dist.format,
        }
    for dist in distributions:
        source = dist.metadata.name if dist.metadata and dist.metadata.name else dist.filename
        deps, _ = analyse_dependencies(dist, extras="all", context=context)
        for dep in deps:
            if dep.normalised not in nodes and dep.name not in nodes:
                nodes[dep.name] = {
                    "id": dep.name,
                    "resolved": False,
                    "version": None,
                    "format": None,
                }
            edges.append(
                {
                    "from": source,
                    "to": dep.name,
                    "kind": dep.kind,
                    "marker": dep.marker or "",
                    "specifier": dep.specifier,
                }
            )
    return {
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": edges,
        "note": "Edges are direct declared dependencies only. Unresolved nodes have no local metadata.",
    }


def render_tree(graph: dict[str, Any]) -> str:
    children: dict[str, list[dict[str, str]]] = {}
    sources = {edge["from"] for edge in graph["edges"]}
    for edge in graph["edges"]:
        children.setdefault(edge["from"], []).append(edge)
    roots = [node["id"] for node in graph["nodes"] if node["id"] in sources]
    if not roots:
        roots = [node["id"] for node in graph["nodes"]]
    lines: list[str] = []
    seen: set[str] = set()

    def walk(name: str, prefix: str) -> None:
        if name in seen:
            lines.append(f"{prefix}{name} (cycle)")
            return
        seen.add(name)
        lines.append(f"{prefix}{name}")
        for edge in children.get(name, []):
            kind = edge["kind"]
            spec = f" {edge['specifier']}" if edge["specifier"] else ""
            marker = f" [{edge['marker']}]" if edge["marker"] else ""
            lines.append(f"{prefix}  - {edge['to']}{spec} ({kind}){marker}")

    for root in roots:
        walk(root, "")
    return "\n".join(lines)


def render_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    for node in graph["nodes"]:
        label = node["id"]
        if not node["resolved"]:
            label += " (unresolved)"
        safe = _ident(node["id"])
        lines.append(f'    {safe}["{label}"]')
    for edge in graph["edges"]:
        lines.append(f"    {_ident(edge['from'])} -->|{edge['kind']}| {_ident(edge['to'])}")
    return "\n".join(lines)


def render_dot(graph: dict[str, Any]) -> str:
    lines = ["digraph dependencies {", "  rankdir=LR;"]
    for node in graph["nodes"]:
        shape = "box" if node["resolved"] else "ellipse"
        lines.append(f'  "{node["id"]}" [shape={shape}];')
    for edge in graph["edges"]:
        lines.append(f'  "{edge["from"]}" -> "{edge["to"]}" [label="{edge["kind"]}"];')
    lines.append("}")
    return "\n".join(lines)


def _ident(name: str) -> str:
    return "n_" + "".join(ch if ch.isalnum() else "_" for ch in name)
