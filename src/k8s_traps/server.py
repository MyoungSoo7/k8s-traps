"""MCP server (stdio) exposing the trap catalog to AI agents."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .loader import load
from .traps import TRAPS, audit

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

mcp = MCPServer(
    name="k8s-traps",
    version=__version__,
    website_url="https://github.com/MyoungSoo7/k8s-traps",
    instructions=(
        "Audits Kubernetes YAML for incident-derived traps that generic linters miss "
        "(service-link env collisions, ServiceMonitors that select nothing, subPath mounts that never "
        "update, dead routes that serve another app, soft-only replica spreading, plaintext secrets, "
        "namespaces without NetworkPolicy). Works offline on the YAML you pass in; it never contacts a "
        "cluster. Pair it with a baseline scanner such as Kubescape or kube-linter."
    ),
)


@mcp.tool(annotations=READ_ONLY)
def audit_manifests(manifests: list[str], traps: list[str] | None = None) -> dict:
    """Check Kubernetes YAML for known production traps.

    manifests: one or more YAML strings (multi-document `---` is fine; `helm template` output works).
    traps: optional subset of trap ids such as ["T01", "T02"]; default runs all.
    Returns findings sorted by severity. Secret values are never echoed back.
    """
    bundle = load(manifests)
    findings = audit(bundle, traps)
    return {
        "objects_scanned": len(bundle.objects),
        "parse_errors": bundle.errors,
        "findings": [f.to_dict() for f in findings],
    }


@mcp.tool(annotations=READ_ONLY)
def list_traps() -> list[dict]:
    """List every trap this server checks, with id, title and default severity."""
    return [{"id": t.id, "title": t.title, "severity": t.severity, "docs": t.docs} for t in TRAPS.values()]


@mcp.tool(annotations=READ_ONLY)
def explain_trap(trap_id: str) -> dict:
    """Explain one trap: what goes wrong, the incident it came from, and how to fix it."""
    trap = TRAPS.get(trap_id.upper())
    if trap is None:
        raise ValueError(f"unknown trap id {trap_id!r}; known: {', '.join(TRAPS)}")
    return {"id": trap.id, "title": trap.title, "severity": trap.severity, "summary": trap.summary,
            "incident": trap.incident, "fix": trap.fix, "docs": trap.docs}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
