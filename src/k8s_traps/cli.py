"""Command-line entry point: `k8s-traps [FILE ...]` (reads stdin when no file or `-`)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .loader import load
from .traps import SEVERITY_ORDER, TRAPS, audit


def _read(paths: list[str]) -> list[str]:
    if not paths or paths == ["-"]:
        return [sys.stdin.read()]
    texts = []
    for p in paths:
        path = Path(p)
        files = sorted(f for f in path.rglob("*") if f.suffix in (".yaml", ".yml")) if path.is_dir() else [path]
        texts += [f.read_text(encoding="utf-8") for f in files]
    return texts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="k8s-traps", description=__doc__)
    parser.add_argument("paths", nargs="*", help="YAML files or directories (default: stdin)")
    parser.add_argument("--trap", action="append", help="run only this trap id (repeatable)")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"], default="high",
                        help="exit 1 if any finding is at or above this severity (default: high)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--list", action="store_true", help="list traps and exit")
    parser.add_argument("--mcp", action="store_true", help="run the MCP server on stdio (same as k8s-traps-mcp)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.mcp:
        from .server import main as serve
        serve()
        return 0

    if args.list:
        for t in TRAPS.values():
            print(f"{t.id}  {t.severity:<6}  {t.title}")
        return 0

    bundle = load(_read(args.paths))
    findings = audit(bundle, args.trap)

    if args.json:
        print(json.dumps({"objects_scanned": len(bundle.objects), "parse_errors": bundle.errors,
                          "findings": [f.to_dict() for f in findings]}, indent=2, ensure_ascii=False))
    else:
        for e in bundle.errors:
            print(f"warning: {e}", file=sys.stderr)
        for f in findings:
            print(f"[{f.severity.upper()}] {f.trap} {f.object}\n  {f.message}\n  fix: {f.fix}\n  docs: {f.docs}\n")
        print(f"{len(findings)} finding(s) in {len(bundle.objects)} object(s).")

    if args.fail_on == "never":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= limit for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
