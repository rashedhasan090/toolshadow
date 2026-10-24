"""Command line interface for toolshadow."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .core import (SEVERITY_ORDER, Finding, check_catalog, check_lock, filter_min,
                   load_catalog, make_lock)


def _render_text(findings: List[Finding], n_tools: int, n_servers: int) -> str:
    lines = [f"toolshadow: {n_tools} tools across {n_servers} servers, {len(findings)} finding(s)"]
    order = sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.rule))
    for x in order:
        lines.append(f"[{x.severity.upper():6}] {x.rule} {x.kind}: {x.message}")
        if x.evidence:
            lines.append(f"         evidence: {x.evidence}")
    return "\n".join(lines)


def _render_md(findings: List[Finding]) -> str:
    out = ["| severity | rule | kind | tools | message |", "|---|---|---|---|---|"]
    for x in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.rule)):
        msg = x.message.replace("|", "\\|")
        out.append(f"| {x.severity} | {x.rule} | {x.kind} | {', '.join(x.tools)} | {msg} |")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="toolshadow",
                                description="Detect cross-server tool shadowing and rug pulls in MCP tool catalogs.")
    p.add_argument("--version", action="version", version=f"toolshadow {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="analyze tools/list dumps")
    sc.add_argument("dumps", nargs="+", help="tools/list JSON files, one per server")
    sc.add_argument("--lock", help="lockfile to diff against (rug-pull detection)")
    sc.add_argument("--format", choices=["text", "json", "md"], default="text")
    sc.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="info")
    sc.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                    help="exit 1 if any finding is at or above this severity")
    sc.add_argument("--similarity", type=float, default=0.6,
                    help="Jaccard threshold for lookalike-purpose (default 0.6)")

    lk = sub.add_parser("lock", help="write a lockfile pinning every tool definition")
    lk.add_argument("dumps", nargs="+")
    lk.add_argument("-o", "--output", default="toolshadow.lock.json")

    a = p.parse_args(argv)
    try:
        tools = load_catalog(a.dumps)
    except (OSError, ValueError) as e:
        print(f"toolshadow: error: {e}", file=sys.stderr)
        return 2

    if a.cmd == "lock":
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump(make_lock(tools), fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"toolshadow: pinned {len(tools)} tools to {a.output}")
        return 0

    findings = check_catalog(tools, similarity=a.similarity)
    if a.lock:
        with open(a.lock, encoding="utf-8") as fh:
            findings += check_lock(tools, json.load(fh))
    findings = filter_min(findings, a.min_severity)
    servers = {t.server for t in tools}
    if a.format == "json":
        print(json.dumps({"tools": len(tools), "servers": sorted(servers),
                          "findings": [x.to_dict() for x in findings]}, indent=2, ensure_ascii=False))
    elif a.format == "md":
        print(_render_md(findings))
    else:
        print(_render_text(findings, len(tools), len(servers)))
    if a.fail_on and any(SEVERITY_ORDER[x.severity] >= SEVERITY_ORDER[a.fail_on] for x in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
