"""Output formatting — human-readable tables and JSON.

No external dependencies. Table formatting uses simple string alignment.
"""

from __future__ import annotations

import json
from typing import Any

from .ports import AnubisInstance


def format_status(
    instances: list[AnubisInstance],
    health_map: dict[str, str] | None = None,
    as_json: bool = False,
) -> str:
    if as_json:
        return _format_status_json(instances, health_map)
    return _format_status_table(instances, health_map)


def _format_status_table(
    instances: list[AnubisInstance],
    health_map: dict[str, str] | None,
) -> str:
    if not instances:
        return "No Anubis instances found."

    headers = ["DOMAIN", "PORT", "METRICS", "USER", "STATE", "VERSION", "VHOSTS"]
    if health_map is not None:
        headers.append("HEALTH")

    ncols = len(headers)
    vhost_col = headers.index("VHOSTS")

    rows = []
    for inst in instances:
        vhosts = inst.vhosts if inst.vhosts else [inst.domain]
        first = vhosts[0]
        row = [
            inst.domain,
            str(inst.port),
            str(inst.metrics_port),
            inst.user,
            inst.service_state,
            inst.version or "unknown",
            first,
        ]
        if health_map is not None:
            row.append(health_map.get(inst.domain, "unknown"))
        rows.append(row)
        for vh in vhosts[1:]:
            sub = [""] * ncols
            sub[vhost_col] = vh
            rows.append(sub)

    return _format_table(headers, rows)


def _format_status_json(
    instances: list[AnubisInstance],
    health_map: dict[str, str] | None,
) -> str:
    data = []
    for inst in instances:
        entry: dict[str, Any] = {
            "domain": inst.domain,
            "port": inst.port,
            "metrics_port": inst.metrics_port,
            "user": inst.user,
            "state": inst.service_state,
            "version": inst.version or "unknown",
            "vhosts": inst.vhosts,
            "vhost_count": len(inst.vhosts),
        }
        if health_map is not None:
            entry["health"] = health_map.get(inst.domain, "unknown")
        data.append(entry)
    return json.dumps(data, indent=2)


def format_steps(steps: list[str], title: str = "", as_json: bool = False) -> str:
    if as_json:
        return json.dumps({"steps": steps}, indent=2)
    lines = []
    if title:
        lines.append(title)
        lines.append("")
    for i, step in enumerate(steps, 1):
        lines.append(f"  {i}. {step}")
    if not steps:
        lines.append("  (nothing to do)")
    return "\n".join(lines)


def format_dry_run(steps: list[str], title: str = "Dry run — would do:", as_json: bool = False) -> str:
    return format_steps(steps, title=title, as_json=as_json)


def _format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    lines = [fmt_row(headers)]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append(fmt_row(row))
    return "\n".join(lines)
