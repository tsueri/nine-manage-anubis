"""Tests for output.py — table and JSON formatting."""

import json

from nine_manage_anubis.output import (
    format_status,
    format_steps,
    format_dry_run,
)
from nine_manage_anubis.ports import AnubisInstance


def _instance(domain="test.com", port=7010, state="active", vhosts=None, version="1.27.0"):
    return AnubisInstance(
        domain=domain,
        port=port,
        metrics_port=port + 1,
        user="www-anubis",
        service_state=state,
        vhosts=vhosts or [domain],
        version=version,
    )


# --- format_status table ------------------------------------------------------


def test_status_table_basic():
    instances = [_instance("a.com", 7010), _instance("b.com", 7012)]
    out = format_status(instances)
    assert "DOMAIN" in out
    assert "a.com" in out
    assert "b.com" in out
    assert "7010" in out
    assert "7012" in out
    assert "VERSION" in out
    assert "1.27.0" in out


def test_status_table_empty():
    out = format_status([])
    assert "No Anubis" in out


def test_status_table_with_health():
    instances = [_instance("a.com", 7010)]
    health = {"a.com": "HTTP 200"}
    out = format_status(instances, health_map=health)
    assert "HEALTH" in out
    assert "HTTP 200" in out


def test_status_table_lists_all_vhosts():
    instances = [_instance("example.ch", 7014, vhosts=["example.ch", "blog.example.ch", "forum.example.ch"])]
    out = format_status(instances)
    assert "example.ch" in out
    assert "blog.example.ch" in out
    assert "forum.example.ch" in out
    assert "example.ch, blog.example.ch, forum.example.ch" not in out


def test_status_table_vhosts_vertical():
    instances = [_instance("example.ch", 7014, vhosts=["example.ch", "blog.example.ch"])]
    out = format_status(instances)
    lines = out.strip().splitlines()
    vhost_lines = [l for l in lines if "blog.example.ch" in l]
    assert len(vhost_lines) == 1
    assert "example.ch" not in vhost_lines[0].split("VHOSTS")[-1] if "VHOSTS" in vhost_lines[0] else True
    example_lines = [l for l in lines if l.strip().startswith("example.ch") or l.strip().startswith("www-anubis") or "example.ch" in l]
    first_vhost_line = [l for l in lines if "example.ch" in l and "7014" in l]
    assert len(first_vhost_line) == 1


def test_status_table_vhosts_falls_back_to_domain():
    instances = [_instance("a.com", 7010, vhosts=[])]
    out = format_status(instances)
    assert "a.com" in out


# --- format_status JSON -------------------------------------------------------


def test_status_json_basic():
    instances = [_instance("a.com", 7010)]
    out = format_status(instances, as_json=True)
    data = json.loads(out)
    assert len(data) == 1
    assert data[0]["domain"] == "a.com"
    assert data[0]["port"] == 7010
    assert data[0]["vhost_count"] == 1
    assert data[0]["version"] == "1.27.0"


def test_status_json_with_health():
    instances = [_instance("a.com", 7010)]
    health = {"a.com": "ok"}
    out = format_status(instances, health_map=health, as_json=True)
    data = json.loads(out)
    assert data[0]["health"] == "ok"


# --- format_steps -------------------------------------------------------------


def test_format_steps():
    steps = ["step one", "step two", "step three"]
    out = format_steps(steps, title="Done:")
    assert "Done:" in out
    assert "1. step one" in out
    assert "2. step two" in out
    assert "3. step three" in out


def test_format_steps_empty():
    out = format_steps([])
    assert "nothing to do" in out


def test_format_steps_json():
    steps = ["step one", "step two"]
    out = format_steps(steps, as_json=True)
    data = json.loads(out)
    assert data["steps"] == steps


def test_format_dry_run():
    steps = ["would do X", "would do Y"]
    out = format_dry_run(steps)
    assert "Dry run" in out
    assert "would do X" in out
