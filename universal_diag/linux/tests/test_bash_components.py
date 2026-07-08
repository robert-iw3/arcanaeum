"""Bash component tests: plugin contract compliance and CLI behavior.
The TSV assertions here double as the parity suite for the Rust port —
same fixtures in, byte-identical events out (spec/event-schema.md).
"""
import datetime
import json
import re
import subprocess

import pytest

from conftest import LINUX_DIR, FIXTURES

UNIDIAG = str(LINUX_DIR / "unidiag.sh")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z?$")
SEVERITIES = {"crit", "error", "warn"}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


# ------------------------------------------------------- syslog plugin (TSV)

def syslog_collect(fixture):
    script = (f'. "{LINUX_DIR}/plugins/collect/20-syslog.sh"; '
              f'SYSLOG_FILE="{fixture}"; syslog_collect')
    return run(["bash", "-c", script]).stdout.splitlines()


def test_syslog_plugin_emits_valid_tsv():
    lines = syslog_collect(FIXTURES / "syslog.sample")
    assert lines, "collector emitted nothing"
    for line in lines:
        fields = line.split("\t")
        assert len(fields) == 5, f"not 5 TSV fields: {line!r}"
        ts, sev, source, origin, message = fields
        assert TS_RE.match(ts), f"bad timestamp: {ts}"
        assert sev in SEVERITIES
        assert source == "syslog"
        assert origin and message


def test_syslog_plugin_classification():
    lines = syslog_collect(FIXTURES / "syslog.sample")
    by_origin = {l.split("\t")[3]: l.split("\t")[1] for l in lines}
    assert by_origin["nginx"] == "error"      # "refused"
    assert by_origin["sshd"] == "error"       # "Failed"
    assert by_origin["kernel"] == "warn"      # "WARNING"
    assert by_origin["app"] == "crit"         # "FATAL"
    assert "cron" not in by_origin            # benign line dropped
    year = str(datetime.date.today().year)
    nginx_ts = next(l for l in lines if "\tnginx\t" in l).split("\t")[0]
    assert nginx_ts.startswith(year)          # RFC3164 year fill-in


def test_syslog_plugin_ignores_garbage_lines():
    lines = syslog_collect(FIXTURES / "syslog.sample")
    assert not any("no valid timestamp" in l for l in lines)


# ------------------------------------------------------------------ CLI

def test_cli_usage_on_no_args():
    r = run([UNIDIAG])
    assert r.returncode == 1
    assert "Usage" in r.stdout


def test_cli_rejects_bad_since():
    r = run([UNIDIAG, "scan", "--since", "yesterday"])
    assert r.returncode == 1
    assert "--since" in r.stderr


def test_cli_collectors_lists_all_plugins():
    r = run([UNIDIAG, "collectors"])
    assert r.returncode == 0
    for plugin in ("journald", "syslog", "container", "kubernetes",
                   "kernel", "saturation", "capacity", "network", "platform"):
        assert plugin in r.stdout, f"plugin {plugin} missing from listing"


def test_cli_triage_runs_all_sections():
    r = run([UNIDIAG, "triage", "--no-color"])
    assert r.returncode == 0
    for heading in ("saturation", "capacity", "network", "platform"):
        assert f"── {heading} ──" in r.stdout
    assert "host layer" in r.stdout           # final verdict line present


def test_cli_scan_json_is_valid_schema():
    r = run([UNIDIAG, "scan", "--since", "1h", "--json"])
    assert r.returncode == 0
    if "no warn+ events" in r.stdout:
        pytest.skip("host produced no events in window")
    decoder = json.JSONDecoder()
    buf, idx, seen = r.stdout, 0, 0
    while idx < len(buf):
        while idx < len(buf) and buf[idx] in " \t\r\n":
            idx += 1
        if idx >= len(buf):
            break
        obj, idx = decoder.raw_decode(buf, idx)
        assert set(obj) == {"ts", "severity", "source", "origin", "message"}
        assert obj["severity"] in SEVERITIES
        seen += 1
    assert seen > 0
