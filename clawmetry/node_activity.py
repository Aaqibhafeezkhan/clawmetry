"""Bounded polling observations. Private fingerprints never enter public payloads."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import math
import os
import platform
import socket
import stat
import time
import weakref
from pathlib import Path

log = logging.getLogger("clawmetry.node_activity")
DEFAULT_PREFERENCES = {"enabled": True, "processes": True, "listeners": True,
                       "sensitive_files": True, "rule_new_listener": True,
                       "rule_sensitive_change": True}
MAX_PROCESSES = 512
MAX_PROCESS_CANDIDATES = 4096
MAX_LISTENERS = 256
MAX_LOGINS = 64
MAX_FILE_BYTES = 1024 * 1024
UNKNOWN_ACTOR = {"kind": "unknown", "label": "Unattributed"}
_CPU_WARMED = weakref.WeakSet()
SUMMARY_KEYS = ("cpu_percent", "memory_used_bytes", "memory_total_bytes",
                "process_count", "listening_port_count")


def clean(value, limit=100):
    return " ".join("".join(c for c in str(value or "") if c.isprintable()).split())[:limit]


def number(value, integer=False):
    try:
        out = float(value)
        return (int(out) if integer else out) if math.isfinite(out) and out >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def identity(*values):
    return hashlib.sha256("\0".join(str(v) for v in values).encode()).hexdigest()[:32]


def validate_preferences(value):
    if (not isinstance(value, dict) or not value or
            set(value) - set(DEFAULT_PREFERENCES) or
            any(type(v) is not bool for v in value.values())):
        raise ValueError("Choose known monitoring options and use on or off.")
    return dict(value)


def unavailable(reason="No stored observations are available."):
    return {"schema_version": 1, "available": False, "reason": reason, "scope": "node",
            "node": {"id": "", "hostname": "", "platform": ""}, "collected_at": None,
            "stale_after_seconds": 120, "summary": dict.fromkeys(SUMMARY_KEYS),
            "samples": [], "processes": [], "listeners": [], "sensitive_files": [],
            "logins": [], "events": [], "coverage": {},
            "preferences": dict(DEFAULT_PREFERENCES), "truncated": False,
            "retention": {"hours": 24, "event_limit": 2000, "sample_limit": 120}}


def _namespace():
    """Describe only the namespace visible to this daemon, never promise host access."""
    scope = "unknown"
    tokens = []
    if platform.system() == "Linux":
        try:
            tokens = [os.readlink("/proc/self/ns/" + name) for name in ("pid", "net", "mnt")]
        except OSError:
            pass
        if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
            scope = "container"
    uid = os.geteuid() if hasattr(os, "geteuid") else "account"
    return scope, identity(platform.node(), uid, *tokens)


def _coverage(source, scope, now, state="complete", reason="", count=0, truncated=False):
    return {"source": source, "state": state, "method": "polling", "scope": scope,
            "observed_at": now, "reason": reason or "Limited to this account and visible namespace.",
            "count": count, "truncated": truncated}


def collect_node_activity(*, preferences=None, node_id="", now=None, psutil_module=None,
                          fingerprint_key=None, home=None, budget_seconds=3.0):
    """Return public metadata plus private source state for the daemon writer.

    No command line, environment, file content or file digest is public. Polling
    misses short-lived activity. psutil calls themselves cannot be interrupted;
    iteration and file work stop at the shared budget.
    """
    now = int((time.time() if now is None else now) * 1000)
    prefs = dict(DEFAULT_PREFERENCES)
    prefs.update(preferences or {})
    public = unavailable()
    public.update(available=True, reason="", collected_at=now, preferences=prefs,
                  node={"id": clean(node_id, 256), "hostname": clean(platform.node()),
                        "platform": platform.system()})
    out = {"public": public, "sources": {}}
    if not prefs["enabled"]:
        for source in ("resources", "processes", "listeners", "logins", "sensitive_files"):
            public["coverage"][source] = _coverage(source, "unknown", now, "disabled", "Monitoring is disabled.")
            out["sources"][source] = {"identity": "disabled", "rows": []}
        return out
    scope, namespace = _namespace()
    deadline = time.monotonic() + max(0.01, budget_seconds)
    try:
        if psutil_module is None:
            import psutil as psutil_module
        sensor = psutil_module
        try:
            boot = sensor.boot_time()
        except Exception:
            boot = "unknown"
    except Exception as exc:
        sensor, boot = None, "unknown"
        log.warning("Node polling library unavailable: %s", type(exc).__name__)
    source_identity = identity(node_id, namespace, boot)

    def save(name, rows, state="complete", reason="", truncated=False):
        public["coverage"][name] = _coverage(name, scope, now, state, reason, len(rows), truncated)
        out["sources"][name] = {"identity": source_identity, "rows": rows}
        public["truncated"] |= truncated

    enabled = prefs["enabled"]
    # Resources are measurements, not entity differences.
    if enabled and sensor is not None:
        failures = []
        try:
            measured = number(sensor.cpu_percent(interval=None))
            if sensor in _CPU_WARMED:
                public["summary"]["cpu_percent"] = measured
            else:
                _CPU_WARMED.add(sensor)
                failures.append("CPU warm-up")
        except Exception:
            failures.append("CPU")
        try:
            mem = sensor.virtual_memory()
            public["summary"].update(memory_used_bytes=number(mem.used, True),
                                     memory_total_bytes=number(mem.total, True))
        except Exception:
            failures.append("memory")
        save("resources", [], "partial" if failures else "complete",
             "CPU needs a second observation." if failures == ["CPU warm-up"] else
             "Some resource measurements are unavailable." if failures else "")
    else:
        save("resources", [], "disabled" if not enabled else "unavailable")

    pid_ids = {}
    for source, cap in (("processes", MAX_PROCESSES), ("listeners", MAX_LISTENERS),
                        ("logins", MAX_LOGINS)):
        if not enabled or (source != "logins" and not prefs[source]):
            save(source, [], "disabled")
            continue
        if sensor is None:
            save(source, [], "unavailable", "The host polling library is unavailable.")
            continue
        rows, partial, truncated = [], False, False
        try:
            if source == "processes":
                # psutil retains Process objects and their cached creation
                # times across iterations. Refresh before checking PID reuse.
                process_iter = sensor.process_iter
                clear_cache = getattr(process_iter, "cache_clear", None)
                if callable(clear_cache):
                    clear_cache()
                process_deadline = min(deadline - 0.75, time.monotonic() + 1.5)
                candidates = 0
                for proc in process_iter(["pid", "ppid", "name", "create_time", "memory_info"], ad_value=None):
                    if cap <= 0 or candidates >= MAX_PROCESS_CANDIDATES or time.monotonic() > process_deadline:
                        truncated = True
                        break
                    candidates += 1
                    try:
                        info = proc.info
                        started = number(info.get("create_time"))
                        if started is None or not info.get("pid"):
                            partial = True
                            continue
                        pid = int(info["pid"])
                        key = identity(source_identity, pid, started)
                        pid_ids[pid] = key
                        mem = info.get("memory_info")
                        rows.append({"id": key, "pid": pid, "parent_pid": info.get("ppid"),
                                     "name": clean(info.get("name")) or "Process name unavailable",
                                     "started_at": int(started * 1000), "cpu_percent": None,
                                     "memory_bytes": number(getattr(mem, "rss", None), True),
                                     "actor": dict(UNKNOWN_ACTOR)})
                        partial |= info.get("ppid") is None or info.get("name") is None
                    except Exception:
                        partial = True
                # Prefer recent processes with measurable memory. A cap on
                # ascending PID enumeration would hide the user's new work.
                rows.sort(key=lambda row: (row["memory_bytes"] is not None, row["started_at"]), reverse=True)
                truncated |= len(rows) > cap
                rows = rows[:cap]
                pid_ids = {row["pid"]: row["id"] for row in rows}
                public["processes"] = rows
                public["summary"]["process_count"] = len(rows) if not (partial or truncated) else None
            elif source == "listeners":
                if time.monotonic() > deadline - 0.35:
                    raise TimeoutError()
                for conn in sensor.net_connections(kind="inet"):
                    if conn.type != socket.SOCK_STREAM or conn.status != "LISTEN":
                        continue
                    if len(rows) >= cap or time.monotonic() > deadline - 0.35:
                        truncated = True
                        break
                    address, port = conn.laddr[0], int(conn.laddr[1])
                    try:
                        exposure = "loopback" if ipaddress.ip_address(address).is_loopback else "nonloopback"
                    except ValueError:
                        exposure = "unknown"
                    # A listener is the observed endpoint and reported owner PID.
                    # Optional verified process enrichment must not change its ID.
                    owner = pid_ids.get(conn.pid)
                    key = identity(source_identity, address, port, conn.pid, "tcp")
                    rows.append({"id": key, "process_id": owner, "pid": conn.pid,
                                 "address": clean(address), "port": port, "protocol": "tcp",
                                 "exposure": exposure, "actor": dict(UNKNOWN_ACTOR)})
                public["listeners"] = rows
                # Linux may silently omit sockets inaccessible to this account.
                partial = platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() != 0
                public["summary"]["listening_port_count"] = len(rows) if not (partial or truncated) else None
            else:
                if time.monotonic() > deadline - 0.35:
                    raise TimeoutError()
                for login in sensor.users():
                    if len(rows) >= cap:
                        truncated = True
                        break
                    rows.append({"id": identity(source_identity, login.name, login.terminal, login.started),
                                 "account": clean(login.name), "terminal": clean(login.terminal),
                                 "started_at": int(login.started * 1000),
                                 "actor": dict(UNKNOWN_ACTOR)})
                public["logins"] = rows
            save(source, rows, "partial" if partial or truncated else "complete",
                 "Only accessible sockets are shown. Other sockets may be omitted for this account."
                 if source == "listeners" and partial else
                 "Some records may be inaccessible or outside the scan budget." if partial or truncated else "", truncated)
        except NotImplementedError:
            save(source, rows, "unsupported", "This source is not supported on this platform.")
        except Exception as exc:
            save(source, rows, "partial" if rows else "unavailable",
                 "Permission denied." if type(exc).__name__ in ("AccessDenied", "PermissionError")
                 else "The source could not be read within this scan.")
            log.debug("Node %s scan incomplete: %s", source, type(exc).__name__)

    if not enabled or not prefs["sensitive_files"]:
        save("sensitive_files", [], "disabled")
    elif not fingerprint_key:
        save("sensitive_files", [], "unavailable", "The private comparison key is unavailable.")
    else:
        root = Path(home) if home else Path.home()
        specs = (("ssh_authorized_keys", root / ".ssh/authorized_keys", "SSH authorized keys"),
                 ("ssh_config", root / ".ssh/config", "SSH settings"),
                 ("claude_settings", root / ".claude/settings.json", "Claude Code settings"),
                 ("codex_config", root / ".codex/config.toml", "Codex settings"),
                 ("openclaw_config", root / ".openclaw/openclaw.json", "OpenClaw settings"))
        rows, partial = [], False
        for key, path, label in specs:
            if time.monotonic() > deadline:
                partial = True
                break
            row = {"id": key, "label": label, "present": False, "permissions": None}
            try:
                meta = path.lstat()
                if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_FILE_BYTES:
                    partial = True
                    continue
                # Do not follow links to arbitrary files; recheck after opening.
                fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as handle:
                    current = os.fstat(handle.fileno())
                    if (current.st_ino, current.st_dev) != (meta.st_ino, meta.st_dev):
                        partial = True
                        continue
                    data = handle.read(MAX_FILE_BYTES + 1)
                    after = os.fstat(handle.fileno())
                if len(data) > MAX_FILE_BYTES or (current.st_size, current.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    partial = True
                    continue
                row.update(present=True, permissions=oct(stat.S_IMODE(meta.st_mode)),
                           _fingerprint=hmac.new(fingerprint_key, data, hashlib.sha256).hexdigest())
            except FileNotFoundError:
                pass
            except OSError:
                partial = True
                continue
            rows.append(row)
        public["sensitive_files"] = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows]
        save("sensitive_files", rows, "partial" if partial else "complete",
             "Some selected files could not be compared." if partial else "Selected settings only. Contents and fingerprints are private.")
        out["sources"]["sensitive_files"]["identity"] = identity(source_identity, os.path.abspath(str(root)), fingerprint_key.hex())
    return out
