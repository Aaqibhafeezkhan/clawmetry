"""Daemon-owned node evidence, private comparison state and separate reviews."""
from __future__ import annotations

import copy
import json
import logging
import os
import time
import uuid

from clawmetry.node_activity import DEFAULT_PREFERENCES, UNKNOWN_ACTOR, identity, unavailable, validate_preferences

log = logging.getLogger("clawmetry.node_activity_store")
NODE_ACTIVITY_DDL = [
    "CREATE TABLE IF NOT EXISTS node_activity_meta (key VARCHAR PRIMARY KEY, value VARCHAR NOT NULL)",
    "CREATE TABLE IF NOT EXISTS node_activity_events (id VARCHAR PRIMARY KEY, observed_at BIGINT NOT NULL, payload VARCHAR NOT NULL)",
    "CREATE TABLE IF NOT EXISTS node_activity_samples (observed_at BIGINT PRIMARY KEY, payload VARCHAR NOT NULL)",
    "CREATE TABLE IF NOT EXISTS node_activity_reviews (id VARCHAR PRIMARY KEY, event_id VARCHAR NOT NULL, reviewed_at BIGINT NOT NULL, payload VARCHAR NOT NULL)",
]
MAX_REVIEWS = 2000
MAX_REVIEWS_PER_EVENT = 20

SOURCE_NAMES = ("processes", "listeners", "sensitive_files", "logins")


def _encoded(value):
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


def _public_row(row):
    return {k: copy.deepcopy(v) for k, v in row.items() if not k.startswith("_")}


def _comparison(source, row):
    keys = {"processes": ("id", "name", "parent_pid"),
            "listeners": ("id", "address", "port", "protocol"),
            "sensitive_files": ("id", "present", "permissions", "_fingerprint"),
            "logins": ("id",)}[source]
    return {key: row.get(key) for key in keys}


def _event(source, previous, current, now, preferences):
    row = current or previous
    action = "changed" if current and previous else ("added" if current else "removed")
    safe_before, safe_after = (_public_row(previous) if previous else None,
                               _public_row(current) if current else None)
    finding = bool((source == "listeners" and action == "added" and
                    row.get("exposure") == "nonloopback" and preferences["rule_new_listener"]) or
                   (source == "sensitive_files" and preferences["rule_sensitive_change"]))
    if source == "sensitive_files":
        kind, title = "sensitive_config_changed", "Selected settings changed"
        label = row.get("label") or "Selected settings"
        detail = "A selected file differs from an earlier observation. The process that changed it is unknown."
    elif source == "listeners":
        kind = "listener_" + action
        label = str(row.get("address")) + ":" + str(row.get("port"))
        title = "A listening port " + ("appeared" if action == "added" else "changed" if action == "changed" else "disappeared")
        detail = "Polling observed a bound TCP port. This does not establish external reachability."
    elif source == "processes":
        kind = "process_" + action
        label = row.get("name") or "Process"
        title = "A process " + ("appeared" if action == "added" else "changed" if action == "changed" else "disappeared")
        detail = "Process identity includes its start time. A process name does not identify an agent or a person."
    else:
        kind, title, label = "login_" + action, "A login observation changed", "Login session"
        detail = "An account session changed. The account name does not establish who used it or whether access was authorised."
    changed_fields = []
    if source == "sensitive_files":
        changed_fields = [field for field in ("present", "permissions")
                          if (previous or {}).get(field) != (current or {}).get(field)]
        if (previous or {}).get("_fingerprint") != (current or {}).get("_fingerprint"):
            changed_fields.append("contents")
    evidence = ["Comparable periodic observations.", "Activity between scans may be missed."]
    if "contents" in changed_fields:
        evidence.append("The file contents changed. Contents are not included in the displayed evidence.")
    return {"id": "node_evt_" + identity(source, row["id"], now, action), "observed_at": now,
            "kind": kind, "title": title, "detail": detail, "actor": dict(UNKNOWN_ACTOR),
            "target": {"kind": source, "id": row["id"], "label": label},
            "process": safe_after if source == "processes" else None,
            "before": safe_before, "after": safe_after,
            "evidence": evidence, "changed_fields": changed_fields,
            "finding": finding, "severity": "warning" if finding else "info"}


class NodeActivityStoreMixin:
    """Requires LocalStore connection, transaction lock and read helper."""

    def _node_meta_locked(self, key, default=None):
        row = self._conn.execute("SELECT value FROM node_activity_meta WHERE key=?", [key]).fetchone()
        return json.loads(row[0]) if row else default

    def _node_put_locked(self, key, value):
        self._conn.execute("INSERT INTO node_activity_meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                           [key, _encoded(value)])

    def _prune_node_activity_locked(self, now, hours=24, limit=2000):
        """Bound all history after collection and governance writes alike."""
        cutoff = now - hours * 3600 * 1000
        self._conn.execute("DELETE FROM node_activity_events WHERE observed_at<?", [cutoff])
        self._conn.execute("DELETE FROM node_activity_events WHERE id IN (SELECT id FROM node_activity_events ORDER BY observed_at DESC,id DESC OFFSET ?)", [limit])
        self._conn.execute("DELETE FROM node_activity_samples WHERE observed_at<? OR observed_at IN (SELECT observed_at FROM node_activity_samples ORDER BY observed_at DESC OFFSET 120)", [cutoff])
        self._conn.execute("DELETE FROM node_activity_reviews WHERE event_id NOT IN (SELECT id FROM node_activity_events)")
        self._conn.execute("DELETE FROM node_activity_reviews WHERE id IN (SELECT id FROM node_activity_reviews QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY reviewed_at DESC,id DESC)>?)", [MAX_REVIEWS_PER_EVENT])
        self._conn.execute("DELETE FROM node_activity_reviews WHERE id IN (SELECT id FROM node_activity_reviews ORDER BY reviewed_at DESC,id DESC OFFSET ?)", [MAX_REVIEWS])

    def get_node_activity_state(self):
        """Private daemon state. Never add this method to an HTTP allowlist."""
        with self._write_lock:
            prefs = dict(DEFAULT_PREFERENCES)
            prefs.update(self._node_meta_locked("preferences", {}))
            key = self._node_meta_locked("fingerprint_key")
            if key is None:
                if self._read_only:
                    raise RuntimeError("Node comparison key requires the daemon writer")
                key = os.urandom(32).hex()
                self._node_put_locked("fingerprint_key", key)
            return {"preferences": prefs, "fingerprint_key": bytes.fromhex(key)}

    def record_node_activity(self, observation, *, retention_hours=24, max_events=2000):
        if self._read_only:
            raise RuntimeError("Node observations require the daemon writer")
        if not isinstance(observation, dict) or not isinstance(observation.get("public"), dict):
            raise ValueError("Invalid node observation")
        from clawmetry.local_store import _txn
        body = copy.deepcopy(observation["public"])
        now = body.get("collected_at")
        if type(now) is not int or now <= 0:
            raise ValueError("Invalid node observation time")
        hours = max(1, min(int(retention_hours), 168))
        limit = max(1, min(int(max_events), 2000))
        with self._write_lock, _txn(self._conn):
            prefs = dict(DEFAULT_PREFERENCES)
            prefs.update(self._node_meta_locked("preferences", {}))
            body["preferences"] = prefs
            old_public = self._node_meta_locked("public", {})
            old_sources = self._node_meta_locked("source_state", {})
            next_sources = copy.deepcopy(old_sources)
            events = []
            for source in SOURCE_NAMES:
                cov = body.get("coverage", {}).get(source, {})
                incoming = observation.get("sources", {}).get(source, {})
                rows = incoming.get("rows", [])
                old = old_sources.get(source)
                comparable = old and old.get("identity") == incoming.get("identity")
                if cov.get("state") == "complete":
                    if comparable:
                        before = {r["id"]: r for r in old["rows"]}
                        after = {r["id"]: r for r in rows}
                        for key in sorted(set(before) | set(after)):
                            prev, curr = before.get(key), after.get(key)
                            if prev is None or curr is None or _comparison(source, prev) != _comparison(source, curr):
                                events.append(_event(source, prev, curr, now, prefs))
                    next_sources[source] = {"identity": incoming.get("identity"), "rows": rows, "observed_at": now}
                else:
                    # Preserve last evidence, but never compare across an incomplete gap.
                    previous_rows = old_public.get(source, [])
                    existing = {r["id"]: dict(r, stale=True) for r in previous_rows}
                    if comparable or old is None:
                        existing.update({r["id"]: _public_row(r) for r in rows})
                    body[source] = list(existing.values())[:512]
                    if previous_rows:
                        cov["last_successful_at"] = (old or {}).get("observed_at")
                    if old:
                        # Any later full scan re-establishes a baseline. A gap
                        # cannot retrospectively prove a removal or recovery.
                        next_sources.pop(source, None)
            body["retention"] = {"hours": hours, "event_limit": limit, "sample_limit": 120,
                                 "review_limit": MAX_REVIEWS, "reviews_per_event_limit": MAX_REVIEWS_PER_EVENT}
            body["capabilities"] = {"preferences_writable": True, "reviews_writable": True}
            # Collector source caps already bound a full pass. Persist every
            # change, with findings first, before advancing comparison state.
            events.sort(key=lambda event: not event.get("finding"))
            body["truncated"] = bool(body.get("truncated") or len(events) > limit)
            for event in events:
                self._conn.execute("INSERT INTO node_activity_events VALUES (?,?,?) ON CONFLICT DO NOTHING",
                                   [event["id"], now, _encoded(event)])
            if body.get("coverage", {}).get("resources", {}).get("state") != "disabled":
                sample = dict(body.get("summary", {}), observed_at=now)
                self._conn.execute("INSERT INTO node_activity_samples VALUES (?,?) ON CONFLICT(observed_at) DO UPDATE SET payload=excluded.payload",
                                   [now, _encoded(sample)])
            self._node_put_locked("public", body)
            self._node_put_locked("source_state", next_sources)
            self._prune_node_activity_locked(now, hours, limit)
        return self.query_node_activity()

    def query_node_activity(self):
        rows = self._fetch("SELECT value FROM node_activity_meta WHERE key='public'", [])
        body = json.loads(rows[0][0]) if rows else unavailable()
        prefs_rows = self._fetch("SELECT value FROM node_activity_meta WHERE key='preferences'", [])
        body["preferences"] = dict(DEFAULT_PREFERENCES, **(json.loads(prefs_rows[0][0]) if prefs_rows else {}))
        events = self._fetch("SELECT payload FROM node_activity_events ORDER BY observed_at DESC,id DESC LIMIT 2000", [])
        body["events"] = [json.loads(row[0]) for row in events]
        reviews = self._fetch("SELECT event_id,payload FROM node_activity_reviews QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY reviewed_at DESC,id DESC)=1 ORDER BY reviewed_at DESC LIMIT 2000", [])
        by_id = {event_id: json.loads(payload) for event_id, payload in reviews}
        for event in body["events"]:
            if event["id"] in by_id:
                event["review"] = by_id[event["id"]]
        body["samples"] = [json.loads(r[0]) for r in reversed(self._fetch("SELECT payload FROM node_activity_samples ORDER BY observed_at DESC LIMIT 120", []))]
        body["capabilities"] = {"preferences_writable": True, "reviews_writable": True}
        for source in ("resources", *SOURCE_NAMES):
            if not body["preferences"]["enabled"] or (source in body["preferences"] and not body["preferences"][source]):
                body.setdefault("coverage", {}).setdefault(source, {})["state"] = "disabled"
        return body

    def set_node_activity_preferences(self, preferences):
        values = validate_preferences(preferences)
        if self._read_only:
            raise RuntimeError("Node preferences require the daemon writer")
        from clawmetry.local_store import _txn
        now = int(time.time() * 1000)
        with self._write_lock, _txn(self._conn):
            previous = dict(DEFAULT_PREFERENCES, **self._node_meta_locked("preferences", {}))
            updated = dict(previous, **values)
            self._node_put_locked("preferences", updated)
            # Each collection boundary starts a quiet baseline on re-enable.
            if any(previous[k] != updated[k] for k in ("enabled", "processes", "listeners", "sensitive_files")):
                self._node_put_locked("source_state", {})
            if previous != updated:
                event = {"id": "node_pref_" + uuid.uuid4().hex, "observed_at": now,
                         "kind": "monitoring_preferences_changed", "title": "Monitoring options changed",
                         "detail": "This changes ClawMetry observation only.",
                         "actor": {"kind": "operator", "label": "Operator review"},
                         "target": {"kind": "preferences", "id": "monitoring", "label": "Monitoring options"},
                         "before": previous, "after": updated, "evidence": ["Saved by the node collector."],
                         "finding": False, "severity": "info"}
                self._conn.execute("INSERT INTO node_activity_events VALUES (?,?,?)", [event["id"], now, _encoded(event)])
            self._prune_node_activity_locked(now)
        return {"ok": True, "saved": True, "preferences": updated}

    def review_node_activity_event(self, event_id, decision, reason=""):
        if (not isinstance(event_id, str) or len(event_id) > 128 or
                decision not in ("expected", "investigate") or
                not isinstance(reason, str) or len(reason) > 300 or
                any(ord(c) < 32 for c in reason)):
            raise ValueError("Choose a recorded change and a valid review decision.")
        if self._read_only:
            raise RuntimeError("Node reviews require the daemon writer")
        # Redact operator-entered text too; it can contain a pasted token.
        from clawmetry.redaction import scrub_payload
        reason, _ = scrub_payload(reason)
        from clawmetry.local_store import _txn
        review = {"decision": decision, "reason": str(reason), "reviewed_at": int(time.time() * 1000)}
        with self._write_lock, _txn(self._conn):
            self._prune_node_activity_locked(int(time.time() * 1000))
            if not self._conn.execute("SELECT 1 FROM node_activity_events WHERE id=?", [event_id]).fetchone():
                raise ValueError("The recorded change is no longer available.")
            previous = self._conn.execute("SELECT MAX(reviewed_at) FROM node_activity_reviews WHERE event_id=?", [event_id]).fetchone()[0]
            if previous is not None:
                review["reviewed_at"] = max(review["reviewed_at"], previous + 1)
            self._conn.execute("INSERT INTO node_activity_reviews VALUES (?,?,?,?)",
                               [uuid.uuid4().hex, event_id, review["reviewed_at"], _encoded(review)])
            self._prune_node_activity_locked(int(time.time() * 1000))
        return {"ok": True, "saved": True, "review": review}
