"""Node evidence stays bounded, attributable and honest across missing scans.

AC-OBS-NODE-001.1
AC-OBS-NODE-001.2
AC-OBS-NODE-001.3
AC-OBS-NODE-002.1
AC-OBS-NODE-002.2
AC-OBS-NODE-002.3
AC-OBS-NODE-002.4
AC-GOV-NODE-003.1
AC-GOV-NODE-003.2
AC-GOV-NODE-004.1
AC-GOV-NODE-004.2
AC-GOV-NODE-004.3
AC-GOV-NODE-005.1
AC-GOV-NODE-005.2
AC-GOV-NODE-005.3
AC-OBS-NODE-006.1
"""
import copy
import json
import socket
import threading
from types import SimpleNamespace as Obj

import duckdb
import pytest
from flask import Flask

from clawmetry import node_activity as collector
from clawmetry.node_activity_store import NODE_ACTIVITY_DDL, NodeActivityStoreMixin
from routes import node_activity as routes


class Store(NodeActivityStoreMixin):
    def __init__(self, path=":memory:"):
        self._conn = duckdb.connect(path)
        self._write_lock = threading.Lock()
        self._read_only = False
        for sql in NODE_ACTIVITY_DDL:
            self._conn.execute(sql)

    def _fetch(self, sql, params):
        with self._write_lock:
            return self._conn.execute(sql, params).fetchall()


@pytest.fixture
def store():
    result = Store()
    yield result
    result._conn.close()


class Sensor:
    def __init__(self):
        self.start = 100
        self.processes = [Obj(info={"pid": 10, "ppid": 1, "name": "codex", "create_time": self.start,
                                   "memory_info": Obj(rss=40)})]
        self.connections = []
        self.fail_connections = False

    def boot_time(self): return 1
    def cpu_percent(self, interval=None): return 12.5
    def virtual_memory(self): return Obj(used=200, total=1000)
    def process_iter(self, attrs, ad_value=None): return iter(self.processes)
    def users(self): return []
    def net_connections(self, kind):
        if self.fail_connections:
            raise PermissionError()
        return self.connections


def observe(sensor, tmp_path, now=1000, **kwargs):
    return collector.collect_node_activity(psutil_module=sensor, home=tmp_path,
                                           fingerprint_key=b"k" * 32, now=now, **kwargs)


def test_quiet_baseline_pid_reuse_and_name_is_not_agent(store, tmp_path, monkeypatch):
    monkeypatch.setattr(collector.platform, "system", lambda: "Darwin")
    sensor = Sensor()
    first = store.record_node_activity(observe(sensor, tmp_path))
    assert first["events"] == []
    assert first["processes"][0]["actor"]["kind"] == "unknown"
    first_id = first["processes"][0]["id"]
    sensor.processes[0].info["create_time"] = 101
    second = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    assert second["processes"][0]["id"] != first_id
    assert {e["kind"] for e in second["events"]} == {"process_added", "process_removed"}
    ids = [e["id"] for e in second["events"]]
    assert [e["id"] for e in store.record_node_activity(observe(sensor, tmp_path, now=1030))["events"]] == ids


def test_partial_and_namespace_change_never_infer_removal(store, tmp_path, monkeypatch):
    sensor = Sensor()
    store.record_node_activity(observe(sensor, tmp_path))
    monkeypatch.setattr(collector, "MAX_PROCESSES", 0)
    capped = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    assert capped["processes"][0]["stale"]
    assert capped["summary"]["process_count"] is None
    assert capped["coverage"]["processes"]["state"] == "partial"
    assert capped["events"] == []
    monkeypatch.setattr(collector, "MAX_PROCESSES", 512)
    sensor.processes = []
    # Re-establish a baseline after the gap; no retrospective disappearance.
    assert store.record_node_activity(observe(sensor, tmp_path, now=1060))["events"] == []
    sensor.processes = Sensor().processes
    changed = observe(sensor, tmp_path, now=1090)
    changed["sources"]["processes"]["identity"] = "new-visible-namespace"
    assert store.record_node_activity(changed)["events"] == []


def test_socket_finding_and_permission_gap(store, tmp_path, monkeypatch):
    monkeypatch.setattr(collector.platform, "system", lambda: "Darwin")
    sensor = Sensor()
    store.record_node_activity(observe(sensor, tmp_path))
    sensor.connections = [Obj(type=socket.SOCK_STREAM, status="LISTEN", laddr=("0.0.0.0", 8765), pid=10)]
    new = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    finding = next(e for e in new["events"] if e["kind"] == "listener_added")
    assert finding["finding"] and finding["after"]["port"] == 8765
    assert finding["actor"]["kind"] == "unknown"
    assert "kill" not in json.dumps(new)
    sensor.fail_connections = True
    failed = store.record_node_activity(observe(sensor, tmp_path, now=1060))
    assert failed["coverage"]["listeners"]["state"] == "unavailable"
    assert failed["listeners"][0]["stale"]
    assert len(failed["events"]) == len(new["events"])


def test_sensitive_change_fingerprints_private_and_review_keeps_original(store, tmp_path, monkeypatch):
    monkeypatch.setattr("clawmetry.node_activity_store.time.time", lambda: 1030)
    target = tmp_path / ".ssh" / "authorized_keys"
    target.parent.mkdir()
    target.write_text("secret-original")
    sensor = Sensor()
    store.record_node_activity(observe(sensor, tmp_path))
    target.write_text("secret-replacement")
    body = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    event = next(e for e in body["events"] if e["kind"] == "sensitive_config_changed")
    assert event["finding"]
    assert "contents" in event["changed_fields"]
    assert any("file contents changed" in line for line in event["evidence"])
    public = json.dumps(body)
    assert "secret-original" not in public and "secret-replacement" not in public
    assert "fingerprint" not in json.dumps(body["events"]) and "_fingerprint" not in public
    original = copy.deepcopy(event)
    result = store.review_node_activity_event(event["id"], "expected", "A planned update")
    assert result["saved"]
    reviewed = next(e for e in store.query_node_activity()["events"] if e["id"] == event["id"])
    assert reviewed.pop("review")["decision"] == "expected"
    assert reviewed == original
    with pytest.raises(ValueError):
        store.review_node_activity_event("missing", "expected")


def test_preferences_persist_and_disabled_means_no_sensor_calls(tmp_path):
    path = str(tmp_path / "node.duckdb")
    first = Store(path)
    first.set_node_activity_preferences({"enabled": False})
    first._conn.close()
    second = Store(path)
    try:
        state = second.get_node_activity_state()
        assert not state["preferences"]["enabled"]
        class NoSensor:
            def boot_time(self): raise AssertionError("Disabled monitoring read the host")
        observation = collector.collect_node_activity(preferences=state["preferences"], psutil_module=NoSensor())
        assert {s["state"] for s in observation["public"]["coverage"].values()} == {"disabled"}
        body = second.record_node_activity(observation)
        assert body["events"][0]["kind"] == "monitoring_preferences_changed"
        assert len(body["samples"]) == 0
        with pytest.raises(ValueError): second.set_node_activity_preferences({"arbitrary_pid": True})
        with pytest.raises(ValueError): second.set_node_activity_preferences({"enabled": 1})
    finally:
        second._conn.close()


def test_selected_symlink_is_not_read_and_container_scope_is_explicit(tmp_path, monkeypatch):
    target = tmp_path / ".ssh" / "config"
    target.parent.mkdir()
    foreign = tmp_path / "unrelated-secret"
    foreign.write_text("secret")
    target.symlink_to(foreign)
    monkeypatch.setattr(collector, "_namespace", lambda: ("container", "container-identity"))
    observation = observe(Sensor(), tmp_path)
    assert observation["public"]["coverage"]["sensitive_files"]["state"] == "partial"
    assert all(c["scope"] == "container" for c in observation["public"]["coverage"].values())
    assert all(r["id"] != "ssh_config" for r in observation["sources"]["sensitive_files"]["rows"])


def test_retention_and_review_history_are_bounded(store, tmp_path):
    sensor = Sensor()
    store.record_node_activity(observe(sensor, tmp_path, now=1000))
    for index in range(5):
        sensor.processes[0].info["create_time"] += 1
        store.record_node_activity(observe(sensor, tmp_path, now=1030 + index), max_events=3)
    assert len(store.query_node_activity()["events"]) == 3
    store.record_node_activity(observe(sensor, tmp_path, now=100000), max_events=3)
    assert not store.query_node_activity()["events"]


def test_route_stored_only_and_unconfirmed_write_is_failure(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(routes.bp_node_activity)
    monkeypatch.setattr(routes, "store_is_authoritative", lambda: True)
    monkeypatch.setattr(routes, "_write_allowed", lambda: True)
    calls = []
    def call(method, **kwargs):
        calls.append((method, kwargs))
        return collector.unavailable() if method == "query_node_activity" else None
    monkeypatch.setattr(routes, "_call", call)
    client = app.test_client()
    assert client.get("/api/node-activity").status_code == 200
    assert calls == [("query_node_activity", {})]
    result = client.post("/api/node-activity/preferences", json={"enabled": False})
    assert result.status_code == 503 and result.json["saved"] is False
    assert client.post("/api/node-activity/preferences", json={"pid": 10}).status_code == 400
    assert client.post("/api/node-activity/reviews", json={"event_id": "a", "decision": "kill"}).status_code == 400
    monkeypatch.setattr(routes, "store_is_authoritative", lambda: False)
    assert client.get("/api/node-activity").json["available"] is False


def test_service_cadence_and_failure_preserve_stored_evidence(store, monkeypatch):
    from clawmetry import node_activity_service as service
    service._LAST_TICKS.clear()
    calls = []
    def collect(**kwargs):
        calls.append(kwargs)
        raise PermissionError()
    monkeypatch.setattr(service, "collect_node_activity", collect)
    assert service.tick_node_activity(store)["available"] is False
    monkeypatch.setattr(store, "query_node_activity", lambda: pytest.fail("Skipped ticks must not read history"))
    assert service.tick_node_activity(store) is None
    assert len(calls) == 1


def test_cpu_warmup_unknown_and_private_home_change_gets_quiet_baseline(store, tmp_path):
    sensor = Sensor()
    first = observe(sensor, tmp_path)
    assert first["public"]["summary"]["cpu_percent"] is None
    assert first["public"]["coverage"]["resources"]["state"] == "partial"
    assert "second observation" in first["public"]["coverage"]["resources"]["reason"]
    store.record_node_activity(first)
    other = tmp_path / "another-home"
    (other / ".ssh").mkdir(parents=True)
    (other / ".ssh/config").write_text("Unrelated home settings")
    next_observation = observe(sensor, other, now=1030)
    assert next_observation["public"]["summary"]["cpu_percent"] == 12.5
    assert store.record_node_activity(next_observation)["events"] == []


def test_restricted_linux_sockets_never_claim_complete_or_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(collector.platform, "system", lambda: "Linux")
    monkeypatch.setattr(collector.os, "geteuid", lambda: 1000)
    body = observe(Sensor(), tmp_path)["public"]
    assert body["coverage"]["listeners"]["state"] == "partial"
    assert body["summary"]["listening_port_count"] is None
    assert "omitted" in body["coverage"]["listeners"]["reason"]


def test_all_findings_survive_more_than_128_routine_changes(store, tmp_path, monkeypatch):
    monkeypatch.setattr(collector.platform, "system", lambda: "Darwin")
    sensor = Sensor()
    store.record_node_activity(observe(sensor, tmp_path))
    sensor.processes = [Obj(info={"pid": pid, "ppid": 1, "name": "ordinary-process", "create_time": 100,
                                 "memory_info": Obj(rss=40)}) for pid in range(200, 400)]
    sensor.connections = [Obj(type=socket.SOCK_STREAM, status="LISTEN", laddr=("0.0.0.0", 8765), pid=200)]
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh/config").write_text("A changed setting")
    body = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    kinds = [event["kind"] for event in body["events"]]
    assert len(kinds) > 128
    assert "listener_added" in kinds and "sensitive_config_changed" in kinds
    assert len([event for event in body["events"] if event["finding"]]) == 2
    assert not body["truncated"]


def test_listener_identity_stable_when_process_owner_evidence_is_missing(store, tmp_path, monkeypatch):
    monkeypatch.setattr(collector.platform, "system", lambda: "Darwin")
    sensor = Sensor()
    sensor.connections = [Obj(type=socket.SOCK_STREAM, status="LISTEN", laddr=("0.0.0.0", 8765), pid=10)]
    baseline = store.record_node_activity(observe(sensor, tmp_path))
    assert baseline["listeners"][0]["process_id"] is not None
    monkeypatch.setattr(collector, "MAX_PROCESSES", 0)
    missing_owner = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    assert missing_owner["listeners"][0]["process_id"] is None
    assert missing_owner["listeners"][0]["id"] == baseline["listeners"][0]["id"]
    assert missing_owner["events"] == []
    monkeypatch.setattr(collector, "MAX_PROCESSES", 512)
    assert store.record_node_activity(observe(sensor, tmp_path, now=1060))["events"] == []


def test_reviews_bounded_and_latest_even_when_clock_does_not_advance(store, monkeypatch):
    from clawmetry import node_activity_store as module
    monkeypatch.setattr(module.time, "time", lambda: 1000)
    monkeypatch.setattr(module, "MAX_REVIEWS_PER_EVENT", 3)
    monkeypatch.setattr(module, "MAX_REVIEWS", 4)
    store.set_node_activity_preferences({"processes": False})
    first = store.query_node_activity()["events"][0]["id"]
    for index in range(10):
        store.review_node_activity_event(first, "expected", str(index))
    assert store._conn.execute("SELECT COUNT(*) FROM node_activity_reviews").fetchone()[0] == 3
    assert store.query_node_activity()["events"][0]["review"]["reason"] == "9"
    store.set_node_activity_preferences({"processes": True})
    second = next(e["id"] for e in store.query_node_activity()["events"] if e["id"] != first)
    for index in range(10):
        store.review_node_activity_event(second, "investigate", str(index))
    assert store._conn.execute("SELECT COUNT(*) FROM node_activity_reviews").fetchone()[0] == 4
    # No collection is required to apply age retention on a governance write.
    monkeypatch.setattr(module.time, "time", lambda: 100000)
    store.set_node_activity_preferences({"processes": False})
    assert store._conn.execute("SELECT COUNT(*) FROM node_activity_reviews").fetchone()[0] == 0
    assert len(store.query_node_activity()["events"]) == 1


def test_bounded_process_candidates_keep_recent_work_not_first_pids(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "MAX_PROCESSES", 3)
    monkeypatch.setattr(collector, "MAX_PROCESS_CANDIDATES", 6)
    sensor = Sensor()
    sensor.processes = [Obj(info={"pid": pid, "ppid": 1, "name": "ordinary-process", "create_time": pid,
                                 "memory_info": Obj(rss=pid)}) for pid in range(10, 17)]
    body = observe(sensor, tmp_path)["public"]
    assert [p["pid"] for p in body["processes"]] == [15, 14, 13]
    assert body["coverage"]["processes"]["truncated"] is True
    assert body["summary"]["process_count"] is None
    assert body["coverage"]["sensitive_files"]["state"] == "complete"


def test_process_iterator_cache_is_cleared_before_each_identity_scan(store, tmp_path):
    """AC-OBS-NODE-002.4: fresh creation times survive library Process caching."""
    sensor = Sensor()

    class CachedIterator:
        def __init__(self):
            self.actual_start = 100
            self.cached = None
            self.clears = 0

        def cache_clear(self):
            self.cached = None
            self.clears += 1

        def __call__(self, attrs, ad_value=None):
            if self.cached is None:
                self.cached = Obj(info={"pid": 10, "ppid": 1, "name": "ordinary-process",
                                        "create_time": self.actual_start, "memory_info": Obj(rss=40)})
            return iter([self.cached])

    sensor.process_iter = CachedIterator()
    baseline = store.record_node_activity(observe(sensor, tmp_path))
    assert baseline["events"] == []
    previous_id = baseline["processes"][0]["id"]
    sensor.process_iter.actual_start = 200
    reused = store.record_node_activity(observe(sensor, tmp_path, now=1030))
    assert reused["processes"][0]["id"] != previous_id
    assert reused["processes"][0]["started_at"] == 200000
    assert {event["kind"] for event in reused["events"]} == {"process_added", "process_removed"}
    assert sensor.process_iter.clears == 2
