"""Node-wide storage and sealed relay integration.

AC-GOV-NODE-003.3: host detail stays in the encrypted snapshot.
AC-OBS-NODE-006.1: request reads use daemon observations.
AC-OBS-NODE-006.2: hosted fallback cannot collect the cloud host.
AC-OBS-NODE-006.4: the view stays explicitly node-wide.
"""
from pathlib import Path
import json
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def server():
    """These integration tests need no gateway or network server."""
    yield


@pytest.fixture
def relay(monkeypatch, tmp_path):
    from clawmetry import sync, local_store
    monkeypatch.setenv("CLAWMETRY_AUDIT_DB", str(tmp_path / "relay-audit.db"))

    class Store:
        def __init__(self):
            self.settings = {}
            self.preferences = {"enabled": True}
            self.reviews = []
        def _fetch(self, sql, params):
            return [(self.settings[params[0]],)] if params[0] in self.settings else []
        def set_node_setting(self, key, value):
            self.settings[key] = value
        def set_node_activity_preferences(self, preferences):
            if not isinstance(preferences, dict) or any(k != "enabled" or type(v) is not bool for k, v in preferences.items()):
                raise ValueError("invalid preferences")
            self.preferences.update(preferences)
            return {"ok": True, "saved": True, "preferences": dict(self.preferences)}
        def review_node_activity_event(self, event_id, decision, reason=""):
            if event_id != "observed-event" or decision not in {"expected", "investigate"}:
                raise ValueError("invalid review")
            self.reviews.append((event_id, decision, reason))
            return {"ok": True, "saved": True, "review": {"decision": decision, "reason": reason}}
        def query_node_activity(self):
            events = [{"id": e, "review": {"decision": d, "reason": r}} for e, d, r in self.reviews]
            return {"preferences": dict(self.preferences), "events": events}
    store = Store()
    results = []
    monkeypatch.setattr(local_store, "get_store", lambda *a, **k: store)
    monkeypatch.setattr(sync, "_post_process_control_result", lambda c, a, r: results.append(r))
    config = {"encryption_key": sync.generate_encryption_key(), "node_id": "node-one"}
    def send(body, drop_preferences=False, **overrides):
        request = {"operation": "preferences", "preferences": {"enabled": False},
                   "node_id": "node-one", "request_id": "a" * 32, "sent_at": time.time()}
        request.update(body)
        if drop_preferences:
            request.pop("preferences", None)
        action = {"type": "node_activity_update", "sealed": sync.encrypt_payload(request, config["encryption_key"])}
        action.update(overrides)
        sync._dispatch_pending_action(config, action)
        return results[-1]
    return store, send, sync


def test_sealed_update_confirms_persisted_readback_and_binding(relay):
    # AC-GOV-NODE-004.1, AC-GOV-NODE-004.3
    store, send, _ = relay
    result = send({})
    assert result["ok"] and result["saved"] and result["applied"]
    assert result["node_id"] == "node-one" and result["request_id"] == "a" * 32
    assert result["data"]["preferences"]["enabled"] is False
    assert store.preferences["enabled"] is False
    assert send({})["applied"] is False  # Replay does not apply twice.


@pytest.mark.parametrize("body", [
    {"node_id": "node-two"}, {"request_id": "invalid"},
    {"sent_at": time.time() - 1000}, {"sent_at": True},
    {"preferences": {"enabled": "false"}}, {"operation": "kill"},
    {"unexpected": "field"},
])
def test_invalid_or_cross_node_request_cannot_mutate(relay, body):
    store, send, _ = relay
    assert send(body)["applied"] is False
    assert store.preferences["enabled"] is True


def test_invalid_seal_cannot_mutate(relay):
    store, send, _ = relay
    assert send({}, sealed="invalid")["applied"] is False
    assert store.preferences["enabled"] is True


def test_review_requires_existing_event_and_valid_decision(relay):
    # AC-GOV-NODE-004.2: review is historical and preserves evidence.
    store, send, _ = relay
    body = {"operation": "review", "event_id": "observed-event", "decision": "expected", "reason": "My change"}
    # Preference field is not legal on review requests.
    assert send(body)["applied"] is False
    assert store.reviews == []
    result = send(body, drop_preferences=True)
    assert result["applied"] and result["saved"]
    assert store.reviews == [("observed-event", "expected", "My change")]


def test_snapshot_uses_store_and_declares_remote_capability(relay):
    _, _, sync = relay
    data = sync._build_node_activity_snapshot()
    assert data["capabilities"]["remote_mutations"] is True
    source = (ROOT / "clawmetry/sync.py").read_text()
    assert '"nodeActivity": _build_node_activity_snapshot()' in source
    # Collection precedes snapshot and its local-only early return.
    loop = source[source.index("    while True:", source.index("last_git_scan = 0.0")):]
    assert loop.index("tick_node_activity(") < loop.index("sync_system_snapshot(")


def test_tab_is_live_node_wide_and_routes_registered():
    app = (ROOT / "clawmetry/static/js/app.js").read_text()
    dashboard = (ROOT / "dashboard.py").read_text()
    assert "'node-activity': 1" in app
    assert "var _CM_NODE_TABS = ['node-activity'" in app
    assert "loadNodeActivity();" in app and "nodeActivityStop();" in app
    assert "{% include 'tabs/node-activity.html' %}" in dashboard
    assert "app.register_blueprint(bp_node_activity)" in dashboard


def test_replay_ledger_never_evicts_valid_nonces(relay):
    store, send, _ = relay
    store.settings["node_activity.request_ids"] = json.dumps({format(i, "032x"): time.time() for i in range(512)})
    assert send({})["applied"] is False
    assert len(json.loads(store.settings["node_activity.request_ids"])) == 512
    assert store.preferences["enabled"] is True


def test_replay_ledger_read_failure_fails_closed(relay):
    store, send, _ = relay
    def broken(*args):
        raise RuntimeError("store unavailable")
    store._fetch = broken
    assert send({})["applied"] is False
    assert store.preferences["enabled"] is True


def test_review_not_in_readback_cannot_claim_confirmed(relay):
    store, send, _ = relay
    store.query_node_activity = lambda: {"preferences": store.preferences, "events": []}
    result = send({"operation": "review", "event_id": "observed-event", "decision": "expected"}, drop_preferences=True)
    assert result["applied"] is False


@pytest.mark.parametrize("method", ["query_node_activity", "set_node_activity_preferences", "review_node_activity_event"])
def test_internal_node_method_requires_daemon_token_on_public_app(relay, monkeypatch, method):
    from flask import Flask
    from clawmetry import local_server
    from routes.local_query import bp_local_query
    store, _, _ = relay
    monkeypatch.setattr(local_server, "_token", None)
    app = Flask(__name__)
    app.register_blueprint(bp_local_query)
    response = app.test_client().post('/__local_query__/' + method,
                                      json={"kwargs": {"preferences": {"enabled": False}}})
    assert response.status_code == 401
    assert store.preferences["enabled"] is True


def test_authenticated_daemon_rpc_persists_typed_choice(relay, monkeypatch):
    from clawmetry import local_server
    store, _, _ = relay
    monkeypatch.setattr(local_server, "_token", "isolated-unit-token")
    app = local_server._make_app()
    response = app.test_client().post('/__local_query__/set_node_activity_preferences',
            headers={"Authorization": "Bearer isolated-unit-token"},
            json={"kwargs": {"preferences": {"enabled": False}}})
    assert response.status_code == 200
    assert response.json["result"]["saved"] is True
    assert store.preferences["enabled"] is False
