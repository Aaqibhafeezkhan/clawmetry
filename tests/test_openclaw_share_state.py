from __future__ import annotations

from types import SimpleNamespace

from clawmetry.adapters.base import Session
from clawmetry.adapters import openclaw
from clawmetry.adapters.openclaw_share import apply_share_state, apply_share_state_to_payloads


def test_openclaw_share_state_is_exposed(monkeypatch):
    rows = [
        {
            "sessionId": "shared-session",
            "publicShare": {"id": "publication-1", "createdAt": 1720000000000},
        },
        {"sessionId": "private-session"},
    ]
    monkeypatch.setattr(openclaw, "_d", lambda: SimpleNamespace(_get_sessions=lambda: rows))

    sessions = [
        Session(agent="openclaw", id="shared-session"),
        Session(agent="openclaw", id="private-session"),
    ]
    apply_share_state(sessions)

    assert sessions[0].extra["isShared"] is True
    assert sessions[0].extra["shareCreatedAt"] == 1720000000.0
    assert sessions[0].extra["shareVisibility"] == "public-read-only"
    assert sessions[1].extra["isShared"] is False


def test_openclaw_share_state_is_exposed_for_local_store_payloads(monkeypatch):
    rows = [{"key": "shared-session", "publicShare": {"createdAt": 1720000000000}}]
    monkeypatch.setattr(openclaw, "_d", lambda: SimpleNamespace(_get_sessions=lambda: rows))

    payloads = [{"id": "shared-session", "extra": {"model": "test"}}]
    apply_share_state_to_payloads(payloads)

    assert payloads[0]["extra"]["model"] == "test"
    assert payloads[0]["extra"]["isShared"] is True
    assert payloads[0]["extra"]["shareCreatedAt"] == 1720000000.0
    assert payloads[0]["extra"]["shareVisibility"] == "public-read-only"
