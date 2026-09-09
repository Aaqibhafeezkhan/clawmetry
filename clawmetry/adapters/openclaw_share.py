from __future__ import annotations

from typing import Any


def _share_by_session_id() -> dict[str, dict[str, Any]]:
    try:
        from .openclaw import _d
        rows = _d()._get_sessions() or []
    except Exception:
        return {}

    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        share = row.get("publicShare")
        if not isinstance(share, dict):
            continue
        for key in (row.get("sessionId"), row.get("key")):
            if key:
                result[str(key)] = share
    return result


def apply_share_state(sessions) -> None:
    shares = _share_by_session_id()
    for session in sessions:
        share = shares.get(str(session.id))
        if not isinstance(session.extra, dict):
            session.extra = {}
        session.extra["isShared"] = bool(share)
        if not share:
            continue
        created_at = share.get("createdAt")
        if created_at is not None:
            try:
                session.extra["shareCreatedAt"] = float(created_at) / 1000.0
            except (TypeError, ValueError):
                pass
        session.extra["shareVisibility"] = "public-read-only"


def apply_share_state_to_payloads(payloads) -> None:
    shares = _share_by_session_id()
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        share = shares.get(str(payload.get("id")))
        extra = payload.get("extra") if isinstance(payload.get("extra"), dict) else {}
        extra["isShared"] = bool(share)
        if share:
            created_at = share.get("createdAt")
            if created_at is not None:
                try:
                    extra["shareCreatedAt"] = float(created_at) / 1000.0
                except (TypeError, ValueError):
                    pass
            extra["shareVisibility"] = "public-read-only"
        payload["extra"] = extra
