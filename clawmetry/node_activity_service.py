"""Independent, bounded daemon cadence for local and encrypted node views."""
from __future__ import annotations

import logging
import threading
import time

from clawmetry.node_activity import collect_node_activity, unavailable

log = logging.getLogger("clawmetry.node_activity_service")
INTERVAL_SECONDS = 30
_LOCK = threading.Lock()
_LAST_TICKS = {}


def tick_node_activity(store, *, node_id="", now=None):
    """Collect at most once per cadence. A request handler must never call this."""
    if not _LOCK.acquire(blocking=False):
        return None
    try:
        monotonic = time.monotonic()
        # Store identity is stable during a daemon lifetime; no daemon JSON state.
        key = (id(store), node_id)
        if monotonic - _LAST_TICKS.get(key, float("-inf")) < INTERVAL_SECONDS:
            return None
        _LAST_TICKS[key] = monotonic
        state = store.get_node_activity_state()
        observation = collect_node_activity(preferences=state["preferences"], node_id=node_id,
                                            now=now, fingerprint_key=state["fingerprint_key"])
        return store.record_node_activity(observation)
    except Exception as exc:
        log.warning("Node observation was not saved: %s", type(exc).__name__)
        try:
            return store.query_node_activity()
        except Exception:
            return unavailable("The node observation store is unavailable.")
    finally:
        _LOCK.release()
