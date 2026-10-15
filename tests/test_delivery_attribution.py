"""Delivery attribution: which pull request did this session's money buy?

Every cost figure ClawMetry showed before this was keyed on a session, a
runtime, a model or a node, so the product could say what agents cost but
not what the spend produced. These tests pin the two properties that make
the answer trustworthy rather than merely present:

* **The parts sum to the whole.** One session touches several pull requests,
  so joining session cost to each PR it mentions multiplies the money. On a
  real node that join reported a $106,946 pull request on a $3,843 machine.
  Cost is therefore split at event level, and the split plus the
  unattributed remainder must equal the session's own cost.
* **A reference must be a real reference.** Each false positive measured
  against live data has a test here, because a table that quietly attributes
  spend to the wrong pull request is worse than no table.
"""

from __future__ import annotations

import importlib

import pytest

from clawmetry import attribution


# ── Helpers ─────────────────────────────────────────────────────────────────

def _call(command, ts="2026-10-15T10:00:00Z", cost=None):
    """A tool_call event shaped the way the family adapters emit one."""
    return {
        "event_type": "tool_call",
        "ts": ts,
        "cost_usd": cost,
        "data": {
            "role": "assistant",
            "tool_name": "Bash",
            "tool_calls": [{
                "id": "toolu_1",
                "name": "Bash",
                "input": {"command": command},
            }],
        },
    }


def _usage(cost, ts="2026-10-15T10:00:01Z"):
    """A usage event: where the money actually is."""
    return {
        "event_type": "usage",
        "ts": ts,
        "cost_usd": None,
        "data": {"extra": {"costUsd": cost, "model": "claude-opus-5"}},
    }


def _newest_first(events):
    """``query_events`` hands the store's rows back newest-first."""
    return list(reversed(events))


# ── Extraction: the signal ──────────────────────────────────────────────────

def test_gh_pr_command_yields_pr_repo_and_role():
    """``gh pr edit 6275 --repo o/n`` is an explicit, authoring reference."""
    out = attribution.extract_session_delivery(
        _newest_first([_call("gh pr edit 6275 --repo own/repo")]), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert len(prs) == 1
    assert prs[0]["ref"] == "6275"
    assert prs[0]["repo"] == "own/repo"
    assert prs[0]["role"] == attribution.ROLE_AUTHORED
    assert prs[0]["confidence"] == 1.0
    assert prs[0]["basis"] == attribution.BASIS_PR_REFERENCE


def test_pr_url_carries_its_own_repo():
    """A pull-request URL is the strongest form: number and repo together."""
    out = attribution.extract_session_delivery(
        _newest_first([_call("open https://github.com/own/repo/pull/42")]), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert (prs[0]["ref"], prs[0]["repo"]) == ("42", "own/repo")


def test_read_only_verb_is_a_review_not_authorship():
    out = attribution.extract_session_delivery(
        _newest_first([_call("gh pr checks 7 --repo own/repo")]), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert prs[0]["role"] == attribution.ROLE_REVIEWED


def test_git_write_promotes_a_reviewed_pr_to_authored():
    """Viewing a PR in a session that also committed is authoring work."""
    out = attribution.extract_session_delivery(_newest_first([
        _call("gh pr view 7 --repo own/repo"),
        _call("git commit -m 'fix'"),
    ]), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert prs[0]["role"] == attribution.ROLE_AUTHORED
    assert "git_write" in prs[0]["source"]


def test_sole_repo_fills_a_bare_pr_but_lowers_confidence():
    """One repo in the session can own a flagless PR; two must not guess."""
    one = attribution.extract_session_delivery(_newest_first([
        _call("gh pr edit 6338 --title x"),
        _call("git remote -v   # github.com/own/alpha.git"),
    ]), "s1")
    pr = [a for a in one["artifacts"] if a["kind"] == "pr"][0]
    assert pr["repo"] == "own/alpha"
    assert pr["confidence"] < 1.0, "a guessed repo must not claim certainty"

    two = attribution.extract_session_delivery(_newest_first([
        _call("gh pr edit 6338 --title x"),
        _call("git remote -v  # github.com/own/alpha.git github.com/own/beta.git"),
    ]), "s1")
    pr2 = [a for a in two["artifacts"] if a["kind"] == "pr"][0]
    assert pr2["repo"] == "", "two candidate repos must stay blank, not guess"


# ── Extraction: the false positives, each measured on live data ─────────────

@pytest.mark.parametrize("command", [
    # `gh pr list` takes no PR argument, so `20` is the --limit value.
    "gh pr list --repo own/repo --limit 20",
    "gh pr status",
    # Prose, not a command.
    "the fix landed in pr 6275",
    # A different gh subcommand that happens to carry a number.
    "gh run list --repo own/repo 42",
])
def test_these_are_not_pull_request_references(command):
    out = attribution.extract_session_delivery(
        _newest_first([_call(command)]), "s1")
    assert [a for a in out["artifacts"] if a["kind"] == "pr"] == []


def test_repo_resolves_per_command_not_per_payload():
    """Chained commands against different repos must not cross-contaminate.

    One tool call runs several commands; resolving ``--repo`` against the
    whole payload filed PR 2566 under the first command's repository, which
    surfaced as the same pull request appearing under two repositories.

    The neighbouring command's ``--repo`` is deliberately placed CLOSER to
    the pull-request token than the owning command's own flag, which is the
    shape live data actually takes (``gh pr checks N --json a,b,c --repo X``).
    Proximity alone therefore picks the wrong repository here, so this pins
    the command boundary rather than the tie-breaker in front of it.
    """
    out = attribution.extract_session_delivery(_newest_first([
        _call("gh run list --repo own/alpha; gh pr checks 2566 "
              "--json name,state,bucket,link,description,workflow,event "
              "--repo own/beta"),
    ]), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert len(prs) == 1
    assert prs[0]["repo"] == "own/beta"


def test_bracketed_digits_are_not_a_commit():
    """``[2026-10-09 37085346064]`` is a timestamp, not git commit output."""
    assert attribution._find_commit_refs("[2026-10-09 37085346064]") == []
    found = attribution._find_commit_refs("[feat/x 4c9cfa6] subject")
    assert found and found[0]["commit"] == "4c9cfa6"


def test_trunk_branches_are_not_a_unit_of_delivery():
    out = attribution.extract_session_delivery(_newest_first([
        _call("git push origin main"),
        _call("git checkout -b feat/real-work"),
    ]), "s1")
    branches = {a["ref"] for a in out["artifacts"] if a["kind"] == "branch"}
    assert "feat/real-work" in branches
    assert "main" not in branches


# ── Evidence must never leak a secret ───────────────────────────────────────

def test_evidence_is_redacted_before_it_is_stored():
    """Evidence is a slice of a real command line and is scanned first."""
    token = "ghp_" + "a1b2c3d4e5" * 4
    out = attribution.extract_session_delivery(_newest_first([
        _call(f"GH_TOKEN={token} gh pr view 6275 --repo own/repo"),
    ]), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert prs, "the PR itself must still be found"
    assert token not in prs[0]["evidence"]
    for art in out["artifacts"]:
        assert token not in art["evidence"]


# ── The cost split: the parts sum to the whole ──────────────────────────────

def test_cost_split_sums_to_the_session_total():
    """The fan-out guard.

    Two pull requests, $3 spent while each was in play. A session-level join
    would report $6 against each; the split must report $3 each and $6 in
    total, never more.
    """
    events = [
        _call("gh pr edit 100 --repo own/repo", ts="2026-10-15T10:00:00Z"),
        _usage(3.0, ts="2026-10-15T10:00:01Z"),
        _call("gh pr edit 200 --repo own/repo", ts="2026-10-15T10:00:02Z"),
        _usage(3.0, ts="2026-10-15T10:00:03Z"),
    ]
    out = attribution.extract_session_delivery(_newest_first(events), "s1")
    prs = {a["ref"]: a["cost_usd"] for a in out["artifacts"] if a["kind"] == "pr"}
    assert prs == {"100": 3.0, "200": 3.0}
    assert out["total_usd"] == 6.0
    assert out["unattributed_usd"] == 0.0
    assert sum(prs.values()) + out["unattributed_usd"] == out["total_usd"]
    assert out["basis"] == "last_touch_segment"


def test_spend_before_any_pull_request_is_unattributed():
    """Honest remainder: exploration that never named a PR is not free."""
    events = [
        _usage(2.5, ts="2026-10-15T10:00:00Z"),
        _call("gh pr edit 100 --repo own/repo", ts="2026-10-15T10:00:01Z"),
        _usage(1.5, ts="2026-10-15T10:00:02Z"),
    ]
    out = attribution.extract_session_delivery(_newest_first(events), "s1")
    prs = {a["ref"]: a["cost_usd"] for a in out["artifacts"] if a["kind"] == "pr"}
    assert prs == {"100": 1.5}
    assert out["unattributed_usd"] == 2.5
    assert out["total_usd"] == 4.0


def test_a_session_that_names_no_pull_request_attributes_nothing():
    out = attribution.extract_session_delivery(
        _newest_first([_usage(9.0)]), "s1")
    assert [a for a in out["artifacts"] if a["kind"] == "pr"] == []
    assert out["unattributed_usd"] == 9.0


def test_cost_comes_from_the_column_when_present():
    """``events.cost_usd`` is authoritative; the payload is the fallback."""
    events = [
        _call("gh pr edit 1 --repo own/repo"),
        {"event_type": "usage", "ts": "2026-10-15T10:00:05Z",
         "cost_usd": 4.0, "data": {"extra": {"costUsd": 99.0}}},
    ]
    out = attribution.extract_session_delivery(_newest_first(events), "s1")
    assert out["total_usd"] == 4.0


@pytest.mark.parametrize("bad", [-5.0, float("inf"), float("nan"), "abc", None])
def test_a_bad_cost_is_zero_not_a_crash(bad):
    out = attribution.extract_session_delivery(_newest_first([
        _call("gh pr edit 1 --repo own/repo"),
        {"event_type": "usage", "ts": "2026-10-15T10:00:05Z",
         "cost_usd": bad, "data": {}},
    ]), "s1")
    assert out["total_usd"] == 0.0


# ── Never crash on bad input ────────────────────────────────────────────────

@pytest.mark.parametrize("events", [
    [],
    [None, 3, "nonsense"],
    [{"event_type": "tool_call"}],
    [{"event_type": "tool_call", "ts": None, "data": b"\xff\xfe not json"}],
    [{"event_type": "tool_call", "ts": "x", "data": "{broken json"}],
])
def test_malformed_event_streams_never_raise(events):
    out = attribution.extract_session_delivery(events, "s1")
    assert out["artifacts"] == []
    assert out["total_usd"] == 0.0


def test_event_count_is_reported_so_truncation_is_visible():
    out = attribution.extract_session_delivery(
        _newest_first([_call("echo hi"), _usage(1.0)]), "s1")
    assert out["event_count"] == 2


def test_runtime_is_recorded_as_the_store_agent_type():
    out = attribution.extract_session_delivery([], "s1", runtime="codex")
    assert out["agent_type"] == "codex"
    assert attribution.extract_session_delivery([], "s1")["agent_type"] == "openclaw"


def test_per_session_caps_bound_the_work():
    """A digest cron naming hundreds of PRs cannot dominate the table."""
    events = [_call(f"gh pr view {n} --repo own/repo")
              for n in range(1000, 1000 + attribution.MAX_PRS_PER_SESSION + 25)]
    out = attribution.extract_session_delivery(_newest_first(events), "s1")
    prs = [a for a in out["artifacts"] if a["kind"] == "pr"]
    assert len(prs) == attribution.MAX_PRS_PER_SESSION


# ── Persistence + the read API ──────────────────────────────────────────────

@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAWMETRY_LOCAL_STORE_PATH",
                       str(tmp_path / "events.duckdb"))
    monkeypatch.setenv("CLAWMETRY_LOCAL_FLUSH_SECS", "0.05")
    monkeypatch.setenv("CLAWMETRY_LOCAL_FLUSH_BATCH", "5")
    import clawmetry.local_store as ls

    importlib.reload(ls)
    s = ls.LocalStore()
    s.start()
    yield s
    s.stop(flush=True)


def _attribute(store, session_id, events, runtime="openclaw"):
    result = attribution.extract_session_delivery(
        _newest_first(events), session_id, runtime=runtime)
    written = store.persist_session_attribution(result, node_id="node-a")
    return result, written


def test_persist_then_query_delivery_roundtrip(store):
    _attribute(store, "s1", [
        _call("gh pr edit 6275 --repo own/repo"),
        _usage(12.0),
    ])
    out = store.query_delivery(kind="pr")
    assert out["available"] is True
    assert len(out["rows"]) == 1
    row = out["rows"][0]
    assert (row["repo"], row["ref"]) == ("own/repo", "6275")
    assert row["sessions"] == 1
    assert row["cost_usd"] == 12.0
    assert row["role"] == "authored"
    assert row["basis"] == attribution.BASIS_PR_REFERENCE


def test_two_sessions_on_one_pull_request_add_up(store):
    _attribute(store, "s1", [_call("gh pr edit 1 --repo own/repo"), _usage(4.0)])
    _attribute(store, "s2", [_call("gh pr edit 1 --repo own/repo"), _usage(6.0)])
    row = store.query_delivery(kind="pr")["rows"][0]
    assert row["sessions"] == 2
    assert row["cost_usd"] == 10.0


def test_recomputation_drops_an_artifact_that_is_no_longer_there(store):
    """Replace-per-session, so a stale pull request cannot linger forever."""
    _attribute(store, "s1", [_call("gh pr edit 1 --repo own/repo"), _usage(1.0)])
    _attribute(store, "s1", [_call("gh pr edit 2 --repo own/repo"), _usage(1.0)])
    refs = {r["ref"] for r in store.query_delivery(kind="pr")["rows"]}
    assert refs == {"2"}


def test_totals_report_the_unattributed_remainder(store):
    """Attributed spend shown without the remainder reads as the whole bill."""
    _attribute(store, "s1", [
        _usage(7.0, ts="2026-10-15T10:00:00Z"),
        _call("gh pr edit 1 --repo own/repo", ts="2026-10-15T10:00:01Z"),
        _usage(3.0, ts="2026-10-15T10:00:02Z"),
    ])
    totals = store.query_delivery(kind="pr")["totals"]
    assert totals["attributed_usd"] == 3.0
    assert totals["unattributed_usd"] == 7.0
    assert totals["sessions_attributed"] == 1


def test_delivery_is_filtered_by_runtime_server_side(store):
    """The runtime switcher contract: one runtime means one runtime's rows."""
    _attribute(store, "s1", [_call("gh pr edit 1 --repo own/repo"), _usage(5.0)],
               runtime="claude_code")
    _attribute(store, "s2", [_call("gh pr edit 2 --repo own/repo"), _usage(8.0)],
               runtime="codex")

    cc = store.query_delivery(kind="pr", runtime="claude_code")
    assert {r["ref"] for r in cc["rows"]} == {"1"}
    assert cc["totals"]["attributed_usd"] == 5.0

    cx = store.query_delivery(kind="pr", runtime="codex")
    assert {r["ref"] for r in cx["rows"]} == {"2"}
    assert cx["totals"]["attributed_usd"] == 8.0

    absent = store.query_delivery(kind="pr", runtime="cursor")
    assert absent["rows"] == []
    assert absent["totals"]["attributed_usd"] == 0.0, \
        "an absent runtime must report zero, never the node total"

    assert len(store.query_delivery(kind="pr")["rows"]) == 2


def test_session_artifacts_read_back_for_one_session(store):
    _attribute(store, "s1", [
        _call("gh pr edit 9 --repo own/repo"),
        _call("git checkout -b feat/x"),
        _usage(2.0),
    ])
    rows = store.query_session_artifacts(session_id="s1")
    kinds = {r["kind"] for r in rows}
    assert "pr" in kinds and "branch" in kinds
    assert store.query_session_artifacts(session_id="nope") == []


def test_watermarks_let_the_daemon_skip_unchanged_sessions(store):
    _attribute(store, "s1", [_call("gh pr edit 1 --repo own/repo"), _usage(1.0)])
    marks = store.attribution_watermarks()
    assert marks.get("s1") == 2


def test_only_pull_request_rows_carry_money(store):
    """A per-file share of a model call would be an invented number."""
    _attribute(store, "s1", [
        _call("gh pr edit 1 --repo own/repo"),
        _call("git checkout -b feat/x"),
        _usage(5.0),
    ])
    for row in store.query_session_artifacts(session_id="s1"):
        if row["kind"] == "pr":
            assert row["cost_usd"] is not None
        else:
            assert row["cost_usd"] is None


def test_one_pull_request_is_one_row_however_many_checkouts_exist(store):
    """The worktree fan-out guard.

    ``git_repos`` is keyed on ``repo_root``, so the same GitHub repository has
    one row per working directory: a git worktree, a second clone and the
    original checkout are three rows with identical owner/name. Joining the
    pull-request metadata straight through multiplied every row by that
    count, and the live list showed one pull request five times.
    """
    _attribute(store, "s1", [_call("gh pr edit 6382 --repo own/repo"),
                             _usage(15.0)])
    for root in ("/src/repo", "/src/repo-worktree-a", "/src/repo-worktree-b"):
        store.ingest_git_scan({
            "repo_root": root, "owner": "own", "name": "repo",
            "pull_requests": [{"number": 6382, "state": "MERGED",
                               "title": "the one real PR",
                               "url": "https://github.com/own/repo/pull/6382"}],
        })
    rows = store.query_delivery(kind="pr")["rows"]
    assert len(rows) == 1, f"one PR, {len(rows)} rows: the join fanned out"
    assert rows[0]["ref"] == "6382"
    assert rows[0]["cost_usd"] == 15.0, "cost must not be multiplied either"
    assert rows[0]["title"] == "the one real PR", \
        "the enrichment must still arrive after de-duplication"
    assert rows[0]["state"] == "MERGED"


def test_a_pull_request_with_no_local_checkout_still_gets_a_row(store):
    """Attribution must not depend on the repository being on this machine."""
    _attribute(store, "s1", [_call("gh pr edit 77 --repo gone/repo"),
                             _usage(2.0)])
    rows = store.query_delivery(kind="pr")["rows"]
    assert len(rows) == 1
    assert rows[0]["ref"] == "77"
    assert rows[0]["title"] == "", "no checkout means no title, not no row"


def test_evidence_reads_as_the_command_not_as_json(store):
    """Evidence sits under a column headed "How we know".

    Cut as a fixed character window out of the serialized payload it landed
    in neighbouring JSON (``...ods", "name": "Bash", "input": {``), which
    tells a reader nothing. It is bounded to the matched command instead.
    """
    out = attribution.extract_session_delivery(_newest_first([
        _call("gh pr checks 6283 --repo own/repo --json name,state"),
    ]), "s1")
    ev = [a for a in out["artifacts"] if a["kind"] == "pr"][0]["evidence"]
    assert "gh pr checks 6283" in ev
    for noise in ('"name": "Bash"', '"input"', "tool_calls", "toolu_"):
        assert noise not in ev, f"evidence leaked payload structure: {noise}"


def test_empty_store_is_an_honest_empty_not_an_error(store):
    out = store.query_delivery(kind="pr")
    assert out["available"] is True
    assert out["rows"] == []
    assert out["totals"]["attributed_usd"] == 0.0
