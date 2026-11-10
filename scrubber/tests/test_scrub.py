"""Unit tests for scrub.py. Standard library plus pytest only.

    python3 -m pytest -q

Every fixture is a synthetic tree under `tmp_path`, and every pseudonym map is
created with an explicit path and salt, so no state directory is read or
written.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scrub as S  # noqa: E402

SALT = bytes(range(32))


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _tree(root: Path) -> Path:
    """A synthetic source tree with one of every harvestable shape."""
    src = root / "zorvex"
    (src / "docs").mkdir(parents=True)
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text(
        "[remote \"origin\"]\n"
        "\turl = git@github.com:zorvex/beacon-gateway.git\n"
        "[user]\n\tname = Dana Rivera\n\temail = dana.rivera@zorvex.example\n",
        encoding="utf-8",
    )
    (src / "package.json").write_text(
        json.dumps({
            "name": "@zorvex/beacon-sdk",
            "dependencies": {"libfoo": "^3.0.0", "@scope/libbar": "1.0.0"},
        }),
        encoding="utf-8",
    )
    (src / "docs" / "runbook.md").write_text(
        "# Beacon rollout at ZorvexCorp Ltd\n\n"
        "The Beacon service runs on beacon-prod.zorvex.example and talks to\n"
        "ledger.internal over gRPC. Owner is dana.rivera@zorvex.example.\n"
        "Ticket BEAC-4412 tracked the cutover. See https://wiki.zorvex.example/beacon.\n"
        "Libfoo's FooFetcher does the fetching; that part is public.\n"
        "Retry budget is 3 attempts with a 250 ms backoff, then dead-letter.\n",
        encoding="utf-8",
    )
    (src / "docs" / "second.md").write_text(
        "# Second note\n\n"
        "Beacon again, and beacon-prod.zorvex.example again, so the pseudonyms\n"
        "must match the other document. Dana Rivera signed off.\n"
        "The dead-letter queue drains on a 5 minute timer.\n",
        encoding="utf-8",
    )
    return src


@pytest.fixture()
def bg(tmp_path: Path) -> Path:
    """A neutral background corpus: ordinary vocabulary."""
    b = tmp_path / "neutral"
    b.mkdir()
    (b / "notes.md").write_text(
        "Ordinary vocabulary: Users, Features, Fixes, LLM, URL, E2E.\n"
        "We use Docker and Postgres. Retry budgets and dead-letter queues.\n",
        encoding="utf-8",
    )
    return b


@pytest.fixture()
def harvested(tmp_path: Path, bg: Path):
    src = _tree(tmp_path)
    deny = S.harvest([src], floor=1, background_roots=[bg])
    pmap = S.PseudonymMap(path=tmp_path / "map.json", salt=SALT)
    return src, deny, S.Scrubber(deny, pmap)


# ---------------------------------------------------------------------------
# harvest
# ---------------------------------------------------------------------------


def test_harvest_is_derived_from_the_sources_not_typed(harvested):
    _src, deny, _scr = harvested
    have = {t.text.lower() for t in deny.terms.values()}
    # directory name, git remote org/repo, package scope, email, domain,
    # hostname, internal host, tracker prefix
    for expected in ("zorvex", "beacon-gateway", "dana.rivera@zorvex.example",
                     "zorvex.example", "beacon-prod.zorvex.example", "beac"):
        assert expected in have, f"{expected!r} not harvested"
    cats = {t.category for t in deny.terms.values()}
    assert {"org", "repo", "email", "domain", "host", "ticket"} <= cats


def test_a_declared_dependency_is_not_scrubbed(harvested):
    """Replacing a public library's name is knowledge loss, not privacy."""
    _src, deny, scr = harvested
    have = {t.text.lower() for t in deny.terms.values()}
    assert "libfoo" not in have
    out, _ = scr.scrub_text("Libfoo's FooFetcher does the fetching.")
    assert "Libfoo" in out


def test_root_directory_name_survives_every_allowlist(tmp_path, bg):
    """A tree that ships a package named after itself must not allowlist
    itself out of its own denylist."""
    src = tmp_path / "zorvex"
    src.mkdir()
    (src / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"zorvex": "1.0.0"}}),
        encoding="utf-8")
    (src / "note.md").write_text("zorvex is the vendor here.\n", encoding="utf-8")
    deny = S.harvest([src], floor=1, background_roots=[bg])
    assert "org:zorvex" in deny.terms


# ---------------------------------------------------------------------------
# layer 1: identifier substitution
# ---------------------------------------------------------------------------


def test_identifier_is_replaced_at_every_occurrence(harvested):
    _src, _deny, scr = harvested
    text = "zorvex, ZorvexCorp and ZORVEX all name zorvex.\n" * 3
    out, n = scr.scrub_text(text)
    assert scr.hits(out) == {}
    assert "zorvex" not in out.lower()
    assert n >= 12


def test_same_identifier_gets_the_same_pseudonym_in_two_documents(harvested):
    src, _deny, scr = harvested
    a = S.admissible(scr, src / "docs" / "runbook.md")
    b = S.admissible(scr, src / "docs" / "second.md")
    assert not a.refused and not b.refused
    host = scr.map.pseudonym("host", "beacon-prod.zorvex.example")
    assert host in a.text and host in b.text


def test_pseudonyms_are_stable_across_two_fresh_runs(tmp_path, bg):
    src = _tree(tmp_path)
    deny = S.harvest([src], floor=1, background_roots=[bg])
    doc = (src / "docs" / "runbook.md").read_text(encoding="utf-8")
    outs = []
    for i in range(2):
        pmap = S.PseudonymMap(path=tmp_path / f"m{i}.json", salt=SALT)
        outs.append(S.Scrubber(deny, pmap).scrub_text(doc)[0])
    assert outs[0] == outs[1]


def test_an_existing_assignment_is_never_renumbered(tmp_path, bg):
    """The map is append-only: a term that already has a number keeps it when
    the denylist grows."""
    src = _tree(tmp_path)
    deny = S.harvest([src], floor=1, background_roots=[bg])
    pmap = S.PseudonymMap(path=tmp_path / "map.json", salt=SALT)
    S.Scrubber(deny, pmap)
    before = pmap.pseudonym("org", "zorvex")
    pmap.save()

    deny.add("omegacorp", "org", "later")
    pmap2 = S.PseudonymMap(path=tmp_path / "map.json", salt=SALT)
    S.Scrubber(deny, pmap2)
    assert pmap2.pseudonym("org", "zorvex") == before
    assert pmap2.pseudonym("org", "omegacorp") != before


def test_a_ticket_prefix_is_replaced_only_in_the_reference_form(harvested):
    """`PLAN-4412` identifies; the word `PLAN` is domain vocabulary."""
    _src, deny, scr = harvested
    assert "ticket:beac" in deny.terms
    out, _ = scr.scrub_text("BEAC-4412 is the ticket; BEAC is also a status code.")
    assert "BEAC-4412" not in out
    assert "BEAC is also a status code" in out
    assert scr.hits(out) == {}


def test_technical_substance_survives_substitution(harvested):
    src, _deny, scr = harvested
    res = S.admissible(scr, src / "docs" / "runbook.md")
    assert not res.refused
    for kept in ("gRPC", "Retry budget", "250 ms backoff", "dead-letter"):
        assert kept in res.text
    assert res.tokens_replaced < res.tokens_total * 0.25


# ---------------------------------------------------------------------------
# the ordinary-English collision
# ---------------------------------------------------------------------------
#
# `Beacon` is an internal system name here AND an ordinary English word. The
# decision: an ambiguous term is substituted only in identifier context
# (hostname, path, backticks, "the X service"), never as a bare word in prose,
# because substituting it unconditionally destroys sentences that use the word
# in its ordinary sense. `--strict` reverses that for a tree where the identity
# matters more than the prose.


def _beacon(tmp_path: Path, strict: bool = False):
    """`Beacon` alone in the denylist: an internal system name that is also an
    ordinary English word. Built directly rather than harvested, to test the
    substitution layer in isolation."""
    deny = S.Denylist(floor=1, paranoid=True)
    deny.add("Beacon", "term", "test")
    deny.finalise()
    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT),
                     strict=strict)
    return deny, scr


def test_ambiguous_term_is_marked_and_not_replaced_as_a_bare_word(tmp_path):
    deny, scr = _beacon(tmp_path)
    assert deny.terms["term:beacon"].ambiguous is True
    out, _ = scr.scrub_text("The lighthouse sent a beacon across the water.")
    assert "beacon across the water" in out


def test_ambiguous_term_is_replaced_in_identifier_context(tmp_path):
    _deny, scr = _beacon(tmp_path)
    repl = scr.map.pseudonym("term", "Beacon")
    for phrase in ("the Beacon service", "deploy/Beacon/config", "`Beacon`"):
        out, _ = scr.scrub_text(phrase)
        assert repl in out, phrase


def test_strict_mode_replaces_an_ambiguous_term_unconditionally(tmp_path):
    _deny, scr = _beacon(tmp_path, strict=True)
    out, _ = scr.scrub_text("The lighthouse sent a beacon across the water.")
    assert "beacon" not in out.lower()
    assert scr.hits(out) == {}


# ---------------------------------------------------------------------------
# layer 2: path aliasing
# ---------------------------------------------------------------------------


def test_alias_carries_no_identifying_substring(harvested):
    src, deny, scr = harvested
    p = src / "docs" / "zorvex-beacon-prod-runbook.md"
    p.write_text("body\n", encoding="utf-8")
    alias = scr.alias_path(p)
    low = alias.lower()
    for t in deny.terms.values():
        assert t.text.lower() not in low, f"{t.text!r} leaked into {alias}"
    assert scr.hits(alias) == {}


def test_alias_is_stable_and_unique(harvested):
    src, _deny, scr = harvested
    a = src / "docs" / "runbook.md"
    b = src / "docs" / "second.md"
    assert scr.alias_path(a) == scr.alias_path(a)
    assert scr.alias_path(a) != scr.alias_path(b)


def test_alias_is_reversible_only_through_the_local_map(tmp_path, harvested):
    src, _deny, scr = harvested
    p = src / "docs" / "runbook.md"
    alias = scr.alias_path(p)
    scr.map.save()

    assert scr.map.reverse_path(alias) == str(p)
    # A map built on a different salt cannot produce the same alias, and an
    # empty map cannot resolve it.
    other = S.PseudonymMap(path=tmp_path / "other.json", salt=b"\x01" * 32)
    assert other.reverse_path(alias) is None
    assert other.alias_id(str(p)) != scr.map.alias_id(str(p))


def test_alias_of_a_wholly_identifying_filename_drops_the_stem(harvested):
    src, _deny, scr = harvested
    p = src / "docs" / "zorvex.md"
    p.write_text("body\n", encoding="utf-8")
    assert scr.alias_path(p).endswith("/doc.md")


def test_the_map_records_only_a_fingerprint_of_the_salt(tmp_path, harvested):
    _src, _deny, scr = harvested
    scr.map.save()
    blob = json.loads(scr.map.path.read_text(encoding="utf-8"))
    assert blob["salt_sha256_12"] == S.fingerprint(SALT)
    assert SALT.hex() not in scr.map.path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


def test_a_surviving_identifier_refuses_the_document(harvested):
    """A defect in the scrubber must refuse, not index dirty."""
    src, deny, scr = harvested
    p = src / "docs" / "hole.md"
    p.write_text("plain body about retries\n", encoding="utf-8")
    # Add a term after the scrubber compiled its patterns: the substitution
    # cannot see it, the survivor check must.
    deny.add("retries", "term", "injected")
    deny.terms["term:retries"].ambiguous = False
    res = S.admissible(scr, p)
    assert res.refused and res.reason == "survivor"
    assert "term:retries" in res.survivors


# ---------------------------------------------------------------------------
# verification helpers
# ---------------------------------------------------------------------------


def test_a_term_absent_from_root_documents_is_dropped(tmp_path, bg):
    """The co-occurrence gate: a public library's class name lives in a
    vendored copy of that library's docs and never next to the root name."""
    src = tmp_path / "zorvex"
    (src / "vendored").mkdir(parents=True)
    (src / "vendored" / "guide.md").write_text(
        "ZetaFetcher ZetaFetcher ZetaFetcher is a public class.\n", encoding="utf-8")
    (src / "own.md").write_text(
        "zorvex runs LedgerFanout LedgerFanout LedgerFanout internally.\n",
        encoding="utf-8")
    deny = S.harvest([src], floor=1, background_roots=[bg])
    assert "term:ledgerfanout" in deny.terms
    assert "term:zetacrawler" not in deny.terms
    assert deny.stats["dropped"].get("term:not-co-located-with-root", 0) >= 1


def test_paranoid_mode_keeps_everything_harvested(tmp_path, bg):
    src = tmp_path / "zorvex"
    src.mkdir()
    (src / "note.md").write_text(
        "zorvex uses E2E E2E E2E coverage and QRZX QRZX QRZX records.\n",
        encoding="utf-8")
    lax = S.harvest([src], floor=1, background_roots=[bg])
    par = S.harvest([src], floor=1, background_roots=[bg], paranoid=True)
    # `E2E` is ordinary vocabulary in the neutral corpus, so lax drops it;
    # paranoid denies everything harvested and keeps it. `QRZX` is in neither
    # the dictionary nor the neutral corpus, so both keep it.
    assert "term:qrzx" in lax.terms and "term:qrzx" in par.terms
    assert "term:e2e" in par.terms
    assert "term:e2e" not in lax.terms
    assert len(par.terms) > len(lax.terms)


def test_hits_is_the_survivor_oracle(harvested):
    _src, _deny, scr = harvested
    assert scr.hits("nothing to see here") == {}
    assert scr.hits("zorvex.example is the domain")


def test_fingerprint_never_returns_the_value():
    assert S.fingerprint("hunter2") != "hunter2"
    assert len(S.fingerprint("hunter2")) == 12


def test_substitution_iterates_to_a_fixed_point(tmp_path, bg):
    """Replacing a term inside a compound exposes its neighbour. The measured
    case: `request.userData.masterUser` left a bounded `user` behind after the
    CamelCase pass had removed `Data`."""
    src = tmp_path / "zorvex"
    src.mkdir()
    (src / "note.md").write_text("zorvex\n", encoding="utf-8")
    deny = S.harvest([src], floor=1, background_roots=[bg], paranoid=True)
    deny.add("user", "handle", "test")
    deny.add("data", "person", "test")
    deny.finalise()
    for key in ("handle:user", "person:data"):
        deny.terms[key].ambiguous = False
    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT))
    out, _ = scr.scrub_text("request.userData.masterUser is the field")
    assert scr.hits(out) == {}, out
    # `<USER_n>` is the pseudonym namespace for handles, so strip pseudonyms
    # before asserting the source token is gone.
    assert "user" not in re.sub(r"<[A-Z]+_\d+>", "", out).lower()


def test_scrub_state_refuses_to_live_inside_the_output(tmp_path):
    """Output plus the mapping file re-identifies every document, so the map
    must not be written into the output directory."""
    out = tmp_path / "out"
    S._assert_outside(tmp_path / "state", out)          # sibling: fine
    for bad in (out, out / "state"):
        with pytest.raises(S.Refused):
            S._assert_outside(bad, out)


def test_cli_scrub_round_trip(tmp_path, monkeypatch, capsys):
    """harvest -> scrub -> verify -> reverse through the command line."""
    state = tmp_path / "state"
    monkeypatch.setattr(S, "SCRUB_DIR", state)
    src = _tree(tmp_path)
    out = tmp_path / "out"

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["scrub.py", *argv])
        return S.main()

    assert run("harvest", "--root", str(src), "--floor", "1") == 0
    assert run("scrub", "--root", str(src), "--out", str(out)) == 0
    written = [p for p in out.rglob("*.md")]
    assert len(written) == 2
    body = "".join(p.read_text(encoding="utf-8") for p in written)
    assert "zorvex" not in body.lower()
    assert run("verify", "--scrubbed", str(out)) == 0
    alias = str(written[0].relative_to(out))
    capsys.readouterr()
    assert run("reverse", alias) == 0
    assert str(src) in capsys.readouterr().out


def test_a_pseudonym_is_never_re_matched_by_its_own_namespace(tmp_path):
    """Measured runaway: `user` was a denylist term, its pseudonym is
    `<USER_50>`, and the ambiguous rule treats `_` as identifier context — so
    `USER` inside the pseudonym matched again and the text grew to
    `<<<<USER_50>_50>_50>_45>` on every round."""
    deny = S.Denylist(floor=1, paranoid=True)
    deny.add("user", "handle", "t")
    deny.finalise()
    assert deny.terms["handle:user"].ambiguous is True
    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT))
    out, _ = scr.scrub_text("the user_id column and /user/ path\n")
    assert out.count("<") == out.count(">") == 2
    assert "<<" not in out
    assert S.SENTINEL_OPEN not in out and S.SENTINEL_CLOSE not in out
    assert scr.scrub_text(out)[0] == out, "substitution is not idempotent"


def test_an_ordinary_word_needs_structural_corroboration(tmp_path, bg):
    """Measured over-scrub: `data.distribution@…` split into "persons" `data`,
    `distribution`, `travel`, `your`, and `Data/observability` in a heading
    became `<PERSON_2>/observability`. An ordinary English word only counts as
    an identifier when something structural says so."""
    src = tmp_path / "zorvex"
    src.mkdir()
    (src / "note.md").write_text(
        "Contact data.distribution@zorvex.example about Advanced Solutions Ltd.\n"
        "The Data/observability split is a heading, not a person.\n",
        encoding="utf-8")
    deny = S.harvest([src], floor=1, background_roots=[bg])
    for gone in ("person:data", "person:distribution", "org:advanced solutions"):
        assert gone not in deny.terms, gone
    # the address itself and the client's own domain are still denied
    assert "email:data.distribution@zorvex.example" in deny.terms
    assert "domain:zorvex.example" in deny.terms

    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT))
    out, _ = scr.scrub_text("The Data/observability split stays readable.")
    assert "Data/observability" in out


def test_corroborated_ordinary_word_is_still_denied(tmp_path, bg):
    """`root` as a package name in a manifest is corroborated, so it stays."""
    src = tmp_path / "zorvex"
    src.mkdir()
    (src / "pyproject.toml").write_text('[project]\nname = "beacon"\n', encoding="utf-8")
    (src / "note.md").write_text("the beacon service\n", encoding="utf-8")
    deny = S.harvest([src], floor=1, background_roots=[bg])
    assert "pkg:beacon" in deny.terms
    assert deny.terms["pkg:beacon"].ambiguous is True


def test_the_subjects_own_name_is_removed_even_inside_a_longer_token(tmp_path, bg):
    """Measured survivors of a boundary-only match, on a scrub that reported
    zero: `NAME_API_URL`, `NAME_HMAC_KEY`, `<name>s`, `name_errors_2025`.
    A name that IS the subject is matched as a bare substring."""
    src = _tree(tmp_path)
    deny = S.harvest([src], floor=1, background_roots=[bg])
    assert deny.is_hard("zorvex")
    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT))
    probe = ("ZORVEX_API_URL and zorvexs and zorvex_errors_2025 and "
             "ZorvexCorpDashboard and zorvex")
    out, _ = scr.scrub_text(probe)
    assert scr.hits(out) == {}, out
    assert "zorvex" not in out.lower()


def test_underscore_closes_a_token_for_the_oracle(tmp_path, bg):
    """The boundary class is letters and digits, not `_`: in an identifier an
    underscore is a separator, so it has to end the token."""
    src = _tree(tmp_path)
    deny = S.harvest([src], floor=1, background_roots=[bg])
    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT))
    assert "repo:beacon-gateway" in deny.terms
    # `_` after the term used to hide it from both the substituter and the
    # oracle, because `_` counted as a word character.
    assert scr.hits("beacon-gateway_config") == {"repo:beacon-gateway": 1}
    out, _ = scr.scrub_text("the beacon-gateway_config file")
    assert scr.hits(out) == {}, out
    assert "beacon-gateway" not in out


def test_a_ticket_prefix_that_is_an_ordinary_word_is_still_a_ticket(tmp_path, bg):
    """`POLICY-101` survived a scrub because `policy` is an ordinary word and
    the corroboration rule dropped it. The reference form is its own
    corroboration; the bare word is untouched either way."""
    src = tmp_path / "zorvex"
    src.mkdir()
    (src / "note.md").write_text(
        "POLICY-101 and RISK-3 are tickets. The policy itself is a document,\n"
        "and RISK is a column in the table.\n", encoding="utf-8")
    deny = S.harvest([src], floor=1, background_roots=[bg])
    assert "ticket:policy" in deny.terms and "ticket:risk" in deny.terms
    scr = S.Scrubber(deny, S.PseudonymMap(path=tmp_path / "m.json", salt=SALT))
    out, _ = scr.scrub_text("POLICY-101 blocks RISK-3; the policy doc and the RISK column stay.")
    assert "POLICY-101" not in out and "RISK-3" not in out
    assert "the policy doc" in out and "the RISK column" in out
