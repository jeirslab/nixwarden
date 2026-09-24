from __future__ import annotations

import json
from pathlib import Path

import pytest

from nixwarden import manifest


def test_valid_entry_has_no_problems(make_entry):
    assert manifest.validate([make_entry()]) == []


def test_load_rejects_non_array(tmp_path: Path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"not": "a list"}))
    with pytest.raises(ValueError, match="array"):
        manifest.load(p)


def test_load_reads_stdin(monkeypatch, make_entry):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps([make_entry()])))
    assert len(manifest.load("-")) == 1


def test_missing_required_fields_all_reported(make_entry):
    problems = manifest.validate([make_entry(org="", name="", sopsFile=None)])
    text = "\n".join(problems)
    assert "'org'" in text and "'name'" in text and "no sopsFile" in text


def test_bad_type_and_field(make_entry):
    assert any("not one of" in p for p in manifest.validate([make_entry(type="card")]))
    assert any("not valid for a note" in p for p in manifest.validate([make_entry(type="note", field="password", username=None, uris=[])]))


def test_login_only_slots_on_note(make_entry):
    problems = manifest.validate([make_entry(type="note", field="notes", username="x", uris=[])])
    assert any("only apply to login" in p for p in problems)


def test_doubled_slot(make_entry):
    problems = manifest.validate([make_entry(field="username", username="admin")])
    assert any("both target the same slot" in p for p in problems)


def test_ref_with_empty_key(make_entry):
    problems = manifest.validate([make_entry(username={"sopsKey": "", "sopsFile": None})])
    assert any("empty sopsKey" in p for p in problems)


def test_reserved_marker_field(make_entry):
    problems = manifest.validate([make_entry(fields=[{"name": "nixwarden", "value": "x"}])])
    assert any("reserved" in p for p in problems)


def test_duplicate_coordinate(make_entry):
    a = make_entry(sopsKey="a")
    b = make_entry(sopsKey="b")
    problems = manifest.validate([a, b])
    assert any("same vault item" in p for p in problems)


def test_resolve_paths_makes_relative_absolute(make_entry, tmp_path: Path):
    e = make_entry(sopsFile="secrets/x.yaml",
                   username={"sopsKey": "u", "sopsFile": "secrets/y.yaml"},
                   fields=[{"name": "t", "value": {"sopsKey": "t", "sopsFile": "z.yaml"}}])
    [r] = manifest.resolve_paths([e], tmp_path)
    assert r["sopsFile"] == str((tmp_path / "secrets/x.yaml").resolve())
    assert r["username"]["sopsFile"] == str((tmp_path / "secrets/y.yaml").resolve())
    assert r["fields"][0]["value"]["sopsFile"] == str((tmp_path / "z.yaml").resolve())


def test_resolve_paths_leaves_store_paths(make_entry, tmp_path: Path):
    e = make_entry(sopsFile="/nix/store/abc-source/secrets/x.yaml")
    [r] = manifest.resolve_paths([e], tmp_path)
    assert r["sopsFile"] == "/nix/store/abc-source/secrets/x.yaml"
