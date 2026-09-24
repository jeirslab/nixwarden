from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from nixwarden import items


def test_login_item_resolves_anchor_and_refs(make_entry, resolver):
    e = make_entry(username={"sopsKey": "svc/user", "sopsFile": None},
                   fields=[{"name": "token", "value": {"sopsKey": "svc/token", "sopsFile": None}},
                           {"name": "docs", "value": "https://docs"}])
    item = items.desired_item(e, resolver)
    assert item["type"] == 1
    assert item["login"]["password"] == "hunter2"
    assert item["login"]["username"] == "generated-user"
    assert item["login"]["uris"] == [{"match": None, "uri": "https://svc.example"}]
    by_name = {f["name"]: f for f in item["fields"]}
    assert by_name["nixwarden"] == {"name": "nixwarden", "value": "sops:svc/password", "type": 0}
    assert by_name["token"] == {"name": "token", "value": "tok-123", "type": 1}  # from sops -> hidden
    assert by_name["docs"] == {"name": "docs", "value": "https://docs", "type": 0}  # literal -> text
    assert items.is_managed(item)


def test_ref_can_name_another_file(make_entry, resolver):
    e = make_entry(username={"sopsKey": "x/y", "sopsFile": "/tmp/other.yaml"})
    assert items.desired_item(e, resolver)["login"]["username"] == "other-value"


def test_note_item_puts_anchor_in_notes(make_entry, resolver):
    e = make_entry(type="note", field="notes", sopsKey="age/key", username=None, uris=[])
    item = items.desired_item(e, resolver)
    assert item["type"] == 2
    assert item["secureNote"] == {"type": 0}
    assert item["notes"] == "AGE-SECRET-KEY-1XYZ\n"
    assert item["login"] is None


def test_anchor_in_username(make_entry, resolver):
    e = make_entry(field="username", username=None, sopsKey="svc/user")
    item = items.desired_item(e, resolver)
    assert item["login"]["username"] == "generated-user"
    assert item["login"]["password"] is None


def test_missing_key_propagates(make_entry, resolver):
    from nixwarden.sops import SopsError
    with pytest.raises(SopsError):
        items.desired_item(make_entry(sopsKey="nope"), resolver)


def test_shape_and_diff_ignore_ids_and_dates(make_entry, resolver):
    desired = items.desired_item(make_entry(), resolver)
    desired["organizationId"], desired["collectionIds"] = "o1", ["c1"]
    existing = {**desired, "id": "abc", "revisionDate": "2026-01-01", "deletedDate": None,
                "login": {**desired["login"], "passwordRevisionDate": None},
                "notes": ""}  # bw returns "" where we sent null
    assert items.changed_attributes(items.shape(desired), items.shape(existing)) == []


def test_diff_names_attributes_not_values(make_entry, resolver):
    desired = items.desired_item(make_entry(), resolver)
    desired["organizationId"], desired["collectionIds"] = "o1", ["c1"]
    existing = {**desired, "id": "abc", "login": {**desired["login"], "password": "old"},
                "collectionIds": ["c1", "c2"]}
    diff = items.changed_attributes(items.shape(desired), items.shape(existing))
    assert diff == ["collections", "login.password"]
    assert "old" not in " ".join(diff) and "hunter2" not in " ".join(diff)


def test_merge_for_update_keeps_id(make_entry, resolver):
    desired = items.desired_item(make_entry(), resolver)
    desired["organizationId"], desired["collectionIds"] = "o1", ["c1"]
    existing = {"id": "abc", "folderId": "f", "type": 1, "name": "svc admin", "fields": [], "login": {},
                "organizationId": "o1", "collectionIds": ["c1", "c2"], "notes": None,
                "favorite": False, "reprompt": 0, "secureNote": None, "sshKey": None}
    merged = items.merge_for_update(existing, desired)
    assert merged["id"] == "abc" and merged["folderId"] == "f"
    assert merged["collectionIds"] == ["c1"]
    assert merged["login"]["password"] == "hunter2"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ssh_key_item_derives_public_half(make_entry, tmp_path: Path):
    key = tmp_path / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(key)], check=True)
    private = key.read_text()
    e = make_entry(type="ssh-key", field="privateKey", sopsKey="ssh/key", username=None, uris=[])
    item = items.desired_item(e, lambda f, k: private)
    assert item["type"] == 5
    assert item["sshKey"]["privateKey"] == private.rstrip("\n")
    assert item["sshKey"]["publicKey"].startswith("ssh-ed25519 ")
    assert item["sshKey"]["keyFingerprint"].startswith("SHA256:")


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ssh_garbage_is_refused(make_entry):
    e = make_entry(type="ssh-key", field="privateKey", username=None, uris=[])
    with pytest.raises(items.ItemError):
        items.desired_item(e, lambda f, k: "not a key")
