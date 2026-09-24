from __future__ import annotations

from typing import Any

import pytest

from nixwarden import items, reconcile

ORGS = [{"id": "o-lab", "name": "lab"}, {"id": "o-other", "name": "other"}]
COLLS = {"o-lab": [{"id": "c-infra", "name": "infra"}, {"id": "c-old", "name": "old"}]}


def managed(name: str, *, cid: str = "c-infra", iid: str = "i1", typ: int = 1, **over: Any) -> dict[str, Any]:
    item = {
        "id": iid, "organizationId": "o-lab", "collectionIds": [cid], "type": typ, "name": name,
        "notes": None, "favorite": False, "reprompt": 0,
        "fields": [{"name": "nixwarden", "value": "sops:svc/password", "type": 0}],
        "login": {"username": "admin", "password": "hunter2", "totp": None,
                  "uris": [{"match": None, "uri": "https://svc.example"}]},
        "secureNote": None, "sshKey": None, "deletedDate": None,
    }
    item.update(over)
    return item


def run(entries, existing, **kw):
    return reconcile.plan(entries, organizations=ORGS, collections_by_org=COLLS,
                          items_by_org={"o-lab": existing}, resolver=kw.pop("resolver"), **kw)


def kinds(plan_):
    return [(a.kind, a.name) for a in plan_.actions]


def test_create_when_absent(make_entry, resolver):
    p = run([make_entry()], [], resolver=resolver)
    assert kinds(p) == [("create", "svc admin")]
    [a] = p.actions
    assert a.payload["organizationId"] == "o-lab" and a.payload["collectionIds"] == ["c-infra"]


def test_noop_when_identical(make_entry, resolver):
    p = run([make_entry()], [managed("svc admin")], resolver=resolver)
    assert kinds(p) == [("noop", "svc admin")]


def test_update_names_changed_attributes(make_entry, resolver):
    ex = managed("svc admin", login={"username": "admin", "password": "stale", "totp": None,
                                     "uris": [{"match": None, "uri": "https://svc.example"}]})
    p = run([make_entry()], [ex], resolver=resolver)
    [a] = p.actions
    assert a.kind == "update" and a.detail == "login.password" and a.existing_id == "i1"
    assert a.payload["id"] == "i1" and a.payload["login"]["password"] == "hunter2"


def test_recreate_on_type_change(make_entry, resolver):
    p = run([make_entry()], [managed("svc admin", typ=2)], resolver=resolver)
    [a] = p.actions
    assert a.kind == "recreate" and "note -> login" in a.detail


def test_unmanaged_same_name_is_a_conflict(make_entry, resolver):
    ex = managed("svc admin", fields=[])
    p = run([make_entry()], [ex], resolver=resolver)
    assert kinds(p) == [("conflict", "svc admin")]
    assert p.errors and not p.writes


def test_adopt_takes_over_unmanaged(make_entry, resolver):
    ex = managed("svc admin", fields=[])
    p = run([make_entry()], [ex], resolver=resolver, adopt=True)
    [a] = p.actions
    assert a.kind == "update" and a.detail.startswith("adopt")
    assert items.is_managed(a.payload)


def test_two_managed_same_name_is_ambiguous(make_entry, resolver):
    p = run([make_entry()], [managed("svc admin", iid="i1"), managed("svc admin", iid="i2")], resolver=resolver)
    assert kinds(p) == [("ambiguous", "svc admin")]


def test_prune_only_marked_items_in_managed_collections(make_entry, resolver):
    stale = managed("gone", iid="i9")                       # managed, in infra -> delete
    human = managed("hand-made", iid="i8", fields=[])        # unmanaged -> untouched
    elsewhere = managed("elsewhere", iid="i7", cid="c-old")  # managed, undeclared collection -> orphan
    p = run([make_entry()], [stale, human, elsewhere], resolver=resolver)
    assert sorted(kinds(p)) == sorted([("create", "svc admin"), ("delete", "gone"), ("orphan", "elsewhere")])
    delete = next(a for a in p.actions if a.kind == "delete")
    assert delete.existing_id == "i9" and delete.collection == "infra"


def test_no_prune_reports_instead(make_entry, resolver):
    p = run([make_entry()], [managed("gone", iid="i9")], resolver=resolver, prune=False)
    assert ("skip-prune", "gone") in kinds(p)
    assert not [a for a in p.actions if a.kind == "delete"]


def test_missing_collection_is_created_first(make_entry, resolver):
    p = run([make_entry(collection="new")], [], resolver=resolver)
    assert kinds(p) == [("create-collection", ""), ("create", "svc admin")]
    create = p.actions[1]
    assert create.pending_collection == ("lab", "new") and create.payload["collectionIds"] == []


def test_unknown_org_is_fatal(make_entry, resolver):
    with pytest.raises(reconcile.PlanError, match="not visible"):
        run([make_entry(org="nope")], [], resolver=resolver)


def test_missing_sops_key_is_an_error_action(make_entry, resolver):
    p = run([make_entry(sopsKey="nope")], [], resolver=resolver)
    assert kinds(p) == [("error", "svc admin")]
    assert p.errors


class FakeVault:
    def __init__(self):
        self.calls: list[tuple[str, Any]] = []

    def create_org_collection(self, org_id, name):
        self.calls.append(("create-collection", (org_id, name)))
        return {"id": "c-new"}

    def create_item(self, item):
        self.calls.append(("create", item["name"], list(item["collectionIds"])))
        return {**item, "id": "made"}

    def update_item(self, item_id, item):
        self.calls.append(("update", item_id))
        return item

    def delete_item(self, item_id, *, permanent=False):
        assert permanent is False
        self.calls.append(("delete", item_id))


def test_apply_refuses_a_plan_with_errors(make_entry, resolver):
    p = run([make_entry()], [managed("svc admin", fields=[])], resolver=resolver)
    with pytest.raises(reconcile.PlanError):
        reconcile.apply(p, FakeVault())


def test_apply_creates_collection_then_patches_items(make_entry, resolver):
    p = run([make_entry(collection="new"), make_entry(sopsKey="svc/user", name="other", field="username", username=None)],
            [managed("gone", iid="i9")], resolver=resolver)
    v = FakeVault()
    reconcile.apply(p, v)
    assert v.calls[0] == ("create-collection", ("o-lab", "new"))
    assert ("create", "svc admin", ["c-new"]) in v.calls
    assert ("create", "other", ["c-infra"]) in v.calls
    assert ("delete", "i9") in v.calls  # 'gone' sits in infra, which 'other' still declares
    assert all(a.ok for a in p.writes)


def test_apply_records_failures_and_continues(make_entry, resolver):
    class Failing(FakeVault):
        def create_item(self, item):
            from nixwarden.bw import BwError
            raise BwError("nope")
    p = run([make_entry()], [managed("gone", iid="i9")], resolver=resolver)
    v = Failing()
    reconcile.apply(p, v)
    create = next(a for a in p.actions if a.kind == "create")
    assert create.ok is False and "nope" in create.error
    assert ("delete", "i9") in v.calls


def test_error_entry_does_not_prune_its_own_item(make_entry, resolver):
    p = run([make_entry(sopsKey="nope")], [managed("svc admin")], resolver=resolver)
    assert kinds(p) == [("error", "svc admin")]


def test_org_matched_case_insensitively(make_entry, resolver):
    orgs = [{"id": "o-lab", "name": "JeirsLab"}]
    p = reconcile.plan([make_entry(org="jeirslab")], organizations=orgs, collections_by_org=COLLS,
                       items_by_org={"o-lab": []}, resolver=resolver)
    assert kinds(p) == [("create", "svc admin")]
    assert p.actions[0].payload["organizationId"] == "o-lab"


def test_org_by_id_and_case_clash(make_entry, resolver):
    orgs = [{"id": "o-lab", "name": "lab"}, {"id": "o-lab2", "name": "LAB"}]
    p = reconcile.plan([make_entry(org="o-lab2")], organizations=orgs, collections_by_org=COLLS,
                       items_by_org={"o-lab2": []}, resolver=resolver)
    assert p.actions[-1].payload["organizationId"] == "o-lab2"
    with pytest.raises(reconcile.PlanError, match="several by case"):
        reconcile.plan([make_entry(org="Lab")], organizations=orgs, collections_by_org=COLLS,
                       items_by_org={}, resolver=resolver)
