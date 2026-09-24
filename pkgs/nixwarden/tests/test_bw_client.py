"""The REST half of :class:`nixwarden.bw.Vault`, against a fake ``bw serve``.

No process is spawned: an ``httpx.MockTransport`` plays the daemon, so what is
tested is the request shapes and the unwrapping of ``{success, data}``.
"""

from __future__ import annotations

import json

import httpx
import pytest

from nixwarden.bw import BwError, Vault
from nixwarden.credentials import Credentials

CREDS = Credentials("https://vault.example", "user.1", "s", "pw")


def make_vault(handler):
    client = httpx.Client(base_url="http://127.0.0.1:1", transport=httpx.MockTransport(handler))
    return Vault(CREDS, client=client)


def ok(data):
    return httpx.Response(200, json={"success": True, "data": data})


def test_list_unwraps_double_data():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"] = str(req.url)
        return ok({"object": "list", "data": [{"id": "o1", "name": "lab"}]})

    v = make_vault(handler)
    assert v.organizations() == [{"id": "o1", "name": "lab"}]
    assert seen["url"].endswith("/list/object/organizations")


def test_items_and_collections_pass_org_id():
    urls = []

    def handler(req):
        urls.append(str(req.url))
        return ok({"object": "list", "data": []})

    v = make_vault(handler)
    v.items("o1")
    v.org_collections("o1")
    assert "list/object/items?organizationId=o1" in urls[0]
    assert "list/object/org-collections?organizationId=o1" in urls[1]


def test_failure_message_is_surfaced_without_body():
    def handler(req):
        return httpx.Response(400, json={"success": False, "message": "Invalid master password."})

    v = make_vault(handler)
    with pytest.raises(BwError, match="Invalid master password"):
        v.organizations()


def test_non_json_is_an_error():
    v = make_vault(lambda req: httpx.Response(502, text="bad gateway"))
    with pytest.raises(BwError, match="non-JSON"):
        v.organizations()


def test_create_collection_shape():
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        seen["body"] = json.loads(req.content)
        return ok({"id": "c1", "name": "infra"})

    v = make_vault(handler)
    assert v.create_org_collection("o1", "infra")["id"] == "c1"
    assert "object/org-collection?organizationId=o1" in seen["url"]
    assert seen["body"] == {"organizationId": "o1", "name": "infra", "externalId": None, "groups": []}
    assert "users" not in seen["body"]


def test_delete_is_soft_by_default():
    seen = {}

    def handler(req):
        seen["method"], seen["url"] = req.method, str(req.url)
        return ok(None)

    v = make_vault(handler)
    v.delete_item("i1")
    assert seen["method"] == "DELETE" and seen["url"].endswith("/object/item/i1")
    v.delete_item("i1", permanent=True)
    assert "permanent=true" in seen["url"]


def test_update_puts_full_item():
    seen = {}

    def handler(req):
        seen["method"], seen["url"], seen["body"] = req.method, str(req.url), json.loads(req.content)
        return ok(seen["body"])

    v = make_vault(handler)
    v.update_item("i1", {"name": "x", "id": "i1"})
    assert seen["method"] == "PUT" and seen["url"].endswith("/object/item/i1") and seen["body"]["id"] == "i1"
