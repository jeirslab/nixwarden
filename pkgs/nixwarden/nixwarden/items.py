"""From a manifest entry to the item ``bw`` will write, and back to something
comparable.

Two halves:

* :func:`desired_item` resolves every SOPS reference an entry carries and
  builds the JSON ``bw serve`` accepts for ``POST /object/item``. It is the
  only place values are assembled, so it is the only place that needs to be
  careful about them -- and it is careful: nothing here logs.
* :func:`shape` projects an item (desired or existing) onto the fields that
  matter for "is the vault already right", so :func:`changed_attributes` can
  name what differs -- ``login.password``, ``fields`` -- without ever saying
  how.

The marker field is what makes prune safe. Every item this tool writes
carries a custom field named ``nixwarden``; an item without it was made by a
person and is never updated or deleted, whatever its name.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from nixwarden.manifest import MARKER_FIELD, is_ref

__all__ = [
    "ItemError",
    "Resolver",
    "TYPE_CODES",
    "changed_attributes",
    "desired_item",
    "is_managed",
    "marker_field",
    "merge_for_update",
    "shape",
    "ssh_public",
]

#: Bitwarden's cipher type codes for the kinds this tool writes.
TYPE_CODES: dict[str, int] = {"login": 1, "note": 2, "ssh-key": 5}
FIELD_TEXT = 0
FIELD_HIDDEN = 1

#: ``(sops_file, sops_key) -> value``. The CLI passes ``sops.read_key``; the
#: tests pass a dict lookup.
Resolver = Callable[[str, str], str]


class ItemError(RuntimeError):
    pass


def marker_field(entry: dict[str, Any]) -> dict[str, Any]:
    """The managed marker: a text field naming the SOPS key the item mirrors.

    The value is provenance for a person reading the vault ("where does this
    come from?"), not part of the identity: :func:`is_managed` looks at the
    name only, so a key rename updates the marker rather than orphaning the
    item.
    """
    return {"name": MARKER_FIELD, "value": f"sops:{entry['sopsKey']}", "type": FIELD_TEXT}


def is_managed(item: dict[str, Any]) -> bool:
    return any(
        isinstance(f, dict) and f.get("name") == MARKER_FIELD
        for f in (item.get("fields") or [])
    )


def _resolve(entry: dict[str, Any], value: Any, resolver: Resolver) -> tuple[str, bool]:
    """A slot's value and whether it came from SOPS (and so is stored hidden)."""
    if is_ref(value):
        file = value.get("sopsFile") or entry["sopsFile"]
        return resolver(file, value["sopsKey"]), True
    return str(value), False


def ssh_public(private_key: str) -> tuple[str | None, str | None]:
    """Derive ``(public key, fingerprint)`` from an OpenSSH private key.

    Returns ``(None, None)`` when ``ssh-keygen`` is not on PATH -- the item is
    still written, with the private key alone, and the vault UI derives the
    rest on display. A key ``ssh-keygen`` cannot read is an error: a
    truncated file should be refused here, not discovered at fetch time.

    The key touches disk for the duration of two ``ssh-keygen`` calls, in a
    0700 directory as a 0600 file, because ``ssh-keygen -y`` reads a file
    and nothing else.
    """
    if shutil.which("ssh-keygen") is None:
        return None, None
    with tempfile.TemporaryDirectory(prefix="nixwarden-ssh-") as tmp:
        os.chmod(tmp, 0o700)
        path = Path(tmp) / "key"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(private_key.rstrip("\n") + "\n")
        pub = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(path)], capture_output=True, text=True, check=False
        )
        if pub.returncode != 0:
            raise ItemError("not a readable OpenSSH private key (ssh-keygen -y refused it)")
        fp = subprocess.run(
            ["ssh-keygen", "-lf", str(path)], capture_output=True, text=True, check=False
        )
    public = pub.stdout.strip()
    fingerprint = None
    if fp.returncode == 0:
        parts = fp.stdout.split()
        if len(parts) >= 2:
            fingerprint = parts[1]
    return public, fingerprint


def desired_item(entry: dict[str, Any], resolver: Resolver) -> dict[str, Any]:
    """The full item JSON for one manifest entry, values resolved.

    ``organizationId`` and ``collectionIds`` are left for the planner, which
    is the one that knows the ids. Everything else is final.
    """
    typ = entry["type"]
    if typ not in TYPE_CODES:
        raise ItemError(f"unknown item type {typ!r}")

    slots: dict[str, str | None] = {
        "password": None, "username": None, "totp": None, "notes": None, "privateKey": None,
    }
    slots[entry["field"]] = resolver(entry["sopsFile"], entry["sopsKey"])
    for slot in ("username", "totp", "notes"):
        if entry.get(slot) is not None:
            slots[slot], _ = _resolve(entry, entry[slot], resolver)

    fields: list[dict[str, Any]] = [marker_field(entry)]
    for f in entry.get("fields") or []:
        text, hidden = _resolve(entry, f["value"], resolver)
        fields.append({"name": f["name"], "value": text, "type": FIELD_HIDDEN if hidden else FIELD_TEXT})

    item: dict[str, Any] = {
        "organizationId": None,
        "collectionIds": [],
        "folderId": None,
        "type": TYPE_CODES[typ],
        "name": entry["name"],
        "notes": slots["notes"],
        "favorite": bool(entry.get("favorite", False)),
        "reprompt": 1 if entry.get("reprompt", False) else 0,
        "fields": fields,
        "login": None,
        "secureNote": None,
        "card": None,
        "identity": None,
        "sshKey": None,
    }
    if typ == "login":
        item["login"] = {
            "username": slots["username"],
            "password": slots["password"],
            "totp": slots["totp"],
            "uris": [{"match": None, "uri": u} for u in entry.get("uris") or []],
        }
    elif typ == "note":
        item["secureNote"] = {"type": 0}
    elif typ == "ssh-key":
        private = (slots["privateKey"] or "").rstrip("\n")
        public, fingerprint = ssh_public(private)
        item["sshKey"] = {"privateKey": private, "publicKey": public, "keyFingerprint": fingerprint}
    return item


def _s(value: Any) -> str | None:
    return None if value in (None, "") else str(value)


def shape(item: dict[str, Any]) -> dict[str, Any]:
    """The comparable projection of an item.

    Existing items carry ids, dates, revision history and nulls for every
    kind they are not; desired ones carry none of that. This keeps what a
    declaration can express and normalises the empty-string/null ambiguity
    ``bw`` introduces on the way back.
    """
    out: dict[str, Any] = {
        "type": item.get("type"),
        "name": item.get("name"),
        "notes": _s(item.get("notes")),
        "favorite": bool(item.get("favorite")),
        "reprompt": int(item.get("reprompt") or 0),
        "fields": sorted(
            (str(f.get("name")), _s(f.get("value")), int(f.get("type") or 0))
            for f in (item.get("fields") or [])
            if isinstance(f, dict)
        ),
        "collections": sorted(item.get("collectionIds") or []),
    }
    login = item.get("login")
    if isinstance(login, dict):
        out["login"] = {
            "username": _s(login.get("username")),
            "password": _s(login.get("password")),
            "totp": _s(login.get("totp")),
            "uris": [u.get("uri") for u in (login.get("uris") or []) if isinstance(u, dict)],
        }
    ssh = item.get("sshKey")
    if isinstance(ssh, dict):
        out["sshKey"] = {
            "privateKey": _s((ssh.get("privateKey") or "").rstrip("\n")),
            "publicKey": _s(ssh.get("publicKey")),
            "keyFingerprint": _s(ssh.get("keyFingerprint")),
        }
    return out


def changed_attributes(desired: dict[str, Any], existing: dict[str, Any]) -> list[str]:
    """Names of the attributes that differ between two shapes. Never values."""
    changed: list[str] = []
    for key in ("type", "name", "notes", "favorite", "reprompt", "fields", "collections"):
        if desired.get(key) != existing.get(key):
            changed.append(key)
    for group in ("login", "sshKey"):
        d, e = desired.get(group), existing.get(group)
        if d is None and e is None:
            continue
        if d is None or e is None:
            changed.append(group)
            continue
        for key in d:
            # Without ssh-keygen the desired public half is unknown; do not
            # report a difference that is only our own ignorance.
            if group == "sshKey" and key in ("publicKey", "keyFingerprint") and d[key] is None:
                continue
            if d[key] != e.get(key):
                changed.append(f"{group}.{key}")
    return changed


def merge_for_update(existing: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    """The body for ``PUT /object/item/<id>``: the existing item with every
    declared attribute replaced. Ids, dates and the like ride through."""
    merged = dict(existing)
    for key in ("type", "name", "notes", "favorite", "reprompt", "fields",
                "login", "secureNote", "sshKey", "organizationId", "collectionIds"):
        merged[key] = desired[key]
    return merged
