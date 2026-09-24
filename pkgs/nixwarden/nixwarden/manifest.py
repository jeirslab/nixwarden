"""Loading and validation of the declarative vault manifest.

The manifest is a JSON array produced by the Nix half of this repo from the
NixOS configurations of the estate (``nixwarden.lib.manifestOf``). It is the
single source of truth for which items the vault should contain; ``reconcile``
makes the vault match it.

An entry looks like::

    {
      "sopsKey":    "authentik/admin_password",
      "sopsFile":   "/nix/store/…-source/secrets/idp.yaml",
      "hosts":      ["idp"],
      "org":        "jeirslab",
      "collection": "infrastructure",
      "name":       "Authentik admin",
      "type":       "login",
      "field":      "password",
      "username":   {"sopsKey": "authentik/admin_user", "sopsFile": null},
      "uris":       ["https://auth.jeirslab.xyz"],
      "totp":       null,
      "notes":      null,
      "fields":     [{"name": "api url", "value": "https://…"}],
      "favorite":   false,
      "reprompt":   false
    }

The anchored secret (``sopsKey`` in ``sopsFile``) lands in ``field``. Every
other slot is a literal string or a *ref* -- ``{"sopsKey", "sopsFile"}`` --
resolved at sync time; a ref with ``sopsFile: null`` reads the entry's own
file.

Validation is a separate pass returning *all* problems rather than raising on
the first: a manifest is generated wholesale, so an operator wants the full
list, not a game of whack-a-mole across regeneration cycles. It repeats what
``nixwarden.lib.assertManifest`` checks at eval time, for anyone consuming
the manifest outside Nix.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "TYPES",
    "FIELDS",
    "FIELDS_FOR",
    "MARKER_FIELD",
    "REQUIRED_FIELDS",
    "coordinate",
    "entry_label",
    "is_ref",
    "load",
    "resolve_paths",
    "validate",
]

#: Item kinds the reconciler knows how to write, and the slots each accepts.
TYPES: tuple[str, ...] = ("login", "note", "ssh-key")
FIELDS: tuple[str, ...] = ("password", "username", "totp", "notes", "privateKey")
FIELDS_FOR: dict[str, tuple[str, ...]] = {
    "login": ("password", "username", "totp", "notes"),
    "note": ("notes",),
    "ssh-key": ("privateKey", "notes"),
}

#: The custom field the reconciler stamps on every item it writes, and the
#: only thing it will ever prune. A person's hand-made item in the same
#: collection has no such field and is never touched.
MARKER_FIELD = "nixwarden"

REQUIRED_FIELDS: tuple[str, ...] = (
    "sopsKey",
    "org",
    "collection",
    "name",
    "type",
    "field",
)


def is_ref(value: Any) -> bool:
    return isinstance(value, dict) and "sopsKey" in value


def coordinate(entry: dict[str, Any]) -> str:
    """``org/collection:name`` -- the identity an item is matched on."""
    return f"{entry.get('org', '?')}/{entry.get('collection', '?')}:{entry.get('name', '?')}"


def entry_label(entry: dict[str, Any], index: int) -> str:
    """A stable, secret-free identifier for an entry, for error messages."""
    key = entry.get("sopsKey")
    if isinstance(key, str) and key:
        return f"entry[{index}] sopsKey={key!r}"
    return f"entry[{index}]"


def load(source: str | Path) -> list[dict[str, Any]]:
    """Read a manifest from a JSON file, or from stdin when ``source`` is ``-``."""
    if str(source) == "-":
        raw = sys.stdin.read()
        origin = "<stdin>"
    else:
        path = Path(source)
        if not path.is_file():
            raise ValueError(f"manifest not found: {path}")
        raw = path.read_text(encoding="utf-8")
        origin = str(path)

    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest {origin} is not valid JSON: {exc}") from exc
    if not isinstance(document, list):
        raise ValueError(f"manifest {origin} must be a JSON array of entries")

    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest {origin} entry[{index}] is not an object")
        entries.append(entry)
    return entries


def _value_problems(label: str, slot: str, value: Any) -> list[str]:
    if value is None or isinstance(value, str):
        return []
    if is_ref(value):
        key = value.get("sopsKey")
        if not isinstance(key, str) or not key:
            return [f"{label}: {slot} ref has an empty sopsKey"]
        file = value.get("sopsFile")
        if file is not None and not isinstance(file, str):
            return [f"{label}: {slot} ref sopsFile must be a string or null"]
        return []
    return [f"{label}: {slot} must be a string, a ref, or null"]


def validate(entries: Iterable[dict[str, Any]]) -> list[str]:
    """Return every problem with the manifest; an empty list means valid."""
    problems: list[str] = []
    seen: dict[str, str] = {}

    for index, entry in enumerate(entries):
        label = entry_label(entry, index)

        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if not isinstance(value, str) or not value:
                problems.append(f"{label}: missing or empty {field!r}")
        sops_file = entry.get("sopsFile")
        if not isinstance(sops_file, str) or not sops_file:
            problems.append(
                f"{label}: no sopsFile (set sops.defaultSopsFile or a per-secret sopsFile)"
            )

        typ = entry.get("type")
        field = entry.get("field")
        if isinstance(typ, str) and typ not in TYPES:
            problems.append(f"{label}: type {typ!r} is not one of {', '.join(TYPES)}")
        elif isinstance(typ, str) and isinstance(field, str) and field not in FIELDS_FOR[typ]:
            problems.append(f"{label}: field {field!r} is not valid for a {typ} item")

        if typ != "login":
            if entry.get("username") is not None or entry.get("totp") is not None or entry.get("uris"):
                problems.append(f"{label}: username, totp and uris only apply to login items")

        for slot in ("username", "totp", "notes"):
            problems.extend(_value_problems(label, slot, entry.get(slot)))
            if field == slot and entry.get(slot) is not None:
                problems.append(f"{label}: the anchored value and a declared {slot} both target the same slot")

        uris = entry.get("uris", [])
        if not isinstance(uris, list) or any(not isinstance(u, str) for u in uris):
            problems.append(f"{label}: uris must be a list of strings")

        fields = entry.get("fields", [])
        if not isinstance(fields, list):
            problems.append(f"{label}: fields must be a list")
        else:
            names: set[str] = set()
            for f in fields:
                if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not f["name"]:
                    problems.append(f"{label}: every custom field needs a name")
                    continue
                if f["name"] == MARKER_FIELD:
                    problems.append(f"{label}: custom field {MARKER_FIELD!r} is reserved for the managed marker")
                if f["name"] in names:
                    problems.append(f"{label}: custom field {f['name']!r} declared twice")
                names.add(f["name"])
                problems.extend(_value_problems(label, f"fields.{f['name']}", f.get("value")))

        for flag in ("favorite", "reprompt"):
            if flag in entry and not isinstance(entry[flag], bool):
                problems.append(f"{label}: {flag} must be a boolean")

        hosts = entry.get("hosts", [])
        if not isinstance(hosts, list):
            problems.append(f"{label}: hosts must be a list")

        coord = coordinate(entry)
        if all(isinstance(entry.get(k), str) and entry[k] for k in ("org", "collection", "name")):
            if coord in seen:
                problems.append(f"{label}: same vault item as {seen[coord]} ({coord})")
            else:
                seen[coord] = label

    return problems


def resolve_paths(entries: list[dict[str, Any]], base: Path) -> list[dict[str, Any]]:
    """Make every ``sopsFile`` (entry and ref) absolute, relative to ``base``.

    A manifest rendered by Nix carries store paths, which are absolute already.
    A hand-written one, or one from a test, may not be; resolving here means
    the rest of the code never has to ask.
    """
    out: list[dict[str, Any]] = []
    for entry in entries:
        e = dict(entry)
        if isinstance(e.get("sopsFile"), str):
            e["sopsFile"] = str((base / e["sopsFile"]).resolve()) if not Path(e["sopsFile"]).is_absolute() else e["sopsFile"]
        for slot in ("username", "totp", "notes"):
            v = e.get(slot)
            if is_ref(v) and isinstance(v.get("sopsFile"), str) and not Path(v["sopsFile"]).is_absolute():
                e[slot] = {**v, "sopsFile": str((base / v["sopsFile"]).resolve())}
        fields = []
        for f in e.get("fields", []) or []:
            v = f.get("value") if isinstance(f, dict) else None
            if is_ref(v) and isinstance(v.get("sopsFile"), str) and not Path(v["sopsFile"]).is_absolute():
                fields.append({**f, "value": {**v, "sopsFile": str((base / v["sopsFile"]).resolve())}})
            else:
                fields.append(f)
        e["fields"] = fields
        out.append(e)
    return out
