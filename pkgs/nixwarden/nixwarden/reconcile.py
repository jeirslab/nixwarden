"""Make the vault match the manifest.

Two phases, deliberately separate:

* :func:`plan` is PURE. It takes the manifest and a snapshot of the vault
  (organizations, their collections, their items) plus a value resolver, and
  returns a list of actions. Nothing here talks to a network, which is what
  makes every branch of the decision table testable with a dict.
* :func:`apply` walks the plan against a live :class:`~nixwarden.bw.Vault`.
  It refuses to start if the plan carries a single error: a sync that writes
  half the fleet and then stops on a conflict leaves the operator guessing
  which half.

The decision table, per manifest entry, keyed on what already sits at
``(collection, name)``:

=====================================  ==========================================
found                                  action
=====================================  ==========================================
nothing                                ``create``
one managed item, same type, same      ``noop``
one managed item, differs              ``update`` (names the attributes)
one managed item, different type       ``recreate`` (trash + create; types are
                                       not editable in Bitwarden)
one unmanaged item                     ``conflict`` -- unless ``--adopt``, then
                                       ``update`` with the marker added
several managed items                  ``ambiguous`` -- a person has to pick
=====================================  ==========================================

Then prune: a managed item in a *managed collection* (one the manifest
declares at least one entry into) that no entry claims is trashed. A managed
item anywhere else is reported as an ``orphan`` and left alone -- removing
the last declaration from a collection stops this tool from touching that
collection at all, which is the safe reading of "I stopped declaring things
there".

Items go to the trash, never past it. Bitwarden keeps them thirty days.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nixwarden import items as it
from nixwarden.bw import BwError, Vault
from nixwarden.manifest import MARKER_FIELD
from nixwarden.sops import SopsError

__all__ = ["Action", "Plan", "PlanError", "apply", "plan"]

#: Kinds that mean "nothing will be written until a person acts".
ERROR_KINDS = ("conflict", "ambiguous", "error")
#: Kinds that write.
WRITE_KINDS = ("create-collection", "create", "update", "recreate", "delete")


class PlanError(RuntimeError):
    pass


@dataclass
class Action:
    kind: str
    org: str
    collection: str
    name: str
    type: str | None = None
    detail: str = ""
    existing_id: str | None = None
    payload: dict[str, Any] | None = field(default=None, repr=False)
    #: For entries in a collection that does not exist yet: which pending
    #: collection the payload's ``collectionIds`` must be patched with.
    pending_collection: tuple[str, str] | None = None
    ok: bool | None = None
    error: str | None = None

    @property
    def where(self) -> str:
        return f"{self.org}/{self.collection}"


@dataclass
class Plan:
    actions: list[Action]

    @property
    def errors(self) -> list[Action]:
        return [a for a in self.actions if a.kind in ERROR_KINDS]

    @property
    def writes(self) -> list[Action]:
        return [a for a in self.actions if a.kind in WRITE_KINDS]

    def count(self, kind: str) -> int:
        return sum(1 for a in self.actions if a.kind == kind)


def _type_word(code: Any) -> str | None:
    for word, num in it.TYPE_CODES.items():
        if num == code:
            return word
    return None


def _match_organizations(wanted: list[str], organizations: list[dict[str, Any]]) -> dict[str, str]:
    """Declared org name -> id.

    Exact name first, then case-insensitive if that is unique, then an id
    given verbatim. A vault shows "JeirsLab" where every declaration says
    "jeirslab", and making the person spell the vault's capitalisation is
    not a security boundary, just friction. Two orgs whose names differ only
    in case is a real ambiguity and is reported as one.
    """
    by_name = {o["name"]: o["id"] for o in organizations}
    by_id = {o["id"] for o in organizations}
    result: dict[str, str] = {}
    unknown: list[str] = []
    for name in wanted:
        if name in by_name:
            result[name] = by_name[name]
            continue
        if name in by_id:
            result[name] = name
            continue
        folded = [o for o in organizations if o["name"].casefold() == name.casefold()]
        if len(folded) == 1:
            result[name] = folded[0]["id"]
        elif len(folded) > 1:
            raise PlanError(
                f"organization {name!r} matches several by case: "
                + ", ".join(repr(o["name"]) for o in folded)
            )
        else:
            unknown.append(name)
    if unknown:
        known = ", ".join(sorted(by_name)) or "none"
        raise PlanError(
            f"organization(s) not visible to this login: {', '.join(unknown)} (visible: {known})"
        )
    return result


def plan(
    entries: list[dict[str, Any]],
    *,
    organizations: list[dict[str, Any]],
    collections_by_org: dict[str, list[dict[str, Any]]],
    items_by_org: dict[str, list[dict[str, Any]]],
    resolver: it.Resolver,
    prune: bool = True,
    adopt: bool = False,
) -> Plan:
    wanted_orgs = sorted({e["org"] for e in entries})
    org_ids = _match_organizations(wanted_orgs, organizations)

    actions: list[Action] = []

    # Collections: name -> id per org, plus the ones to create.
    coll_ids: dict[str, dict[str, str]] = {}
    for org in wanted_orgs:
        oid = org_ids[org]
        coll_ids[org] = {c["name"]: c["id"] for c in collections_by_org.get(oid, [])}
        for name in sorted({e["collection"] for e in entries if e["org"] == org}):
            if name not in coll_ids[org]:
                actions.append(Action("create-collection", org, name, "", detail="missing",
                                      payload={"organizationId": oid}))

    # Index existing items by (collection id, name).
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for org in wanted_orgs:
        for item in items_by_org.get(org_ids[org], []):
            if item.get("deletedDate"):
                continue
            for cid in item.get("collectionIds") or []:
                index.setdefault((cid, item.get("name", "")), []).append(item)

    claimed: set[str] = set()  # ids of existing items some entry keeps

    for entry in entries:
        org, coll, name = entry["org"], entry["collection"], entry["name"]
        oid = org_ids[org]
        cid = coll_ids[org].get(coll)
        pending = None if cid is not None else (org, coll)

        matches = index.get((cid, name), []) if cid is not None else []
        managed = [m for m in matches if it.is_managed(m)]
        unmanaged = [m for m in matches if not it.is_managed(m)]
        # Spoken for, whatever happens below: a managed item carrying a
        # declared name is never a prune candidate, even when this entry
        # ends in an error or an ambiguity -- a plan that cannot decide
        # between two items must not propose trashing both.
        claimed.update(m["id"] for m in managed)

        try:
            desired = it.desired_item(entry, resolver)
        except (SopsError, it.ItemError) as exc:
            actions.append(Action("error", org, coll, name, entry["type"], detail=str(exc)))
            continue
        desired["organizationId"] = oid
        desired["collectionIds"] = [cid] if cid is not None else []

        if len(managed) > 1:
            ids = ", ".join(m.get("id", "?") for m in managed)
            actions.append(Action("ambiguous", org, coll, name, entry["type"],
                                  detail=f"{len(managed)} managed items share this name ({ids})"))
            continue

        existing: dict[str, Any] | None = None
        adopting = False
        if managed:
            existing = managed[0]
        elif unmanaged:
            if not adopt:
                actions.append(Action("conflict", org, coll, name, entry["type"],
                                      detail="an item with this name exists here and is not managed by "
                                             "nixwarden (re-run with --adopt to take it over)",
                                      existing_id=unmanaged[0].get("id")))
                continue
            if len(unmanaged) > 1:
                actions.append(Action("ambiguous", org, coll, name, entry["type"],
                                      detail=f"{len(unmanaged)} unmanaged items share this name; "
                                             "cannot pick one to adopt"))
                continue
            existing = unmanaged[0]
            adopting = True

        if existing is None:
            actions.append(Action("create", org, coll, name, entry["type"],
                                  payload=desired, pending_collection=pending))
            continue

        if existing.get("type") != desired["type"]:
            actions.append(Action("recreate", org, coll, name, entry["type"],
                                  detail=f"type {_type_word(existing.get('type'))} -> {entry['type']}",
                                  existing_id=existing["id"], payload=desired))
            continue
        diff = it.changed_attributes(it.shape(desired), it.shape(existing))
        if adopting:
            diff = ["adopt"] + diff
        if diff:
            actions.append(Action("update", org, coll, name, entry["type"],
                                  detail=", ".join(diff), existing_id=existing["id"],
                                  payload=it.merge_for_update(existing, desired)))
        else:
            actions.append(Action("noop", org, coll, name, entry["type"], existing_id=existing["id"]))

    # Prune.
    managed_cids: dict[str, set[str]] = {}
    for entry in entries:
        cid = coll_ids[entry["org"]].get(entry["collection"])
        if cid is not None:
            managed_cids.setdefault(entry["org"], set()).add(cid)
    for org in wanted_orgs:
        oid = org_ids[org]
        names_by_cid = {cid: name for name, cid in coll_ids[org].items()}
        seen: set[str] = set()
        for item in items_by_org.get(oid, []):
            iid = item.get("id", "")
            if item.get("deletedDate") or not it.is_managed(item) or iid in claimed or iid in seen:
                continue
            seen.add(iid)
            cids = item.get("collectionIds") or []
            where = ", ".join(names_by_cid.get(c, c) for c in cids) or "(no collection)"
            provenance = next((f.get("value") for f in item.get("fields") or []
                               if isinstance(f, dict) and f.get("name") == MARKER_FIELD), "")
            typ = _type_word(item.get("type"))
            if any(c in managed_cids.get(org, set()) for c in cids):
                kind = "delete" if prune else "skip-prune"
                actions.append(Action(kind, org, where, item.get("name", ""), typ,
                                      detail=f"no longer declared ({provenance})", existing_id=iid))
            else:
                actions.append(Action("orphan", org, where, item.get("name", ""), typ,
                                      detail=f"managed item in an undeclared collection ({provenance})",
                                      existing_id=iid))

    actions.sort(key=lambda a: (a.org, a.collection, a.name, a.kind))
    return Plan(actions)


def apply(plan_: Plan, vault: Vault) -> Plan:
    """Execute every write in the plan, in dependency order. Marks each action
    ``ok`` or records its ``error``; keeps going past a failed item so one
    bad entry does not hold the rest of the fleet hostage."""
    if plan_.errors:
        raise PlanError(f"{len(plan_.errors)} problem(s) in the plan; nothing written")

    created: dict[tuple[str, str], str] = {}
    for a in plan_.actions:
        if a.kind != "create-collection":
            continue
        assert a.payload is not None
        try:
            made = vault.create_org_collection(a.payload["organizationId"], a.collection)
            created[(a.org, a.collection)] = made["id"]
            a.ok = True
        except (BwError, KeyError, TypeError) as exc:
            a.ok, a.error = False, str(exc)

    for a in plan_.actions:
        if a.kind not in ("create", "update", "recreate", "delete"):
            continue
        try:
            if a.pending_collection is not None:
                cid = created.get(a.pending_collection)
                if cid is None:
                    raise BwError("its collection could not be created")
                assert a.payload is not None
                a.payload["collectionIds"] = [cid]
            if a.kind == "create":
                assert a.payload is not None
                vault.create_item(a.payload)
            elif a.kind == "update":
                assert a.payload is not None and a.existing_id is not None
                vault.update_item(a.existing_id, a.payload)
            elif a.kind == "recreate":
                assert a.payload is not None and a.existing_id is not None
                vault.delete_item(a.existing_id)
                vault.create_item(a.payload)
            elif a.kind == "delete":
                assert a.existing_id is not None
                vault.delete_item(a.existing_id)
            a.ok = True
        except BwError as exc:
            a.ok, a.error = False, str(exc)
    return plan_
