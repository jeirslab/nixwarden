"""``nixwarden`` -- the operator CLI.

    nixwarden validate --manifest m.json
    nixwarden sync     --manifest m.json [--dry-run] [--no-prune] [--adopt]
    nixwarden status
    nixwarden collections [--org NAME]

Credentials come from flags, the environment, or ``--admin-file`` (a SOPS
file); see :mod:`nixwarden.credentials`. Nothing this command prints is ever
a secret value: plans name attributes, errors name files and keys.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import click

from nixwarden import __version__, credentials, manifest, reconcile, sops
from nixwarden.bw import BwError, Vault
from nixwarden.credentials import CredentialsError

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_INVALID = 2


def _fail(message: str, code: int = EXIT_RUNTIME) -> None:
    click.echo(f"nixwarden: {message}", err=True)
    sys.exit(code)


def _resolve_age_key(explicit: Path | None) -> None:
    """Point sops at an age identity when the caller named one.

    ``:=`` semantics: an operator who exported SOPS_AGE_KEY_FILE meant it.
    A named file that is not there is a warning, not an export -- pointing
    sops at a missing file would narrow its search rather than widen it.
    """
    if explicit is None or os.environ.get("SOPS_AGE_KEY_FILE"):
        return
    path = Path(os.path.expandvars(str(explicit))).expanduser()
    if path.is_file():
        os.environ["SOPS_AGE_KEY_FILE"] = str(path)
    else:
        click.echo(f"nixwarden: no age identity at {path}; falling back to sops' own search", err=True)


def _load_manifest(source: str) -> list[dict[str, Any]]:
    try:
        entries = manifest.load(source)
    except ValueError as exc:
        _fail(str(exc), EXIT_INVALID)
    problems = manifest.validate(entries)
    if problems:
        click.echo("nixwarden: invalid manifest:", err=True)
        for p in problems:
            click.echo(f"  - {p}", err=True)
        sys.exit(EXIT_INVALID)
    return manifest.resolve_paths(entries, Path.cwd())


def _vault(ctx: click.Context) -> Vault:
    opts = ctx.obj
    try:
        creds = credentials.resolve(url=opts["url"], admin_file=opts["admin_file"])
    except CredentialsError as exc:
        _fail(str(exc), EXIT_INVALID)
    return Vault(creds, appdata=opts["appdata"], bw=opts["bw"])


def _print_plan(plan_: reconcile.Plan) -> None:
    rows = [(a.kind, a.where, a.name or "-", a.type or "-", a.detail) for a in plan_.actions]
    if not rows:
        click.echo("nothing declared and nothing managed; the vault is untouched")
        return
    widths = [max(len(r[i]) for r in rows + [("ACTION", "ORG/COLLECTION", "NAME", "TYPE", "")]) for i in range(4)]
    click.echo("  ".join(h.ljust(w) for h, w in zip(("ACTION", "ORG/COLLECTION", "NAME", "TYPE"), widths)) + "  DETAIL")
    for r in rows:
        click.echo("  ".join(c.ljust(w) for c, w in zip(r[:4], widths)) + f"  {r[4]}")


def _summary(plan_: reconcile.Plan) -> str:
    parts = []
    for kind in ("create-collection", "create", "update", "recreate", "delete", "skip-prune",
                 "noop", "orphan", "conflict", "ambiguous", "error"):
        n = plan_.count(kind)
        if n:
            parts.append(f"{kind} {n}")
    return ", ".join(parts) or "nothing to do"


@click.group()
@click.version_option(__version__, prog_name="nixwarden")
@click.option("--url", metavar="URL", help="Vault server URL (or BITWARDEN_SERVER_URL).")
@click.option("--admin-file", type=click.Path(path_type=Path), metavar="SOPS_YAML",
              help="SOPS file holding server_url / client_id / client_secret / password.")
@click.option("--age-key-file", type=click.Path(path_type=Path), metavar="PATH",
              help="age identity for sops, if SOPS_AGE_KEY_FILE is not already set.")
@click.option("--appdata", type=click.Path(path_type=Path), metavar="DIR",
              help="Reuse a bw CLI data directory instead of a throwaway one.")
@click.option("--bw", default="bw", show_default=True, metavar="BIN", help="The Bitwarden CLI binary.")
@click.pass_context
def cli(ctx: click.Context, url: str | None, admin_file: Path | None, age_key_file: Path | None,
        appdata: Path | None, bw: str) -> None:
    """Mirror sops-declared secrets into a Bitwarden / Vaultwarden vault."""
    ctx.obj = {"url": url, "admin_file": admin_file, "appdata": appdata, "bw": bw}
    _resolve_age_key(age_key_file)


@cli.command("validate")
@click.option("--manifest", "manifest_source", required=True, metavar="FILE|-",
              help="Manifest JSON (`nix run .#bitwarden-manifest`), or - for stdin.")
def validate_command(manifest_source: str) -> None:
    """Check a manifest offline: no vault, no decryption."""
    entries = _load_manifest(manifest_source)
    orgs = sorted({e["org"] for e in entries})
    click.echo(f"manifest ok: {len(entries)} item(s) across {len(orgs)} organization(s)")


@cli.command("sync")
@click.option("--manifest", "manifest_source", required=True, metavar="FILE|-",
              help="Manifest JSON, or - for stdin.")
@click.option("--dry-run", is_flag=True, help="Plan and print; write nothing.")
@click.option("--no-prune", is_flag=True, help="Report managed items the manifest dropped, but keep them.")
@click.option("--adopt", is_flag=True,
              help="Take over an unmanaged item that has a declared name, adding the marker.")
@click.pass_context
def sync_command(ctx: click.Context, manifest_source: str, dry_run: bool, no_prune: bool, adopt: bool) -> None:
    """Make the vault match the manifest. THIS PRUNES: a managed item the
    manifest no longer declares is moved to the trash (restorable for 30
    days). --dry-run names every deletion first."""
    entries = _load_manifest(manifest_source)
    resolver = lambda file, key: sops.read_key(Path(file), key)  # noqa: E731

    try:
        with _vault(ctx) as vault:
            orgs = vault.organizations()
            org_ids = reconcile._match_organizations(sorted({e["org"] for e in entries}), orgs)
            collections = {oid: vault.org_collections(oid) for oid in org_ids.values()}
            existing = {oid: vault.items(oid) for oid in org_ids.values()}
            plan_ = reconcile.plan(
                entries,
                organizations=orgs,
                collections_by_org=collections,
                items_by_org=existing,
                resolver=resolver,
                prune=not no_prune,
                adopt=adopt,
            )
            _print_plan(plan_)
            click.echo("")
            click.echo(("dry run: " if dry_run else "plan: ") + _summary(plan_))
            if plan_.errors:
                click.echo(f"nixwarden: {len(plan_.errors)} problem(s) above must be resolved first", err=True)
                sys.exit(EXIT_INVALID)
            if dry_run or not plan_.writes:
                return
            reconcile.apply(plan_, vault)
    except (BwError, reconcile.PlanError, sops.SopsError) as exc:
        _fail(str(exc))

    failed = [a for a in plan_.writes if a.ok is False]
    for a in failed:
        click.echo(f"! {a.kind} {a.where} {a.name!r}: {a.error}", err=True)
    done = sum(1 for a in plan_.writes if a.ok)
    click.echo(f"applied: {done} write(s) ok, {len(failed)} failed")
    if failed:
        sys.exit(EXIT_RUNTIME)


@cli.command("status")
@click.pass_context
def status_command(ctx: click.Context) -> None:
    """Log in, unlock, and report what this login can see."""
    try:
        with _vault(ctx) as vault:
            st = vault.status()
            click.echo(f"server:  {st.get('serverUrl')}")
            click.echo(f"user:    {st.get('userEmail')}")
            click.echo(f"status:  {st.get('status')}")
            for org in sorted(vault.organizations(), key=lambda o: o["name"]):
                colls = vault.org_collections(org["id"])
                items = vault.items(org["id"])
                managed = sum(1 for i in items if i.get("fields") and any(
                    f.get("name") == manifest.MARKER_FIELD for f in i["fields"]))
                click.echo(f"org {org['name']!r}: {len(colls)} collection(s), "
                           f"{len(items)} item(s), {managed} managed by nixwarden")
    except BwError as exc:
        _fail(str(exc))


@cli.command("collections")
@click.option("--org", "org_name", metavar="NAME", help="Only this organization.")
@click.pass_context
def collections_command(ctx: click.Context, org_name: str | None) -> None:
    """List organizations and their collections (name -> id)."""
    try:
        with _vault(ctx) as vault:
            for org in sorted(vault.organizations(), key=lambda o: o["name"]):
                if org_name and org["name"] != org_name:
                    continue
                click.echo(f"[{org['name']}] {org['id']}")
                for c in sorted(vault.org_collections(org["id"]), key=lambda c: c["name"]):
                    click.echo(f"  {c['name']}  {c['id']}")
    except BwError as exc:
        _fail(str(exc))


def main() -> None:
    cli()
