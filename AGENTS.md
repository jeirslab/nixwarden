# AGENTS.md — nixwarden

Mirror sops-declared secrets into a Bitwarden / Vaultwarden vault. SOPS stays
the source of truth; the vault is the person-facing view of it — the place a
bootstrapped admin password can be found, in the right org and collection,
without anyone pasting it there.

This file is the entry point when nixwarden is consumed as a flake input and
you have no checkout of it.

## 1. What can be declared — a file, not a server

```sh
nix build github:jeirslab/nixwarden#docs
```

Produces `index.md`, `options.json`, `options.md`, `commands.md`: every
option the NixOS module declares and the CLI's full `--help`, generated from
the module system and the click tree rather than written beside them.

No credentials, no network, no vault.

## 2. The three surfaces

- **Declare** — `sops.secrets.<key>.bitwarden = nixwarden.lib.mkLogin { … }`
  on a host, or `nixwarden.lib.mkExportOnly { sopsFile; sopsKey; … }` for a
  credential no host consumes. `org` and `collection` are names, never ids.
- **Render** — `nix run .#bitwarden-manifest -- table`. Structure only: SOPS
  key paths and routing, no values, safe to `nix build` and to show anyone.
- **Sync** — `nix run .#bitwarden-sync -- --dry-run`, then without. Decrypts
  on the operator's machine with their age key, writes through a throwaway
  `bw serve`, prunes what the manifest dropped (to the trash, never past it).

## 3. Rules that are not obvious from the code

- **The marker field is the contract.** Every item nixwarden writes carries
  a custom field named `nixwarden`. An item without it was made by a person:
  never updated, never pruned, and a declared name that collides with one
  is a `conflict` until `--adopt` is passed on purpose.
- **Four credentials, not two.** Server URL and API key log the CLI in; the
  master password unlocks the vault. Items are end-to-end encrypted with a
  key derived from it, and the API key alone cannot read or write one. The
  Public API that needs no master password manages members and collections,
  not items. `nixwarden.credentials` says where each comes from.
- **Nothing printed is ever a value.** Plans name attributes
  (`login.password`, `fields`); errors name files and key paths. Keep it so.
- **Importing the export module rebuilds every sops host once.** sops-nix
  serialises the whole submodule into its manifest, unknown fields included.
  Import it in the same change as the first annotations.
- **Prune is scoped to managed collections.** Dropping the last declaration
  from a collection stops nixwarden touching that collection; leftovers there
  are reported as `orphan`, not deleted.

## 4. Working in this repo

- `nix flake check` runs the Python suite (offline), builds the docs, builds
  the sync app under shellcheck, and asserts a fixture fleet's manifest.
- `pytest pkgs/nixwarden` inside `nix develop` for the fast loop. The sops
  and ssh-keygen suites skip themselves when the binary is absent.
- Anything needing a live vault is an operation, not a check. Do it with
  `--dry-run` first, against `nixwarden status`.
