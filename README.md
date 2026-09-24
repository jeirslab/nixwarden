# nixwarden

Declarative Bitwarden / Vaultwarden mirroring for NixOS fleets. Annotate a
`sops.secrets` entry with where it belongs in the vault; `nixwarden sync`
puts it there — as a login, a secure note, or an SSH key, in the right
organization and collection — and keeps it there.

The problem it solves: a bootstrap generates an admin password into a SOPS
file, the host consumes it, and the person who has to log in with it goes
looking in the vault and finds nothing. With nixwarden the declaration that
made the secret also says which vault item it is, and the item exists the
next time the sync runs.

The sibling of [nixfisical](https://github.com/jeirslab/nixfisical), same
shape: SOPS is the source of truth, the manifest is structure only, the CLI
decrypts on the operator's machine at run time, and the declaration is the
single place a secret's routing lives.

## Declaring

Import the module on every host you want to mirror from, and annotate:

```nix
# flake.nix
inputs.nixwarden.url = "github:jeirslab/nixwarden";

# in a host's modules
{ nixwarden, ... }: {
  imports = [ nixwarden.nixosModules.export ];

  sops.secrets."authentik/admin_password".bitwarden = nixwarden.lib.mkLogin {
    org        = "jeirslab";                              # names, as the vault shows them
    collection = "infrastructure";
    name       = "Authentik admin";
    username   = nixwarden.lib.ref "authentik/admin_user";  # another key in the same file
    uris       = [ "https://auth.jeirslab.xyz" ];
  };

  sops.secrets."deploy_key".bitwarden = nixwarden.lib.mkSshKey {
    org = "jeirslab"; collection = "infrastructure/sops-decrypt"; name = "deploy key";
  };
}
```

For a credential no host consumes — the usual case for a bootstrapped
*person's* password — name the file and key directly:

```nix
nixwarden.lib.mkExportOnly {
  sopsFile   = ./secrets/nextcloud.yaml;
  sopsKey    = "admin_password";
  org        = "jeirslab";
  collection = "infrastructure";
  name       = "Nextcloud admin";
  username   = "admin";
  uris       = [ "https://nextcloud.jeirslab.xyz" ];
}
```

One annotated secret is one vault item. Its value lands in `field` (the
password of a login, the body of a note, the private key of an SSH key). Every
other slot — `username`, `totp`, `notes`, a custom field — is either a literal
string or a `ref` to another SOPS key, resolved at sync time. A value that
arrives through a `ref` is stored hidden; a literal is stored as text.

`org` and `collection` have no defaults: together they decide who can see the
item. A missing collection is created on the first sync; a missing
organization is an error, because membership is not this tool's to grant.

## Rendering and syncing

```nix
packages.${system} = {
  bitwarden-manifest = nixwarden.mkManifestApp {
    inherit pkgs;
    inherit (self) nixosConfigurations;
    extraSecrets = [ /* mkExportOnly results */ ];
  };
  bitwarden-sync = nixwarden.mkSyncApp {
    inherit pkgs;
    inherit (self) nixosConfigurations;
    extraSecrets = [ /* the same list */ ];
    url = "https://vault.jeirslab.xyz";
    adminFile  = "secrets/bitwarden-admin.yaml";   # optional; else the environment
    ageKeyFile = "\${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt";
  };
};
```

```sh
nix run .#bitwarden-manifest -- table   # what would be mirrored, no values
nix run .#bitwarden-sync -- --dry-run   # the plan: create / update / delete / conflict
nix run .#bitwarden-sync                # converge
```

The manifest is JSON built at eval time. It names SOPS files and key paths
and says where each lands; it carries no decrypted value, so it is safe to
`nix build` and to hand to someone who cannot read the secrets it describes.

**`sync` prunes.** A managed item the manifest no longer declares is moved
to the vault's trash on the next run, where Bitwarden keeps it for thirty
days. `--dry-run` names every deletion; `--no-prune` reports them and keeps
them.

**`sync` never touches a person's items.** Every item nixwarden writes
carries a custom field named `nixwarden`. An item without it — one someone
made by hand — is never updated or pruned, and a declared name that collides
with one is reported as a `conflict`. `--adopt` takes such an item over,
deliberately.

## Credentials

Four values, and there is no getting below four:

| value                | environment                               | admin file key  |
| -------------------- | ----------------------------------------- | --------------- |
| server URL           | `BITWARDEN_SERVER_URL` (or `--url`)       | `server_url`    |
| API key client id    | `BW_CLIENTID`                             | `client_id`     |
| API key secret       | `BW_CLIENTSECRET`                         | `client_secret` |
| master password      | `BITWARDEN_USER_PASSWORD` / `BW_PASSWORD` | `password`      |

The API key (web vault → Settings → Security → Keys → *View API key*) logs
the CLI in without a browser or 2FA prompt. The master password is still
required: vault items are end-to-end encrypted with a key derived from it,
and no API credential can encrypt an item without it. Bitwarden's Public API,
which needs no master password, manages members and collections — not items.

Environment variables win over the admin file, field by field. The admin
file is a SOPS-encrypted YAML with those four keys at the top level; keep it
encrypted to the same age key as the fleet's secrets, so whoever can run the
sync can read it and nobody else can. The same `.env` the nexus key scripts
use works unchanged.

The CLI runs `bw` against a throwaway state directory: your own `bw` login,
on whatever server, is neither read nor disturbed. Pass `--appdata DIR` to
keep one across runs. Each run pays one login and one full vault sync, which
is most of the twenty to forty seconds a `status` takes.

**The `bw` version is pinned on purpose.** bitwarden-cli 2026.9.0 answers
`bw serve`'s unlock with an HTTP 500 from inside its SDK against a current
Vaultwarden; 2026.8.0 and 2026.6.0 do not. The flake takes `bw` from a
separate `nixpkgs-bw` input for that reason (the comment there has the
details), and `--bw PATH` overrides it for anyone who wants to try another.

## The CLI on its own

```
nixwarden validate --manifest m.json          # offline
nixwarden sync --manifest m.json --dry-run    # plan
nixwarden sync --manifest m.json              # converge
nixwarden status                              # what this login sees
nixwarden collections [--org NAME]            # name -> id, per organization
```

`nix run github:jeirslab/nixwarden -- --help`. `nix build .#docs` renders
every option and every command to Markdown without a checkout or a vault.

## What it deliberately does not do

- **Run the vault.** nixpkgs has `services.vaultwarden`; use it.
- **Pull values back.** SOPS is the truth. Rotating a password in the vault
  UI does not change the file, and the next sync puts the file's value back.
  That is the contract, and the reason the marker field exists: a person's
  own items are never in that loop.
- **Grant access.** A created collection is visible to the creating user and
  to org owners/admins. Who else reads it is decided in the vault UI.
- **Write to a personal vault.** Items live in an organization. Personal
  folders would need a different identity model and nobody has asked.

## Costs worth knowing

Importing `nixosModules.export` rebuilds every host that uses sops-nix, once,
annotated or not — sops-nix serialises the whole `sops.secrets` submodule
into its on-host manifest, unknown fields included. The activation is a
no-op; the deploy is not. Import it in the same change as the first
annotations. nixfisical's export module has the same cost and the two stack.

Routing metadata (org, collection, item name, a literal username, uris) ends
up in world-readable store paths on each host. It names no values. If an
item name is itself sensitive, that is where it leaks.

## Layout

```
flake.nix               lib, nixosModules, overlay, mkManifestApp, mkSyncApp, checks
nix/lib/default.nix     mkBitwarden/mkLogin/mkNote/mkSshKey, ref, mkExportOnly,
                        manifestOf/manifestFrom, assertManifest
nix/modules/export.nix  sops.secrets.<key>.bitwarden
nix/modules/sops-stub.nix  sops-nix's options, for checks and docs without sops-nix
nix/pkgs/nixwarden.nix  the CLI, wrapped with bw, sops, ssh-keygen
nix/docs/               options.md / commands.md, generated
pkgs/nixwarden/         the Python package and its offline tests
examples/               reference declarations, including the jeirslab wiring
```

`nix flake check` runs everything that can run without a vault.
