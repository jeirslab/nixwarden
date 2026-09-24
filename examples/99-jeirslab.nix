# How jeirslab/homelab will wire this in. Not evaluated here; a reference for
# the change to homelab's flake.nix, written to mirror its nixfisical wiring
# line for line so the two read as one pattern.
#
# ── flake.nix, inputs ───────────────────────────────────────────────────
#
#   nixwarden.url = "github:jeirslab/nixwarden";
#
# ── flake.nix, the fleet's shared modules ───────────────────────────────
#
#   nixwarden.nixosModules.export
#   # …and `nixwarden.lib.mkLogin` to write the annotations with. Via a
#   # module arg, not `inputs.nixwarden`, for the same reason nixfisical is:
#   # `fleet deploy` evaluates hosts without `inputs` in scope.
#   { _module.args.nixwarden = nixwarden; }
#
# ── flake.nix, packages ─────────────────────────────────────────────────
#
#   bitwarden-manifest = nixwarden.mkManifestApp {
#     pkgs = mkPkgs { };
#     inherit (self) nixosConfigurations;
#     extraSecrets = bootstrapped;      # the mkExportOnly list below
#   };
#   bitwarden-sync = nixwarden.mkSyncApp {
#     pkgs = mkPkgs { };
#     inherit (self) nixosConfigurations;
#     extraSecrets = bootstrapped;
#     url = "https://vault.jeirslab.xyz";
#     # The same per-repo age key the infisical-sync app names, for the same
#     # reason: a flake app runs outside the dev shell that would set it.
#     ageKeyFile = "\${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/alexanderjerome/jeirslab/key.txt";
#     # Credentials from the environment: nexus's .env already carries
#     # BITWARDEN_SERVER_URL, BW_CLIENTID, BW_CLIENTSECRET and
#     # BITWARDEN_USER_PASSWORD for the key scripts. Or encrypt the four into
#     # secrets/bitwarden-admin.yaml and set `adminFile` here.
#   };
#
# ── first run ───────────────────────────────────────────────────────────
#
#   nix run .#bitwarden-manifest -- table      # review: no values, just routing
#   nix run .#bitwarden-sync -- --dry-run      # the plan; expect `create` lines
#                                              # and, for names that already
#                                              # exist in the vault, `conflict`
#   nix run .#bitwarden-sync -- --dry-run --adopt   # if those conflicts are
#                                              # the same credentials uploaded
#                                              # by hand: take them over
#   nix run .#bitwarden-sync                   # converge
#
# The org is `jeirslab` (id 7fa1e938-…), collections `infrastructure` and
# `infrastructure/sops-decrypt` exist already (see nexus keys.toml). A new
# collection named here is created on the first sync.
{ nixwarden, ... }:

{
  # Host-side: on the host that bootstraps the credential, or nowhere (see
  # `bootstrapped` below) when the host only ever holds a hash.
  sops.secrets."nextcloud/admin_password".bitwarden = nixwarden.lib.mkLogin {
    org = "jeirslab";
    collection = "infrastructure";
    name = "Nextcloud admin";
    username = "admin";
    uris = [ "https://nextcloud.jeirslab.xyz" ];
  };

  # Flake-side: the people-facing credentials no host consumes.
  #   bootstrapped = [ (nixwarden.lib.mkExportOnly { … }) … ];
}
