# A credential no host consumes.
#
# This is the case nixwarden exists for. A bootstrap mints an admin password
# into a SOPS file; the host verifies a hash and never needs the value; the
# person who must log in does. Declaring it on a host to make the mirror work
# would have sops-nix materialise it on a machine with no use for it, so the
# file and key are named directly and the entry carries `hosts = [ ]`.
#
# These go in the flake, not in a host module, and are handed to both
# `mkManifestApp` and `mkSyncApp` as `extraSecrets`. They are pruned like
# any other entry: drop one and the next sync trashes the item.
{ nixwarden, ... }:

let
  people = [
    (nixwarden.lib.mkExportOnly {
      sopsFile = ./secrets/nextcloud.yaml;
      sopsKey = "admin_password";
      org = "lab";
      collection = "infrastructure";
      name = "Nextcloud admin";
      username = "admin";
      uris = [ "https://nextcloud.example" ];
    })
    (nixwarden.lib.mkExportOnly {
      sopsFile = ./secrets/infisical-admin.yaml;
      sopsKey = "admin/password";
      org = "lab";
      collection = "infrastructure";
      name = "Infisical instance admin";
      username = nixwarden.lib.ref "admin/email";
      uris = [ "https://infisical.example" ];
    })
  ];
in
{
  # packages.${system}.bitwarden-manifest = nixwarden.mkManifestApp {
  #   inherit pkgs; inherit (self) nixosConfigurations; extraSecrets = people;
  # };
  inherit people;
}
