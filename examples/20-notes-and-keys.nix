# Opaque blobs and SSH keys.
#
# A `note` puts the anchored value in the item's notes body -- the right home
# for an age identity, a PEM, a kubeconfig. An `ssh-key` puts it in the SSH
# key slot; the public key and fingerprint are derived at sync time with
# ssh-keygen, so the vault shows them and a truncated key is refused before
# it is stored.
{ nixwarden, ... }:

{
  imports = [ nixwarden.nixosModules.export ];

  sops.defaultSopsFile = ./secrets/keys.yaml;

  sops.secrets."age/host_key".bitwarden = nixwarden.lib.mkNote {
    org = "lab";
    collection = "infrastructure/sops-decrypt";
    name = "lab host age key";
  };

  # The attribute name is not the lookup path when `key` is set; the manifest
  # reads `key`, exactly as sops-nix does.
  sops.secrets."deployer-ssh" = {
    key = "ssh/deployer";
    bitwarden = nixwarden.lib.mkSshKey {
      org = "lab";
      collection = "infrastructure/sops-decrypt";
      name = "lab deployer";
      notes = "Authorised on every host's root; rotate with `fleet keys`.";
    };
  };
}
