# A login item with every slot in use.
#
# The annotated secret is the anchor: its value lands in `field`, which for a
# login defaults to `password`. Everything else is a literal or a `ref`.
{ nixwarden, ... }:

{
  imports = [ nixwarden.nixosModules.export ];

  sops.secrets."authentik/admin_password" = {
    sopsFile = ./secrets/idp.yaml;
    bitwarden = nixwarden.lib.mkLogin {
      org = "lab";
      collection = "infrastructure";
      name = "Authentik admin";

      # Another key in the same file, read at sync time and stored as the
      # username. A bootstrap that writes `user` next to `password` is the
      # case this exists for.
      username = nixwarden.lib.ref "authentik/admin_user";

      # A key in a *different* file. `sopsFile` on a ref overrides the
      # entry's own.
      totp = nixwarden.lib.ref { sopsKey = "authentik/totp_seed"; sopsFile = ./secrets/totp.yaml; };

      uris = [ "https://auth.example" "https://auth.example/if/admin/" ];

      # Custom fields. A literal is stored as text (it is in the Nix store
      # anyway); a ref is stored hidden. The name `nixwarden` is reserved.
      fields = {
        "api url" = "https://auth.example/api/v3/";
        "api token" = nixwarden.lib.ref "authentik/api_token";
      };

      notes = "Bootstrapped by the idp host; rotate via the SOPS file, not here.";
      reprompt = true;
    };
  };
}
