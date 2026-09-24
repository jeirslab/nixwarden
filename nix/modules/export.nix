# nixwarden export module — adds `bitwarden` to every sops.secrets entry.
#
# The NixOS module system merges submodule option-sets across every module
# that targets the same option, so this re-declares `sops.secrets` with ONLY
# a type contributing one new option. sops-nix's own declaration is untouched
# and still wins; this adds a field and nothing else.
#
# IT IS NOT FREE. sops-nix builds its on-host manifest from the WHOLE
# submodule, fields it has never heard of included, so `"bitwarden": null`
# lands in every host's manifest.json the moment this module is imported,
# which moves the host's toplevel. Importing this fleet-wide rebuilds every
# host that uses sops, annotated or not; changing one annotation afterwards
# rebuilds that host. sops-nix never *reads* the field (`sops-install-secrets`
# ignores unknown JSON keys), so the activation is a no-op — the cost is a
# deploy, not a behaviour change. nixfisical's export module carries the same
# cost, measured on a 17-host fleet; if both are imported the manifest moves
# once for each.
#
# Plan around it the same way: import this in the same change as your first
# annotations, not ahead of them. And know that the routing metadata (org,
# collection, item name, a literal username, uris) ends up in a
# world-readable /nix/store path on each host. It names no values — a `ref`
# is a key path, not a value — but if an item name is itself sensitive, that
# is where it leaks.
#
# A secret with no `bitwarden` (the default) is infra-only: it stays in SOPS,
# reaches the host, and is never mirrored. Mirroring is opt-in per secret.
#
# Import this on every host whose secrets you want to be mirrorable, then
# render with `nixwarden.lib.manifestOf self.nixosConfigurations`.
{ lib, ... }:

let
  inherit (lib) mkOption mkDefault types;

  nw = import ../lib { inherit lib; };

  # Another SOPS key, for a slot that is not the anchor. `sopsFile` null
  # means "the entry's own file".
  refType = types.submodule {
    options = {
      sopsKey = mkOption {
        type = types.str;
        description = "Key path (`a/b/c`) in the SOPS file to read this slot's value from.";
        example = "authentik/admin_user";
      };
      sopsFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          The encrypted file holding `sopsKey`. Null means the same file as
          the annotated secret, which is the usual case.
        '';
      };
    };
  };

  # A literal string, or a ref. The distinction is preserved into the
  # manifest: a literal is written as text, a ref is resolved at sync time
  # and written as a hidden value.
  valueType = types.either types.str refType;

  bitwardenType = types.submodule ({ config, ... }: {
    options = {
      org = mkOption {
        type = types.str;
        description = ''
          Organization the item lands in, by NAME as the vault shows it.
          Together with `collection` this is the access boundary — who can
          see the item — so it has no default.
        '';
        example = "jeirslab";
      };

      collection = mkOption {
        type = types.str;
        description = ''
          Collection within the organization, by name. A nested collection is
          written with slashes, exactly as `bw list org-collections` prints it.
          Created on the first sync if it does not exist.
        '';
        example = "infrastructure/sops-decrypt";
      };

      type = mkOption {
        type = types.enum nw.types;
        default = "login";
        description = ''
          What kind of vault item this secret becomes. `login` for a
          username/password pair, `note` for an opaque blob (an age key, a
          PEM), `ssh-key` for an OpenSSH private key — the public key and
          fingerprint are derived at sync time.
        '';
      };

      field = mkOption {
        type = types.enum nw.fields;
        description = ''
          Which slot of the item the annotated secret's value lands in.
          Defaults per `type`: `password` for a login, `notes` for a note,
          `privateKey` for an ssh-key. Set it to `username` or `totp` to
          anchor a login on one of those instead, with the password coming
          in through `password`'s absence — rarely what you want, but the
          slot exists.
        '';
      };

      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Item name as the vault shows it. Defaults to the last segment of
          the SOPS key path, so `services/grafana/admin_password` becomes
          `admin_password`. Worth overriding: it is the name a person searches
          for, and it is the identity `nixwarden sync` matches on.
        '';
        example = "Grafana admin";
      };

      username = mkOption {
        type = types.nullOr valueType;
        default = null;
        description = ''
          Login username: a literal, or `nixwarden.lib.ref "<sopsKey>"` to read
          it from the secrets file at sync time. Login items only.
        '';
        example = "akadmin";
      };

      uris = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "URIs the login applies to. Login items only.";
        example = [ "https://auth.example.org" ];
      };

      totp = mkOption {
        type = types.nullOr valueType;
        default = null;
        description = "TOTP seed or otpauth:// URI. Login items only.";
      };

      notes = mkOption {
        type = types.nullOr valueType;
        default = null;
        description = ''
          Free-text notes on the item. For a `note` item whose `field` is
          `notes` (the default) leave this null: the anchored value IS the
          note body.
        '';
      };

      fields = mkOption {
        type = types.attrsOf valueType;
        default = { };
        description = ''
          Custom fields, by name. A literal is stored as text; a ref is
          stored hidden. The name `nixwarden` is reserved for the marker the
          CLI uses to recognise the items it manages.
        '';
        example = lib.literalExpression ''
          { "api url" = "https://api.example.org"; token = nixwarden.lib.ref "svc/api_token"; }
        '';
      };

      favorite = mkOption {
        type = types.bool;
        default = false;
        description = "Mark the item as a favourite.";
      };

      reprompt = mkOption {
        type = types.bool;
        default = false;
        description = "Ask for the master password again before revealing the item.";
      };
    };

    config.field = mkDefault (nw.defaultField config.type);
  });
in
{
  options.sops.secrets = mkOption {
    type = types.attrsOf (types.submodule {
      options.bitwarden = mkOption {
        type = types.nullOr bitwardenType;
        default = null;
        description = ''
          Vault-facing mirror metadata. When set, this secret is emitted into
          the Bitwarden manifest as one item in the given org / collection.
          `null` (the default) means infra-only: the secret stays in SOPS and
          never reaches the vault.
        '';
      };
    });
  };
}
