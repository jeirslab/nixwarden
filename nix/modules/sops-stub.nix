# The sops-nix options `export.nix` and `lib.manifestFrom` read, and nothing
# else.
#
# sops-nix is not an input to this flake and should not become one: the export
# module adds one field to `sops.secrets` and the manifest reads two of its
# existing ones (`key`, `sopsFile`). Taking sops-nix as an input to evaluate a
# module standalone would be a large dependency bought for a small reason.
#
# So this stub declares those. That is the whole contract with sops-nix written
# down where it can be checked: if `manifestFrom` ever reaches for a third
# option, evaluation against this stub fails, and the failure is the
# notification. `sopsFile` defaults from `defaultSopsFile` the way sops-nix's
# does, because that defaulting is exactly what the manifest relies on.
#
# Used by `checks.module-eval` and by the options documentation. It is
# deliberately NOT in the documented-module list in nix/docs: these are
# sops-nix's options, not this flake's.
{ lib, config, ... }:

{
  options.sops.defaultSopsFile = lib.mkOption {
    type = lib.types.nullOr lib.types.path;
    default = null;
    description = "sops-nix's default encrypted file (stub).";
  };

  options.sops.secrets = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
      options.key = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "Key path within the file (stub; sops-nix's own).";
      };
      options.sopsFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = config.sops.defaultSopsFile;
        description = "The encrypted file (stub; sops-nix's own).";
      };
    }));
    default = { };
    # The one description that renders: `sops.secrets` itself is declared by
    # export.nix too, and only one declaration may carry a description.
    description = ''
      sops-nix secrets. nixwarden adds `bitwarden` to each entry; every other
      field here belongs to sops-nix and is documented there.
    '';
  };
}
