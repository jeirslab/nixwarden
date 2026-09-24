{
  description = "Declarative Bitwarden / Vaultwarden mirroring for NixOS — sops-declared secrets pushed into the right org and collection";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Where `bw` comes from, pinned separately from everything else.
    #
    # bitwarden-cli 2026.9.0 (nixos-unstable at the time of writing) answers
    # `bw serve`'s POST /unlock with an HTTP 500 and a wasm stack trace
    # against a Vaultwarden 2026-09 instance -- the panic is inside the
    # Bitwarden SDK, before any vault operation, with a correct password and
    # a login that just succeeded. 2026.8.0 from this revision unlocks, syncs
    # and lists cleanly against the same instance; 2026.6.0 too. Reproduced
    # with curl, so it is the CLI and not this client. Move this pin only
    # after `nixwarden status` has been run against a real Vaultwarden with
    # the candidate version.
    nixpkgs-bw.url = "github:NixOS/nixpkgs/3ed67ec0a4d3c7ab4ae1f04f8ee8df07bfa506a2";
  };

  outputs = { self, nixpkgs, flake-utils, nixpkgs-bw }:
    let
      # The declaration/manifest layer is pure — it only needs `lib`, so it is
      # available without a system and callable from a consumer's flake before
      # any package is built.
      nixwardenLib = import ./nix/lib { lib = nixpkgs.lib; };
    in
    {
      lib = nixwardenLib;

      nixosModules = {
        default = ./nix/modules;
        # Add `sops.secrets.<key>.bitwarden` so secrets can be annotated for
        # mirroring. Import this on every host you want to mirror from.
        export = ./nix/modules/export.nix;
      };

      overlays.default = final: prev:
        let
          bwPkgs = import nixpkgs-bw { inherit (final.stdenv.hostPlatform) system; };
        in
        {
          nixwarden = final.callPackage ./nix/pkgs/nixwarden.nix {
            inherit (bwPkgs) bitwarden-cli;
          };
          # The same pinned CLI, for the dev shell and for anyone who wants
          # the version this tool was tested with on their own PATH.
          inherit (bwPkgs) bitwarden-cli;
        };

      # Render a fleet's manifest as a flake app:
      #
      #   packages.bitwarden-manifest = nixwarden.mkManifestApp {
      #     inherit pkgs;
      #     nixosConfigurations = self.nixosConfigurations;
      #     extraSecrets = [ (nixwarden.lib.mkExportOnly { … }) ];
      #   };
      #
      #   nix run .#bitwarden-manifest            # JSON (feeds `nixwarden sync`)
      #   nix run .#bitwarden-manifest -- table   # human review
      #
      # The JSON is baked at eval time and contains no decrypted values —
      # only SOPS key paths and their routing.
      mkManifestApp = { pkgs, nixosConfigurations, extraSecrets ? [ ], validate ? true }:
        let
          raw = nixwardenLib.manifestFrom { inherit nixosConfigurations extraSecrets; };
          manifest = if validate then nixwardenLib.assertManifest raw else raw;
          json = builtins.toJSON manifest;
        in
        pkgs.writeShellApplication {
          name = "bitwarden-manifest";
          runtimeInputs = [ pkgs.jq pkgs.util-linux ];
          text = ''
            M=${pkgs.lib.escapeShellArg json}
            case "''${1:-json}" in
              json)
                printf '%s' "$M" | jq '.'
                ;;
              table)
                {
                  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    ORG COLLECTION NAME TYPE FIELD "SOPS FILE" "SOPS KEY"
                  printf '%s' "$M" | jq -r '
                    .[] | [.org, .collection, .name, .type, .field, .sopsFile, .sopsKey] | @tsv'
                } | column -t -s "$(printf '\t')"
                echo ""
                echo "mirrored items: $(printf '%s' "$M" | jq 'length')"
                ;;
              *)
                echo "usage: bitwarden-manifest [json|table]" >&2
                exit 1
                ;;
            esac
          '';
        };

      # The same manifest, pushed:
      #
      #   packages.bitwarden-sync = nixwarden.mkSyncApp {
      #     inherit pkgs;
      #     nixosConfigurations = self.nixosConfigurations;
      #     url = "https://vault.example.org";
      #     adminFile = "secrets/bitwarden-admin.yaml";   # or rely on the environment
      #   };
      #
      #   nix run .#bitwarden-sync -- --dry-run   # plan only
      #   nix run .#bitwarden-sync                # converge
      #
      # THIS PRUNES. A managed item the manifest no longer declares is moved to
      # the vault's trash on the next run (restorable for thirty days). It never
      # touches an item it did not write: those carry no `nixwarden` marker
      # field and are reported as conflicts if a declared name collides.
      #
      # Runs on the operator's machine, not on a host: the decryption uses the
      # operator's age key, and the vault unlock uses the master password, and
      # no host has either. Credentials come from the environment
      # (BITWARDEN_SERVER_URL, BW_CLIENTID, BW_CLIENTSECRET,
      # BITWARDEN_USER_PASSWORD) or from `adminFile`, a SOPS file holding
      # server_url / client_id / client_secret / password.
      mkSyncApp =
        { pkgs
        , nixosConfigurations
        , url
        , extraSecrets ? [ ]
        , validate ? true
          # A SOPS file with the four credentials; null means environment only.
          # Resolved at run time against the working directory, deliberately:
          # rotate the credential, run again, done — no commit in between.
        , adminFile ? null
          # The age identity to decrypt with, if SOPS_AGE_KEY_FILE is not
          # already set. Null leaves sops to its own default. Worth setting for
          # an estate with a per-repo key: unset, sops reports a missing keyring
          # and a keyring holding the wrong key identically.
        , ageKeyFile ? null
          # Defaults to this flake's own build so a consumer needs neither the
          # overlay nor a matching nixpkgs. Pass `pkgs.nixwarden` if you have it.
        , nixwarden ? self.packages.${pkgs.stdenv.hostPlatform.system}.nixwarden
        }:
        let
          manifestApp = self.mkManifestApp {
            inherit pkgs nixosConfigurations extraSecrets validate;
          };
          inherit (pkgs) lib;
        in
        pkgs.writeShellApplication {
          name = "bitwarden-sync";
          # coreutils for `mktemp`: writeShellApplication only prepends to the
          # ambient PATH, and a script that works everywhere it is tried and
          # depends on the caller's environment anyway is not the goal.
          runtimeInputs = [ manifestApp nixwarden pkgs.coreutils ];
          text = ''
            for arg in "$@"; do
              case "$arg" in
                --dry-run|--no-prune|--adopt) ;;
                *)
                  echo "usage: bitwarden-sync [--dry-run] [--no-prune] [--adopt]" >&2
                  exit 1
                  ;;
              esac
            done

            ${lib.optionalString (ageKeyFile != null) ''
            # `:=` and not `=`: an operator who set SOPS_AGE_KEY_FILE meant it.
            : "''${SOPS_AGE_KEY_FILE:=${ageKeyFile}}"
            if [ -f "$SOPS_AGE_KEY_FILE" ]; then
              export SOPS_AGE_KEY_FILE
            else
              echo "bitwarden-sync: no age identity at $SOPS_AGE_KEY_FILE;" \
                   "falling back to sops' own search" >&2
            fi
            ''}
            manifest=$(mktemp)
            trap 'rm -f "$manifest"' EXIT
            bitwarden-manifest json > "$manifest"

            nixwarden --url ${lib.escapeShellArg url} \
              ${lib.optionalString (adminFile != null) "--admin-file ${lib.escapeShellArg adminFile}"} \
              sync --manifest "$manifest" "$@"
          '';
        };
    }
    //
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
        inherit (pkgs) nixwarden;
        docs = pkgs.callPackage ./nix/docs { inherit nixwarden; };

        # A small fleet, evaluated against the sops stub, whose manifest is
        # asserted below. This is the whole Nix side exercised end to end:
        # module -> lib.manifestOf -> assertManifest -> JSON.
        fixture =
          let
            eval = hostName: secrets: nixpkgs.lib.evalModules {
              modules = [
                ./nix/modules/export.nix
                ./nix/modules/sops-stub.nix
                { sops.defaultSopsFile = ./examples/fixtures/secrets.yaml; sops.secrets = secrets; }
              ];
            };
            hosts = {
              idp = eval "idp" {
                "authentik/admin_password".bitwarden = nixwardenLib.mkLogin {
                  org = "lab"; collection = "infrastructure"; name = "Authentik admin";
                  username = nixwardenLib.ref "authentik/admin_user";
                  uris = [ "https://auth.example" ];
                  fields = { "api url" = "https://auth.example/api"; token = nixwardenLib.ref "authentik/token"; };
                };
                "plain" = { };
                "renamed" = { key = "keys/age"; bitwarden = nixwardenLib.mkNote { org = "lab"; collection = "infrastructure/sops-decrypt"; }; };
              };
              # Same file+key on a second host: must collapse into one entry with two hosts.
              idp2 = eval "idp2" {
                "authentik/admin_password".bitwarden = nixwardenLib.mkLogin {
                  org = "lab"; collection = "infrastructure"; name = "Authentik admin";
                  username = nixwardenLib.ref "authentik/admin_user";
                  uris = [ "https://auth.example" ];
                  fields = { "api url" = "https://auth.example/api"; token = nixwardenLib.ref "authentik/token"; };
                };
              };
            };
            extra = [
              (nixwardenLib.mkExportOnly {
                sopsFile = ./examples/fixtures/people.yaml; sopsKey = "nextcloud/admin_password";
                org = "lab"; collection = "infrastructure"; name = "Nextcloud admin"; username = "admin";
              })
            ];
          in
          nixwardenLib.assertManifest (nixwardenLib.manifestFrom { nixosConfigurations = hosts; extraSecrets = extra; });
      in
      {
        packages = {
          inherit nixwarden docs;
          default = nixwarden;
        };

        apps.default = {
          type = "app";
          program = "${nixwarden}/bin/nixwarden";
          meta.description = "Mirror sops-declared secrets into a Bitwarden / Vaultwarden vault";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            nixwarden
            pkgs.bitwarden-cli
            pkgs.sops
            pkgs.age
            pkgs.jq
            (pkgs.python3.withPackages (ps: [ ps.click ps.httpx ps.pyyaml ps.pytest ]))
          ];
          shellHook = ''
            echo "nixwarden dev shell — 'nixwarden --help' for the CLI, 'pytest pkgs/nixwarden' for the suite."
          '';
        };

        checks = {
          package = nixwarden;

          # Building the docs evaluates every option's default and example,
          # which nothing else here does.
          inherit docs;

          # Build the sync app: shellcheck on the generated script and proof
          # that both helper functions evaluate at all, which `nix flake
          # check` would otherwise never reach (they are top-level functions).
          sync-app = self.mkSyncApp {
            inherit pkgs;
            nixosConfigurations = { };
            url = "https://vault.invalid";
            adminFile = "secrets/bitwarden-admin.yaml";
            ageKeyFile = "\${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt";
          };

          # The fixture fleet's manifest, rendered and asserted: the module
          # merged into `sops.secrets`, `key` honoured over the attribute
          # name, `defaultSopsFile` inherited, refs normalised, two hosts
          # collapsed into one entry, an export-only entry alongside, and the
          # result accepted by the CLI's own validator.
          module-eval = pkgs.runCommand "nixwarden-module-eval"
            {
              nativeBuildInputs = [ pkgs.jq nixwarden ];
              manifest = builtins.toJSON fixture;
              passAsFile = [ "manifest" ];
            } ''
            jq '.' "$manifestPath" > manifest.json
            fail() { echo "module-eval: $*" >&2; cat manifest.json >&2; exit 1; }
            [ "$(jq 'length' manifest.json)" = 3 ] || fail "expected 3 entries"
            jq -e '.[] | select(.name=="Authentik admin") | .hosts == ["idp","idp2"]' manifest.json >/dev/null \
              || fail "two hosts did not collapse into one entry"
            jq -e '.[] | select(.name=="Authentik admin") | .username == {sopsKey:"authentik/admin_user", sopsFile:null}' manifest.json >/dev/null \
              || fail "ref not normalised"
            jq -e '.[] | select(.name=="Authentik admin") | .fields == [{name:"api url",value:"https://auth.example/api"},{name:"token",value:{sopsKey:"authentik/token",sopsFile:null}}]' manifest.json >/dev/null \
              || fail "fields not normalised and sorted"
            jq -e '.[] | select(.sopsKey=="keys/age") | .type=="note" and .field=="notes" and .name=="age"' manifest.json >/dev/null \
              || fail "sops-nix key/attr distinction lost, or note defaults wrong"
            jq -e '.[] | select(.name=="Nextcloud admin") | .hosts == [] and .username=="admin"' manifest.json >/dev/null \
              || fail "export-only entry wrong"
            jq -e 'all(.[]; .sopsFile | startswith("/nix/store/"))' manifest.json >/dev/null \
              || fail "sopsFile not a store path"
            nixwarden validate --manifest manifest.json || fail "CLI validator rejected the Nix-rendered manifest"
            cp manifest.json $out
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
