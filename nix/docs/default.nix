# nixwarden/nix/docs — the option surface and the CLI surface, rendered.
#
# `nix build github:jeirslab/nixwarden#docs` produces a directory a person or
# an agent can read without a checkout, credentials, or a vault:
#
#   index.md         what this flake provides and which piece answers what
#   options.json     every option this repo declares, machine-readable
#   options.md       the same, rendered
#   commands.md      `--help` of every command
#
# A derivation and not a server: "what can be declared" needs no process and
# no network, and prose that is generated from the module system cannot
# drift from it -- an option added without a description is a hole visible
# here, and a renamed one moves here in the same commit.
{ lib
, pkgs
, nixwarden
}:

let
  documented = [ "export.nix" ];

  # Matched on the path's tail, not its basename: a basename match would
  # claim any `export.nix` a consumer's nixpkgs happened to carry.
  ours = f: d: lib.hasSuffix "/nix/modules/${f}" (toString d);
  isOurs = opt: lib.any (d: lib.any (f: ours f d) documented) (opt.declarations or [ ]);

  repoUrl = "https://github.com/jeirslab/nixwarden";

  # Declarations arrive as store paths, which change on every commit; a docs
  # output that churns on content-free rebuilds is one nobody diffs.
  relink = decl:
    let
      s = toString decl;
      m = builtins.match ".*/(nix/modules/.*)" s;
    in
    if m == null then decl
    else { name = builtins.head m; url = "${repoUrl}/blob/main/${builtins.head m}"; };

  # The stub stands in for sops-nix, so `sops.secrets` evaluates; its own two
  # options are filtered out by `isOurs` above.
  eval = lib.evalModules {
    modules = [ ../modules/export.nix ../modules/sops-stub.nix ];
  };

  optionsDoc = pkgs.nixosOptionsDoc {
    options = eval.options;
    transformOptions = opt:
      if isOurs opt then opt // { declarations = map relink opt.declarations; }
      else opt // { visible = false; };
  };

  commands = [ "" "validate" "sync" "status" "collections" ];
in
pkgs.runCommand "nixwarden-docs" { nativeBuildInputs = [ nixwarden pkgs.jq ]; } ''
  mkdir -p $out
  cp ${optionsDoc.optionsJSON}/share/doc/nixos/options.json $out/options.json
  cp ${optionsDoc.optionsCommonMark} $out/options.md

  # Empty docs are a broken filter, not an empty flake.
  n=$(jq 'length' $out/options.json)
  [ "$n" -gt 0 ] || { echo "no options documented: the declaration filter matched nothing" >&2; exit 1; }
  # The rendered Markdown escapes the dots and angle brackets; the JSON keys
  # are the option paths verbatim, so that is where the annotation is looked for.
  jq -e 'has("sops.secrets.<name>.bitwarden") and has("sops.secrets.<name>.bitwarden.org")' $out/options.json >/dev/null \
    || { echo "options.json does not carry the bitwarden annotation" >&2; exit 1; }

  {
    echo "# nixwarden commands"
    echo
    ${lib.concatMapStringsSep "\n" (c: ''
      echo '## nixwarden ${c}'
      echo
      echo '```'
      nixwarden ${c} --help
      echo '```'
      echo
    '') commands}
  } > $out/commands.md

  cat > $out/index.md <<'MD'
  # nixwarden — reference

  - `options.md` / `options.json`: the `sops.secrets.<name>.bitwarden` annotation
    and every field it takes. Declared by `nixosModules.export`.
  - `commands.md`: the operator CLI. `sync` is the one that writes; it prunes.

  Generated from the module system and the click tree by `nix build .#docs`.
  MD
''
