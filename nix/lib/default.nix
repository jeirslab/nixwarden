# nixwarden/nix/lib — the declaration + manifest layer.
#
# Two halves, the same shape as nixfisical's:
#
#   mkBitwarden   attached to a `sops.secrets.<key>` entry, says which vault
#                 item that secret becomes and where in Bitwarden it lands.
#                 `mkLogin`, `mkNote` and `mkSshKey` are the same function
#                 with `type` filled in.
#   manifestOf    walks a fleet's `nixosConfigurations` and collects every
#                 such annotation into a flat, deduped manifest.
#
# plus an escape hatch for credentials no host declares:
#
#   mkExportOnly  names a (sopsFile, sopsKey) directly, with no host behind it.
#                 This is the common case for a *bootstrapped* credential — an
#                 admin password minted at first boot that a person logs in
#                 with and no machine consumes.
#   manifestFrom  the general form of manifestOf — hosts and export-only
#                 entries merged into one manifest.
#
# The manifest is STRUCTURE ONLY — it names SOPS keys, never values. Nothing
# decrypted ever enters the Nix store. The `nixwarden sync` CLI takes this
# manifest plus your age key and does the decryption at run time, on the
# operator's machine, then writes the items through a local `bw serve`.
#
# One vault item is one manifest entry. The entry is anchored to ONE secret
# (the annotated one) whose value lands in `field` — the password of a login,
# the body of a note, the private key of an SSH key. Every other slot of the
# item (`username`, `totp`, `notes`, a custom field) is either a literal
# string, written into the manifest as-is, or a `ref` to another SOPS key,
# resolved at sync time exactly like the anchor. That is how a login item
# carries a username that was itself generated into the secrets file.
{ lib }:

rec {
  # The item kinds this repo knows how to write, and the slot the anchored
  # secret's value lands in by default for each. Bitwarden's own numbering is
  # applied in the CLI (login = 1, secure note = 2, ssh key = 5); the manifest
  # carries the word so it can be read.
  types = [ "login" "note" "ssh-key" ];

  # Every slot a secret value can be routed to. Which ones a given `type`
  # accepts is checked by `assertManifest` (and by the module's own
  # assertion), not here.
  fields = [ "password" "username" "totp" "notes" "privateKey" ];

  defaultField = type: {
    login = "password";
    note = "notes";
    ssh-key = "privateKey";
  }.${type};

  fieldsFor = type: {
    login = [ "password" "username" "totp" "notes" ];
    note = [ "notes" ];
    ssh-key = [ "privateKey" "notes" ];
  }.${type};

  # A reference to another SOPS key, for the slots that are not the anchor.
  #
  #   username = nixwarden.lib.ref "authentik/admin_user";
  #   username = nixwarden.lib.ref { sopsKey = "admin_user"; sopsFile = ./other.yaml; };
  #
  # `sopsFile` defaults to the entry's own file at sync time, which is the
  # usual case: a bootstrap writes `<svc>/user` and `<svc>/password` side by
  # side. A value that arrives through a ref is always stored as a hidden
  # field; a literal is stored as plain text — it is in the Nix store anyway.
  ref = spec:
    if builtins.isString spec then { sopsKey = spec; sopsFile = null; }
    else {
      sopsKey = spec.sopsKey;
      sopsFile = if (spec.sopsFile or null) == null then null else toString spec.sopsFile;
    };

  # A literal string, or the result of `ref`, or an attrset that looks like
  # one (the module hands those through). Anything else is a call-site error
  # and is reported as such rather than surfacing as a JSON oddity later.
  normalizeValue = what: v:
    if v == null then null
    else if builtins.isString v then v
    else if builtins.isAttrs v && v ? sopsKey then ref v
    else throw "nixwarden: ${what} must be a string or `nixwarden.lib.ref …`, got ${builtins.typeOf v}";

  # `fields = { "api url" = "https://…"; token = ref "svc/token"; }` becomes a
  # list sorted by name, so two manifests of the same declaration are equal
  # byte for byte.
  normalizeFields = fields:
    map
      (name: { inherit name; value = normalizeValue "fields.${name}" fields.${name}; })
      (lib.sort (a: b: a < b) (builtins.attrNames fields));

  # Attach to a secret to mirror it into Bitwarden. `org` and `collection`
  # are the access boundary — who can see the item — so neither has a
  # default: choosing them is a security decision and should be explicit at
  # every call site. Both are NAMES as the vault shows them, resolved to ids
  # at sync time; a nested collection is written with slashes, exactly as
  # `bw list org-collections` prints it ("infrastructure/sops-decrypt").
  #
  #   sops.secrets."authentik/admin_password".bitwarden = nixwarden.lib.mkLogin {
  #     org        = "jeirslab";
  #     collection = "infrastructure";
  #     name       = "Authentik admin";
  #     username   = nixwarden.lib.ref "authentik/admin_user";
  #     uris       = [ "https://auth.jeirslab.xyz" ];
  #   };
  mkBitwarden =
    { org
    , collection
    , type ? "login"
      # Where the anchored secret's value lands. Null means the type's own
      # default: password / notes / privateKey.
    , field ? null
      # Item name as the vault shows it. Defaults to the last segment of the
      # SOPS key path, so `services/grafana/admin_password` becomes
      # `admin_password` — legible, but worth overriding.
    , name ? null
    , username ? null
    , uris ? [ ]
    , totp ? null
    , notes ? null
    , fields ? { }
    , favorite ? false
    , reprompt ? false
    }: {
      inherit org collection type uris favorite reprompt name;
      field = if field != null then field else defaultField type;
      username = normalizeValue "username" username;
      totp = normalizeValue "totp" totp;
      notes = normalizeValue "notes" notes;
      # Kept as an attrset here so the result type-checks against the
      # module's option; `manifestFrom` turns it into the sorted list the
      # manifest carries.
      fields = lib.mapAttrs (n: v: normalizeValue "fields.${n}" v) fields;
    };

  mkLogin = args: mkBitwarden (args // { type = "login"; });
  mkNote = args: mkBitwarden (args // { type = "note"; });
  mkSshKey = args: mkBitwarden (args // { type = "ssh-key"; });

  # Mirror a secret that NO host declares.
  #
  # `mkBitwarden` rides on a `sops.secrets` entry, so the mirrored set is
  # exactly the set some machine consumes. That is right for service
  # credentials and wrong for the thing this repo exists for: a password a
  # bootstrap generated for a *person*. The admin login of a web UI is not
  # deployed anywhere — the host holds a hash, the operator holds the value —
  # and declaring it on a host just to make the export work would have
  # sops-nix materialise it on a machine with no use for it.
  #
  #   nixwarden.lib.mkExportOnly {
  #     sopsFile   = ./secrets/nextcloud.yaml;
  #     sopsKey    = "admin_password";
  #     org        = "jeirslab";
  #     collection = "infrastructure";
  #     name       = "Nextcloud admin";
  #     username   = "admin";
  #     uris       = [ "https://nextcloud.jeirslab.xyz" ];
  #   }
  #
  # The result is an ordinary manifest entry with `hosts = [ ]`. It is
  # validated, deduped and PRUNED exactly like a host-derived one: drop the
  # declaration and the next sync trashes the item.
  mkExportOnly =
    { sopsFile
    , sopsKey
    , ...
    }@args:
    let
      item = mkBitwarden (removeAttrs args [ "sopsFile" "sopsKey" ]);
    in
    normalizeEntry item // {
      inherit sopsKey;
      sopsFile = toString sopsFile;
      host = null;
      name = if item.name != null then item.name else lib.last (lib.splitString "/" sopsKey);
    };

  # The manifest form of an annotation, whether it came through the module
  # (where a ref is a submodule value and `fields` an attrset) or straight
  # from `mkBitwarden`.
  normalizeEntry = e: e // {
    username = normalizeValue "username" (e.username or null);
    totp = normalizeValue "totp" (e.totp or null);
    notes = normalizeValue "notes" (e.notes or null);
    fields = normalizeFields (e.fields or { });
    uris = e.uris or [ ];
    favorite = e.favorite or false;
    reprompt = e.reprompt or false;
  };

  # nixosConfigurations -> [ manifestEntry ]
  manifestOf = nixosConfigurations: manifestFrom { inherit nixosConfigurations; };

  # { nixosConfigurations, extraSecrets } -> [ manifestEntry ]
  #
  # An entry carries its OWN `sopsFile`, read from sops-nix's per-secret
  # option (which defaults to `sops.defaultSopsFile`), so a fleet whose
  # secrets are split across several encrypted files exports correctly and
  # the CLI stays file-agnostic.
  manifestFrom =
    { nixosConfigurations ? { }
    , extraSecrets ? [ ]
    }:
    let
      perHost = lib.mapAttrsToList
        (host: node:
          lib.mapAttrsToList
            (attr: sec:
              let
                e = sec.bitwarden or null;
                # The attribute name is NOT the lookup path: sops-nix resolves
                # a value with `sops.secrets.<attr>.key`, which merely defaults
                # to <attr>. nixfisical shipped a manifest that read <attr>
                # and failed mid-sync on the first secret that set `key`.
                sopsKey = sec.key or attr;
              in
              if e == null then null else
              (removeAttrs (normalizeEntry e) [ "name" ]) // {
                inherit sopsKey host;
                sopsFile =
                  if (sec.sopsFile or null) != null
                  then toString sec.sopsFile
                  else null;
                name = if e.name != null then e.name else lib.last (lib.splitString "/" sopsKey);
              })
            (node.config.sops.secrets or { }))
        nixosConfigurations;

      # Host-derived first, so that on a (sopsFile, sopsKey) collision the fold
      # keeps the host's destination and the export-only entry contributes
      # only its (empty) host list.
      flat = lib.filter (x: x != null) (lib.flatten perHost) ++ extraSecrets;

      # Dedupe on (sopsFile, sopsKey), not sopsKey alone: the same key path can
      # legitimately exist in two encrypted files. Hosts sharing an entry are
      # unioned into `hosts`, which the CLI treats as provenance, never as a
      # target.
      identity = e: "${toString e.sopsFile}#${e.sopsKey}";

      byKey = lib.foldl'
        (acc: e:
          let
            k = identity e;
            prev = acc.${k} or null;
            hosts = lib.optional (e.host != null) e.host;
          in
          acc // {
            ${k} =
              if prev == null
              then (removeAttrs e [ "host" ]) // { inherit hosts; }
              else prev // { hosts = lib.unique (prev.hosts ++ hosts); };
          })
        { }
        flat;
    in
    lib.sort (a: b: identity a < identity b) (lib.attrValues byKey);

  # Fail the evaluation on manifest problems that would otherwise surface as
  # a bw error halfway through a sync, or worse, as a well-formed item in the
  # wrong place. Cheap at `nix flake check` time; `nixwarden validate`
  # repeats these against the rendered JSON for anyone consuming the
  # manifest outside Nix.
  assertManifest = manifest:
    let
      isRef = v: builtins.isAttrs v;
      missingFile = lib.filter (e: (e.sopsFile or null) == null) manifest;
      emptyKey = lib.filter (e: e.sopsKey == "") manifest;
      noOrg = lib.filter (e: (e.org or "") == "") manifest;
      noCollection = lib.filter (e: (e.collection or "") == "") manifest;
      badType = lib.filter (e: !(lib.elem e.type types)) manifest;
      badField = lib.filter
        (e: lib.elem e.type types && !(lib.elem e.field (fieldsFor e.type)))
        manifest;
      # A login-only slot on a note or a key is a declaration that would be
      # silently dropped on write. Loud instead.
      loginOnly = lib.filter
        (e: e.type != "login" && (e.username != null || e.totp != null || e.uris != [ ]))
        manifest;
      # The anchor lands in `username` but a username was also declared:
      # two values for one slot, and which wins would depend on code order.
      doubled = lib.filter
        (e: (e.field == "username" && e.username != null)
          || (e.field == "totp" && e.totp != null)
          || (e.field == "notes" && e.notes != null))
        manifest;
      emptyRef = lib.filter
        (e: lib.any (v: isRef v && v.sopsKey == "")
          ([ e.username e.totp e.notes ] ++ map (f: f.value) e.fields))
        manifest;
      # The marker field is how the CLI tells its own items from a person's.
      # A declaration that reuses the name would be overwritten on every
      # sync and read as "managed" on every prune.
      markerClash = lib.filter
        (e: lib.any (f: f.name == "nixwarden") e.fields)
        manifest;
      # Two entries writing the same vault coordinate: one wins, and which
      # one depends on manifest ordering.
      coordinate = e: "${e.org}/${e.collection}:${e.name}";
      dupDest =
        let
          counts = lib.foldl'
            (acc: e: acc // { ${coordinate e} = (acc.${coordinate e} or 0) + 1; })
            { }
            manifest;
        in
        lib.filter (e: counts.${coordinate e} > 1) manifest;

      err = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " (e: e.sopsKey) entries}";
      errBy = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " coordinate entries}";

      problems =
        (err "secrets with no sopsFile (set sops.defaultSopsFile or a per-secret sopsFile)" missingFile)
        ++ (errBy "whole-file secrets (key = \"\") cannot be mirrored; name a key" emptyKey)
        ++ (err "entries without an org" noOrg)
        ++ (err "entries without a collection" noCollection)
        ++ (err "type must be one of ${lib.concatStringsSep ", " types}" badType)
        ++ (err "field is not valid for the item type" badField)
        ++ (err "username, totp and uris only apply to login items" loginOnly)
        ++ (err "the anchored value and a declared value both target the same slot" doubled)
        ++ (err "a ref with an empty sopsKey" emptyRef)
        ++ (err "a custom field named \"nixwarden\" is reserved for the managed marker" markerClash)
        ++ (errBy "two secrets declared into the same vault item" dupDest);
    in
    if problems == [ ]
    then manifest
    else throw "nixwarden: invalid Bitwarden manifest:\n  - ${lib.concatStringsSep "\n  - " problems}";
}
