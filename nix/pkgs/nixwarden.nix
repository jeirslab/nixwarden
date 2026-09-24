# The `nixwarden` CLI, wrapped with the binaries it shells out to.
#
# `bw` (bitwarden-cli) is the hard runtime dependency: every write goes through
# a local `bw serve`, because vault items are end-to-end encrypted and `bw` is
# the client that holds the keys. `sops` decrypts every value the reconciler
# pushes, on the operator's machine, at run time. `ssh-keygen` derives the
# public half of an ssh-key item from its private key so the vault shows a
# fingerprint; it is a small closure and the item is written without it if
# it were ever absent.
#
# `--prefix PATH` rather than `--set`: the caller's own PATH stays intact, so
# an operator who prefers their own `bw` build can point `--bw` at it.
{ lib
, python3Packages
, bitwarden-cli
, sops
, openssh
, makeWrapper
}:

python3Packages.buildPythonApplication rec {
  pname = "nixwarden";
  version = "0.1.0";
  pyproject = true;

  src = ../../pkgs/nixwarden;

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    click
    httpx
    pyyaml
  ];

  nativeBuildInputs = [ makeWrapper ];

  # Offline-only: no daemon, no network, no vault. The planner is pure and
  # the client is tested over a mock transport. `sops` and `ssh-keygen` are
  # here for the two suites that exercise a real binary against throwaway
  # material in a tmpdir; both skip themselves when the binary is absent,
  # which is exactly why these two lines are load-bearing -- without them
  # the tests do not fail, they silently stop running.
  nativeCheckInputs = [ python3Packages.pytestCheckHook sops openssh ];

  postFixup = ''
    wrapProgram $out/bin/nixwarden \
      --prefix PATH : ${lib.makeBinPath [ bitwarden-cli sops openssh ]}
  '';

  pythonImportsCheck = [
    "nixwarden"
    "nixwarden.bw"
    "nixwarden.cli"
    "nixwarden.credentials"
    "nixwarden.items"
    "nixwarden.manifest"
    "nixwarden.reconcile"
    "nixwarden.sops"
  ];

  meta = with lib; {
    description = "Mirror sops-declared secrets into Bitwarden / Vaultwarden, declared in Nix";
    homepage = "https://github.com/jeirslab/nixwarden";
    license = licenses.mit;
    mainProgram = "nixwarden";
    platforms = platforms.unix;
  };
}
