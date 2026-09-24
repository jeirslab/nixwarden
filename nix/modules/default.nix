# The whole option surface, which today is the `sops.secrets.<key>.bitwarden`
# annotation and nothing else.
#
# There is no server module and no plan for one: nixpkgs already ships
# `services.vaultwarden`, and this flake's job is what happens between a SOPS
# file and a running vault, not running the vault. `flake.nixosModules.export`
# is the same file under the name a consumer will look for first.
{
  imports = [ ./export.nix ];
}
