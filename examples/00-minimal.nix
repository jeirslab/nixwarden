# The smallest declaration that does something.
#
# One host, one secret, one vault item. `org` and `collection` are names as
# the vault shows them; `name` defaults to the last segment of the key path
# ("admin_password" here), which is legible and usually worth overriding.
{ nixwarden, ... }:

{
  imports = [ nixwarden.nixosModules.export ];

  sops.defaultSopsFile = ./secrets/grafana.yaml;

  sops.secrets."grafana/admin_password".bitwarden = nixwarden.lib.mkLogin {
    org = "lab";
    collection = "infrastructure";
    name = "Grafana admin";
    username = "admin";
    uris = [ "https://grafana.example" ];
  };
}
