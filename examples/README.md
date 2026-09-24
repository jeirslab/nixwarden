# Reference declarations

Each file is one shape of declaration, commented. They are not evaluated by
the flake's checks (the fixture fleet in `flake.nix` is), so read them as
documentation with the compiler's honesty rather than as a test suite.

| file                    | shows                                                   |
| ----------------------- | ------------------------------------------------------- |
| `00-minimal.nix`        | one login, the smallest annotation that does something  |
| `10-login.nix`          | username from another key, uris, totp, custom fields    |
| `20-notes-and-keys.nix` | an age key as a secure note, an SSH key as an SSH key   |
| `30-export-only.nix`    | a bootstrapped person's password no host consumes       |
| `99-jeirslab.nix`       | the homelab wiring: flake input, module, sync app, .env |
