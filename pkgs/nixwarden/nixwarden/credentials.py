"""Where the vault credentials come from.

Four values are needed to write to a Bitwarden-compatible vault, and there is
no getting below four:

* the server URL;
* a personal API key (client id + client secret), which logs the CLI in past
  2FA without a browser;
* the master password, which unlocks the vault. This one is not optional and
  not a limitation of this tool: vault items are end-to-end encrypted with a
  key derived from it, and the API key alone cannot decrypt or encrypt
  anything. The Public (organization) API is different -- it needs no master
  password -- but it manages members and collections, not items.

Each value is read from, in order: a command-line flag where one exists, the
environment, then an optional SOPS-encrypted admin file. The environment
names are the ones the ``bw`` CLI and the nexus key scripts already use, so
one ``.env`` serves all of them::

    BITWARDEN_SERVER_URL      https://vault.example.org
    BW_CLIENTID               user.xxxxxxxx-…
    BW_CLIENTSECRET           …
    BITWARDEN_USER_PASSWORD   the master password (BW_PASSWORD also accepted)

The admin file holds the same four under ``server_url``, ``client_id``,
``client_secret`` and ``password``, top-level. It is the right home for an
estate's sync credentials: encrypted to the same age key the secrets are, so
whoever can run the sync can read it and nobody else can.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from nixwarden import sops

__all__ = ["Credentials", "CredentialsError", "resolve"]


class CredentialsError(RuntimeError):
    pass


@dataclass(frozen=True)
class Credentials:
    server_url: str
    client_id: str
    client_secret: str
    password: str

    def __repr__(self) -> str:  # never print the secret half
        return f"Credentials(server_url={self.server_url!r}, client_id={self.client_id!r})"


#: field -> (environment variable names, admin-file key)
_SOURCES: dict[str, tuple[tuple[str, ...], str]] = {
    "server_url": (("BITWARDEN_SERVER_URL",), "server_url"),
    "client_id": (("BW_CLIENTID",), "client_id"),
    "client_secret": (("BW_CLIENTSECRET",), "client_secret"),
    "password": (("BITWARDEN_USER_PASSWORD", "BW_PASSWORD"), "password"),
}


def resolve(
    *,
    url: str | None = None,
    admin_file: Path | None = None,
    environ: dict[str, str] | None = None,
    read_key: Callable[[Path, str], str] = sops.read_key,
) -> Credentials:
    """Assemble credentials from flag, environment and admin file, in that order.

    Every missing value is reported at once, each with both places it could
    have come from, because "set BW_CLIENTSECRET" followed by "set
    BITWARDEN_USER_PASSWORD" on the next run is the kind of loop a tool
    should not put a person in.
    """
    env = os.environ if environ is None else environ
    values: dict[str, str] = {}
    missing: list[str] = []

    if admin_file is not None and not Path(admin_file).is_file():
        raise CredentialsError(f"admin file not found: {admin_file}")

    for field, (env_names, file_key) in _SOURCES.items():
        value: str | None = None
        if field == "server_url" and url:
            value = url
        if value is None:
            for name in env_names:
                if env.get(name):
                    value = env[name]
                    break
        if value is None and admin_file is not None:
            try:
                candidate = read_key(Path(admin_file), file_key)
            except sops.SopsError as exc:
                if "not found in" in str(exc):
                    candidate = ""
                else:
                    raise CredentialsError(str(exc)) from exc
            if candidate:
                value = candidate
        if value is None:
            where = " or ".join(env_names)
            if admin_file is not None:
                where += f", or {file_key!r} in {admin_file}"
            elif field == "server_url":
                where += ", or --url"
            missing.append(f"{field}: set {where}")
        else:
            values[field] = value.strip() if field == "server_url" else value

    if missing:
        raise CredentialsError(
            "vault credentials incomplete:\n  - " + "\n  - ".join(missing)
            + "\n(pass --admin-file <sops yaml> to read them from an encrypted file)"
        )
    if not values["server_url"].startswith(("http://", "https://")):
        raise CredentialsError(f"server url must start with http:// or https://: {values['server_url']!r}")
    return Credentials(**values)
