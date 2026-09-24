"""A logged-in, unlocked vault behind a local ``bw serve``.

Why ``bw serve`` and not the CLI per call: every ``bw`` invocation is a Node
process that re-reads and re-decrypts its state, so a fifty-item sync done as
fifty ``bw create`` calls is a minute of startup time and nothing else. The
daemon pays that once and answers everything after over loopback HTTP.

Why not the server's REST API directly: vault items are end-to-end encrypted
with keys the server never sees. Encrypting an item is a client-side
operation, and ``bw`` is the client. The Public API that needs no master
password manages members and collections, not items.

Three things here were learned in the nexus key scripts and are kept:

* Bind and dial ``127.0.0.1`` explicitly. With ``localhost`` a daemon already
  on ``127.0.0.1`` lets a second one bind ``[::1]`` on the same port, and the
  client then alternates between the two (one unlocked, one locked) -- every
  later call fails with a bare HTTP 400.
* The ``bw`` state directory is a throwaway by default
  (``BITWARDENCLI_APPDATA_DIR`` pointed at a fresh temp dir). The operator's
  own ``bw`` login, on whatever server it is on, is neither read nor
  disturbed, and "already logged in to a different server" cannot happen.
  An API-key login is one round trip, so this costs nothing worth keeping.
* The master password reaches the daemon in the ``/unlock`` request body and
  nowhere else: not on a command line, not in the environment of a child
  process, never in a log line.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from nixwarden.credentials import Credentials

__all__ = ["BwError", "Vault"]


class BwError(RuntimeError):
    """The ``bw`` CLI or its daemon refused. The message never carries a value."""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Vault:
    """Context manager: log in with the API key, serve, unlock, sync; lock and
    tear down on exit.

    ``client`` can be injected for tests (an ``httpx.Client`` over a
    ``MockTransport``); the process-management half is then skipped entirely.
    """

    def __init__(
        self,
        creds: Credentials,
        *,
        appdata: Path | None = None,
        bw: str = "bw",
        start_timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.creds = creds
        self.bw = bw
        self.start_timeout = start_timeout
        self._appdata = Path(appdata) if appdata is not None else None
        self._owns_appdata = appdata is None
        self._proc: subprocess.Popen[bytes] | None = None
        self._client = client
        self.base_url: str | None = None

    # -- process management ---------------------------------------------

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        assert self._appdata is not None
        env["BITWARDENCLI_APPDATA_DIR"] = str(self._appdata)
        env["BW_CLIENTID"] = self.creds.client_id
        env["BW_CLIENTSECRET"] = self.creds.client_secret
        env["BW_NOINTERACTION"] = "true"
        # A session key from the operator's own shell would make `bw` think
        # it is unlocked against a vault it is not logged in to.
        env.pop("BW_SESSION", None)
        return env

    def _bw(self, *args: str) -> str:
        try:
            proc = subprocess.run(
                [self.bw, *args, "--nointeraction"],
                env=self._env(),
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise BwError(f"the `{self.bw}` binary is not on PATH") from exc
        if proc.returncode != 0:
            detail = (proc.stderr.strip() or proc.stdout.strip() or f"exit status {proc.returncode}")
            raise BwError(f"bw {args[0]} failed: {detail}")
        return proc.stdout

    def cli_status(self) -> dict[str, Any]:
        """``bw status`` -- serverUrl / userEmail / status, before the daemon is up."""
        out = self._bw("status")
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise BwError("bw status did not return JSON") from exc

    def open(self) -> "Vault":
        if self._client is not None:
            return self
        if self._appdata is None:
            self._appdata = Path(tempfile.mkdtemp(prefix="nixwarden-bw-"))
            os.chmod(self._appdata, 0o700)
        else:
            self._appdata.mkdir(parents=True, exist_ok=True)

        want = self.creds.server_url.rstrip("/")
        status = self.cli_status()
        have = (status.get("serverUrl") or "").rstrip("/")
        if status.get("status") == "unauthenticated":
            if have != want:
                self._bw("config", "server", want)
            self._bw("login", "--apikey")
        elif have != want:
            raise BwError(
                f"{self._appdata} is logged in to {have or 'the default server'}, not {want}; "
                "use a different --appdata or log that one out"
            )

        port = _free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        try:
            self._proc = subprocess.Popen(
                [self.bw, "serve", "--hostname", "127.0.0.1", "--port", str(port)],
                env=self._env(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise BwError(f"the `{self.bw}` binary is not on PATH") from exc
        self._client = httpx.Client(base_url=self.base_url, timeout=120.0)

        deadline = time.monotonic() + self.start_timeout
        while True:
            if self._proc.poll() is not None:
                self.close()
                raise BwError("bw serve exited before it started listening")
            try:
                if self._client.get("/status").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                self.close()
                raise BwError(f"bw serve did not start on {self.base_url} within {self.start_timeout:.0f}s")
            time.sleep(0.1)

        try:
            self._req("POST", "/unlock", json={"password": self.creds.password}, what="unlock")
            self._req("POST", "/sync", what="sync")
        except BwError:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._client is not None and self._proc is not None:
            try:
                self._client.post("/lock", timeout=5.0)
            except httpx.HTTPError:
                pass
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        if self._owns_appdata and self._appdata is not None:
            shutil.rmtree(self._appdata, ignore_errors=True)
            self._appdata = None

    def __enter__(self) -> "Vault":
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- HTTP ------------------------------------------------------------

    def _req(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        what: str | None = None,
    ) -> Any:
        assert self._client is not None, "vault is not open"
        label = what or f"{method} {path}"
        try:
            response = self._client.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise BwError(f"{label}: {exc.__class__.__name__}") from exc
        try:
            body = response.json()
        except ValueError as exc:
            # The daemon's own crash page (an express "Internal Server Error"),
            # never a vault value: the request that failed is the one whose
            # body it would have echoed, and express does not echo bodies.
            snippet = " ".join(re.sub(r"<[^>]*>", " ", response.text).split())[:160]
            raise BwError(
                f"{label}: HTTP {response.status_code} with a non-JSON body"
                + (f" ({snippet})" if snippet else "")
                + (" -- bw serve crashed on unlock; this is a known failure of bitwarden-cli "
                   "2026.9.0 against Vaultwarden, use the pinned 2026.8.0 (`--bw`)"
                   if path == "/unlock" and response.status_code == 500 else "")
            ) from exc
        if not isinstance(body, dict) or not body.get("success"):
            message = body.get("message") if isinstance(body, dict) else None
            raise BwError(f"{label}: {message or f'HTTP {response.status_code}'}")
        return body.get("data")

    @staticmethod
    def _list(data: Any) -> list[dict[str, Any]]:
        # `/list/object/*` wraps its array one level deeper than `/object/*`.
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return data["data"]
        if isinstance(data, list):
            return data
        raise BwError("unexpected list shape from bw serve")

    # -- vault operations -----------------------------------------------

    def status(self) -> dict[str, Any]:
        data = self._req("GET", "/status")
        return data.get("template", data) if isinstance(data, dict) else {}

    def organizations(self) -> list[dict[str, Any]]:
        return self._list(self._req("GET", "/list/object/organizations"))

    def org_collections(self, org_id: str) -> list[dict[str, Any]]:
        return self._list(
            self._req("GET", "/list/object/org-collections", params={"organizationId": org_id})
        )

    def items(self, org_id: str) -> list[dict[str, Any]]:
        """Every non-trashed item of the organization the login can see."""
        return self._list(self._req("GET", "/list/object/items", params={"organizationId": org_id}))

    def create_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return self._req("POST", "/object/item", json=item, what=f"create item {item.get('name')!r}")

    def update_item(self, item_id: str, item: dict[str, Any]) -> dict[str, Any]:
        return self._req("PUT", f"/object/item/{item_id}", json=item, what=f"update item {item.get('name')!r}")

    def delete_item(self, item_id: str, *, permanent: bool = False) -> None:
        """Move an item to the trash. ``permanent`` skips the trash, and no
        command in this tool sets it: a pruned item that can be restored for
        thirty days is the difference between a typo and an incident."""
        params = {"permanent": "true"} if permanent else None
        self._req("DELETE", f"/object/item/{item_id}", params=params, what="delete item")

    def create_org_collection(self, org_id: str, name: str) -> dict[str, Any]:
        """Create a collection. ``users`` is omitted on purpose: ``bw`` then
        grants the creating user `manage` on it, which is what lets the next
        sync write into it. ``groups`` stays empty -- who else may read the
        collection is an access decision for the vault UI, not this tool."""
        body = {"organizationId": org_id, "name": name, "externalId": None, "groups": []}
        return self._req(
            "POST",
            "/object/org-collection",
            params={"organizationId": org_id},
            json=body,
            what=f"create collection {name!r}",
        )
