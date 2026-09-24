from __future__ import annotations

from pathlib import Path

import pytest

from nixwarden import credentials
from nixwarden.sops import SopsError

ENV = {
    "BITWARDEN_SERVER_URL": "https://vault.example/",
    "BW_CLIENTID": "user.1",
    "BW_CLIENTSECRET": "s3",
    "BITWARDEN_USER_PASSWORD": "pw",
}


def test_env_alone(monkeypatch):
    c = credentials.resolve(environ=ENV)
    assert c.server_url == "https://vault.example/"
    assert c.password == "pw"
    assert "pw" not in repr(c) and "s3" not in repr(c)


def test_flag_beats_env():
    c = credentials.resolve(url="https://other.example", environ=ENV)
    assert c.server_url == "https://other.example"


def test_bw_password_alias():
    env = {**ENV}
    env.pop("BITWARDEN_USER_PASSWORD")
    env["BW_PASSWORD"] = "alias"
    assert credentials.resolve(environ=env).password == "alias"


def test_admin_file_fills_gaps(tmp_path: Path):
    f = tmp_path / "admin.yaml"
    f.write_text("placeholder")
    store = {"server_url": "https://from-file", "client_id": "cid", "client_secret": "cs", "password": "fpw"}

    def read(path, key):
        if key in store:
            return store[key]
        raise SopsError(f"sops key {key!r} not found in {path}")

    env = {"BW_CLIENTID": "env-id"}
    c = credentials.resolve(admin_file=f, environ=env, read_key=read)
    assert c.client_id == "env-id"  # env wins over file
    assert c.client_secret == "cs" and c.password == "fpw" and c.server_url == "https://from-file"


def test_every_missing_value_reported_at_once():
    with pytest.raises(credentials.CredentialsError) as exc:
        credentials.resolve(environ={})
    text = str(exc.value)
    for name in ("BITWARDEN_SERVER_URL", "BW_CLIENTID", "BW_CLIENTSECRET", "BITWARDEN_USER_PASSWORD"):
        assert name in text


def test_missing_admin_file():
    with pytest.raises(credentials.CredentialsError, match="not found"):
        credentials.resolve(admin_file=Path("/nonexistent/admin.yaml"), environ=ENV)


def test_bad_scheme():
    with pytest.raises(credentials.CredentialsError, match="http"):
        credentials.resolve(environ={**ENV, "BITWARDEN_SERVER_URL": "vault.example"})
