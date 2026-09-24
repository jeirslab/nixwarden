from __future__ import annotations

from typing import Any

import pytest


def entry(**over: Any) -> dict[str, Any]:
    """A valid login entry; override what the test is about."""
    base: dict[str, Any] = {
        "sopsKey": "svc/password",
        "sopsFile": "/tmp/secrets.yaml",
        "hosts": ["host-a"],
        "org": "lab",
        "collection": "infra",
        "name": "svc admin",
        "type": "login",
        "field": "password",
        "username": "admin",
        "uris": ["https://svc.example"],
        "totp": None,
        "notes": None,
        "fields": [],
        "favorite": False,
        "reprompt": False,
    }
    base.update(over)
    return base


@pytest.fixture
def make_entry():
    return entry


@pytest.fixture
def resolver():
    values = {
        ("/tmp/secrets.yaml", "svc/password"): "hunter2",
        ("/tmp/secrets.yaml", "svc/user"): "generated-user",
        ("/tmp/secrets.yaml", "svc/token"): "tok-123",
        ("/tmp/secrets.yaml", "age/key"): "AGE-SECRET-KEY-1XYZ\n",
        ("/tmp/other.yaml", "x/y"): "other-value",
    }

    def read(file: str, key: str) -> str:
        try:
            return values[(file, key)]
        except KeyError:
            from nixwarden.sops import SopsError
            raise SopsError(f"sops key {key!r} not found in {file}")

    return read
