"""``read_key`` against the real ``sops`` binary, with a throwaway age key.

Offline: age is local key material. The keypair below is committed on purpose
and is worth exactly nothing; it protects fixtures in a tmpdir. The suite
skips itself when ``sops`` is not on PATH; the Nix build puts it in
``nativeCheckInputs`` so in the build that matters it always runs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nixwarden.sops import SopsError, clear_cache, read_key, top_level_keys

pytestmark = pytest.mark.skipif(shutil.which("sops") is None, reason="needs the sops binary")

AGE_IDENTITY = "AGE-SECRET-KEY-17W9RA7P52C96QDZAU2AQY7ASY6YW8DZEYZCF7QEERA8N6MUYCXAQ4CXNVU"
AGE_RECIPIENT = "age1qq2nt909u726s3fsq9y3p645z8zthcg595y4mf5ly9ed90cc0fjsxls6fd"


@pytest.fixture
def encrypted(tmp_path: Path, monkeypatch) -> Path:
    key = tmp_path / "age.txt"
    key.write_text(AGE_IDENTITY + "\n")
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(key))
    plain = tmp_path / "plain.yaml"
    plain.write_text(
        "svc:\n  password: hunter2\n  user: admin\n  port: 5432\n  tls: true\nempty: \"\"\nkey: |\n  line1\n  line2\n"
    )
    out = tmp_path / "secrets.yaml"
    subprocess.run(
        ["sops", "--encrypt", "--age", AGE_RECIPIENT, "--input-type", "yaml", "--output-type", "yaml",
         "--output", str(out), str(plain)],
        check=True, capture_output=True,
    )
    plain.unlink()
    clear_cache()
    return out


def test_read_nested_and_coerced(encrypted: Path):
    assert read_key(encrypted, "svc/password") == "hunter2"
    assert read_key(encrypted, "svc/port") == "5432"
    assert read_key(encrypted, "svc/tls") == "true"
    assert read_key(encrypted, "empty") == ""
    assert read_key(encrypted, "key") == "line1\nline2\n"


def test_missing_key_names_path_not_values(encrypted: Path):
    with pytest.raises(SopsError) as exc:
        read_key(encrypted, "svc/nope")
    assert "hunter2" not in str(exc.value) and "svc/nope" in str(exc.value)


def test_mapping_is_not_a_value(encrypted: Path):
    with pytest.raises(SopsError, match="not a value"):
        read_key(encrypted, "svc")


def test_decrypts_once(encrypted: Path, monkeypatch):
    calls = []
    real = subprocess.run

    def spy(args, **kw):
        if args and args[0] == "sops":
            calls.append(args)
        return real(args, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    clear_cache()
    read_key(encrypted, "svc/password")
    read_key(encrypted, "svc/user")
    assert len(calls) == 1


def test_top_level_keys_excludes_sops(encrypted: Path):
    assert top_level_keys(encrypted) == {"svc", "empty", "key"}


def test_wrong_key_is_an_error(encrypted: Path, tmp_path: Path, monkeypatch):
    other = tmp_path / "other.txt"
    subprocess.run(["age-keygen", "-o", str(other)], check=True, capture_output=True) if shutil.which("age-keygen") else other.write_text("AGE-SECRET-KEY-1NOPE\n")
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(other))
    clear_cache()
    with pytest.raises(SopsError):
        read_key(encrypted, "svc/password")
