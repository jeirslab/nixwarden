"""Thin, secret-safe wrapper around the ``sops`` binary — the read side only.

We shell out rather than binding libsops because the operator's key material
(age keys, GPG agents, KMS profiles) is already wired into their environment
for the ``sops`` CLI; reimplementing that resolution would be a new and worse
source of "works on my machine".

Two rules govern everything here:

1. **A decrypted value never reaches a log, an exception message, or stdout.**
   Errors name the file and the key path only. ``sops`` writes its diagnostics
   to stderr and its plaintext to stdout, so the two are captured separately
   and only stderr is ever propagated.
2. **Decrypt each file at most once per process.** A 50-item manifest whose
   values live in one file pays one key unwrap (and, with a hardware-backed
   key, one touch), not fifty. :func:`read_key` decrypts a file once, caches
   the parsed document, and indexes into it.

This module never writes an encrypted file. nixwarden mirrors SOPS into the
vault and nothing flows back; the write side that nixfisical carries for its
``import`` command has no counterpart here, on purpose.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "SopsError",
    "clear_cache",
    "decrypt_yaml",
    "read_key",
    "scalar_text",
    "top_level_keys",
]


class SopsError(RuntimeError):
    """``sops`` failed. The message carries its stderr and never its stdout."""


def _run(args: list[str], *, what: str) -> str:
    try:
        proc = subprocess.run(
            ["sops", *args],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SopsError("the `sops` binary is not on PATH") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"exit status {proc.returncode}"
        raise SopsError(f"sops failed to {what}: {detail}")
    return proc.stdout


_CACHE: dict[str, dict[str, Any]] = {}


def _cache_key(file: Path) -> str:
    return str(Path(file).resolve())


def clear_cache() -> None:
    """Forget every decrypted document. Tests call this between cases."""
    _CACHE.clear()


def decrypt_yaml(file: Path, *, use_cache: bool = True) -> dict[str, Any]:
    """Decrypt ``file`` (YAML) to a dict, at most once per process.

    The whole document is held in memory for the life of the process. That is
    the trade the cache makes, and it is the right one for a CLI whose entire
    run is "decrypt, push, exit".
    """
    file = Path(file)
    key = _cache_key(file)
    if use_cache and key in _CACHE:
        return _CACHE[key]
    if not file.is_file():
        raise SopsError(f"sops file not found: {file}")
    text = _run(
        ["--decrypt", "--output-type", "yaml", str(file)],
        what=f"decrypt {file}",
    )
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # The parser's message can quote the offending line, which would be
        # plaintext. Name the file and nothing else.
        raise SopsError(f"decrypted {file} is not valid YAML") from exc
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise SopsError(f"decrypted {file} is not a mapping at the top level")
    if use_cache:
        _CACHE[key] = document
    return document


def scalar_text(value: Any) -> str:
    """Coerce a YAML scalar to the string Bitwarden will store.

    YAML happily parses ``12345`` as an int and ``yes`` as a bool; a vault
    field is a string. Booleans are normalised to lowercase so a value that
    was written ``true`` does not come back ``True``.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    raise SopsError(f"value is a {type(value).__name__}, not a scalar")


def _segments(sops_key: str) -> list[str]:
    parts = [p for p in sops_key.split("/") if p != ""]
    if not parts:
        raise SopsError("empty sops key")
    return parts


def read_key(file: Path, sops_key: str) -> str:
    """Return the value at ``sops_key`` (``a/b/c``) from ``file``, via the cache.

    Errors name the path that was missing and the segment it failed at, and
    never the siblings that were there — a key listing is metadata, but one
    that names a folder called ``prod-db-root`` is metadata worth not leaking
    into a log line.
    """
    document = decrypt_yaml(file)
    node: Any = document
    walked: list[str] = []
    for segment in _segments(sops_key):
        if not isinstance(node, dict) or segment not in node:
            where = "/".join(walked) or "<root>"
            raise SopsError(
                f"sops key {sops_key!r} not found in {file} (no {segment!r} under {where})"
            )
        node = node[segment]
        walked.append(segment)
    if isinstance(node, (dict, list)):
        raise SopsError(f"sops key {sops_key!r} in {file} is a {type(node).__name__}, not a value")
    return scalar_text(node)


def top_level_keys(file: Path) -> set[str]:
    """Top-level key names of a decrypted file, for diagnostics that must not
    quote values."""
    return {str(k) for k in decrypt_yaml(file).keys() if k != "sops"}
