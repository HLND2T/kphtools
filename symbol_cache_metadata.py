"""Validated identities for binary directories materialized from the CI cache."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

ENTRY_NAME = ".ci-cache-entry.json"
SCHEMA_VERSION = 1
ARCHES = ("amd64", "arm64")
SHA256_PATTERN = r"[0-9a-f]{64}"


def cache_namespace(repository: str, platform: str) -> str:
    """Use one symbol store for every runner OS, retaining the platform argument."""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    if repository.split("/")[-1] in (".", "..") or platform not in ("Windows", "Linux", "macOS"):
        raise ValueError("Invalid cache identity")
    digest = hashlib.sha256(repository.lower().encode()).hexdigest()
    return f"kphtools-symbols-v2/{digest}/shared"


def parse_shard_id(value: str) -> dict[str, str]:
    parts = value.split("/")
    if len(parts) != 3 or parts[0] not in ARCHES or not re.fullmatch(SHA256_PATTERN, parts[2]):
        raise ValueError(f"Invalid symbol shard identity: {value}")
    match = re.fullmatch(r"([A-Za-z0-9_][A-Za-z0-9_.-]*)\.([0-9]+(?:\.[0-9]+){3})", parts[1])
    if match is None:
        raise ValueError(f"Invalid binary version directory: {parts[1]}")
    return {"arch": parts[0], "file": match[1], "version": match[2], "sha256": parts[2]}


def validate_metadata(shard_id: str, metadata: dict) -> dict[str, str]:
    identity = parse_shard_id(shard_id)
    if not isinstance(metadata, dict) or any(metadata.get(name) != value for name, value in identity.items()):
        raise ValueError("Cached PE metadata does not match the shard identity")
    for name in ("timestamp", "size"):
        value = metadata.get(name)
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
            raise ValueError(f"Invalid cached PE {name}")
    if int(metadata["size"], 16) <= 0:
        raise ValueError("Invalid cached PE image size")
    return metadata


def load_cached_entry(binary_dir: Path) -> dict | None:
    path = Path(binary_dir) / ENTRY_NAME
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError("Cached metadata must not be a link")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        raise ValueError("Unsupported cached metadata schema")
    shard_id = "/".join(Path(binary_dir).parts[-3:])
    if data.get("shard_id") != shard_id or not isinstance(data.get("shard"), dict):
        raise ValueError("Cached metadata belongs to a different binary directory")
    validate_metadata(shard_id, data["shard"].get("metadata"))
    if not isinstance(data.get("inputs_restored"), bool):
        raise ValueError("Invalid cached input materialization state")
    return data


def cached_binary_exists(binary_dir: Path, file_name: str) -> bool:
    entry = load_cached_entry(binary_dir)
    return entry is not None and entry["shard"]["metadata"]["file"] == file_name


def cached_pe_metadata(binary_path: Path) -> dict[str, str] | None:
    entry = load_cached_entry(Path(binary_path).parent)
    if entry is None or entry["shard"]["metadata"]["file"] != Path(binary_path).name:
        return None
    metadata = entry["shard"]["metadata"]
    return {name: metadata[name] for name in ("timestamp", "size", "sha256")}
