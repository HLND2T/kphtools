"""Content-addressed S3 symbol shards with lightweight results and lazy inputs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile

from ci_s3_cache import parse_endpoint, validate_tree, YAML_SUFFIXES
from symbol_cache_metadata import (
    ARCHES, ENTRY_NAME, SCHEMA_VERSION, SHA256_PATTERN,
    load_cached_entry, parse_shard_id, validate_metadata,
)

BUCKET = "actions-cache-kphtools"
COMPONENTS = ("inputs", "results")
COPY_BUFFER_SIZE = 1024 * 1024
ZSTD_LEVEL = 1
MAX_COMPRESSION_THREADS = 4


class CatalogConflict(RuntimeError):
    """Another producer updated the catalog after this run's restore."""


def cache_namespace(repository: str, platform: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    if repository.split("/")[-1] in (".", "..") or platform not in ("Windows", "Linux", "macOS"):
        raise ValueError("Invalid cache identity")
    digest = hashlib.sha256(repository.lower().encode()).hexdigest()
    return f"kphtools-symbols-v2/{digest}/{platform.lower()}"


def _validate_namespace(value: str) -> None:
    if not re.fullmatch(r"kphtools-symbols-v2/[0-9a-f]{64}/(?:windows|linux|macos)", value):
        raise ValueError("Invalid cache namespace")


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(COPY_BUFFER_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


class S3Store:
    def __init__(self, client, bucket: str = BUCKET):
        self.client = client
        self.bucket = bucket

    @classmethod
    def from_environment(cls):
        import boto3
        from botocore.config import Config

        endpoint = os.environ.get("S3_ENDPOINT_URL", "")
        parse_endpoint(endpoint)
        credentials = {}
        for variable, argument in (
            ("S3_ACCESS_KEY_ID", "aws_access_key_id"),
            ("S3_SECRET_ACCESS_KEY", "aws_secret_access_key"),
        ):
            value = os.environ.get(variable, "")
            if not value.strip():
                raise ValueError(f"{variable} is required")
            credentials[argument] = value
        client = boto3.client(
            "s3", endpoint_url=endpoint, region_name="us-east-1", **credentials,
            config=Config(
                signature_version="s3v4", s3={"addressing_style": "path"},
                retries={"mode": "standard", "max_attempts": 3},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )
        return cls(client)

    def get_catalog(self, key):
        from botocore.exceptions import ClientError

        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as error:
            if error.response["Error"]["Code"] in ("NoSuchKey", "404", "NotFound"):
                return None, None
            raise
        body = response["Body"]
        try:
            return json.loads(body.read()), response["ETag"]
        finally:
            body.close()

    def put_catalog(self, key, value, etag):
        from botocore.exceptions import ClientError

        condition = {"IfMatch": etag} if etag is not None else {"IfNoneMatch": "*"}
        try:
            self.client.put_object(
                Bucket=self.bucket, Key=key, Body=_json_bytes(value),
                ContentType="application/json", **condition,
            )
        except ClientError as error:
            if error.response["Error"]["Code"] in ("PreconditionFailed", "412", "ConditionalRequestConflict", "409"):
                raise CatalogConflict("S3 catalog changed; restore the latest catalog and retry") from error
            raise

    def head(self, key):
        from botocore.exceptions import ClientError

        try:
            response = self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as error:
            if error.response["Error"]["Code"] in ("NoSuchKey", "404", "NotFound"):
                return None
            raise
        return {"size": response["ContentLength"], "sha256": response.get("Metadata", {}).get("sha256")}

    def upload(self, key, path, sha256):
        self.client.upload_file(str(path), self.bucket, key, ExtraArgs={"Metadata": {"sha256": sha256}})

    def download(self, key, path):
        self.client.download_file(self.bucket, key, str(path))


def _validate_ref(namespace: str, shard_id: str, component: str, ref: dict) -> None:
    if not isinstance(ref, dict):
        raise ValueError("Invalid shard reference")
    for name in ("digest", "archive_sha256"):
        if not isinstance(ref.get(name), str) or not re.fullmatch(SHA256_PATTERN, ref[name]):
            raise ValueError(f"Invalid shard {name}")
    expected = f"{namespace}/shards/{shard_id}/{component}/{ref['digest']}.tar.zst"
    if ref.get("key") != expected:
        raise ValueError("Shard object escapes the expected namespace")
    for name in ("archive_size", "unpacked_size", "file_count"):
        if type(ref.get(name)) is not int or ref[name] < (1 if name == "archive_size" else 0):
            raise ValueError(f"Invalid shard {name}")


def _validate_catalog(catalog: dict, namespace: str) -> dict:
    _validate_namespace(namespace)
    if (
        not isinstance(catalog, dict) or catalog.get("schema") != SCHEMA_VERSION
        or catalog.get("namespace") != namespace or not isinstance(catalog.get("shards"), dict)
    ):
        raise ValueError("Invalid symbol catalog")
    for shard_id, entry in catalog["shards"].items():
        if not isinstance(entry, dict):
            raise ValueError("Invalid catalog shard")
        validate_metadata(shard_id, entry.get("metadata"))
        for component in COMPONENTS:
            _validate_ref(namespace, shard_id, component, entry.get(component))
    return catalog


def _read_catalog(store, namespace: str) -> dict:
    value, etag = store.get_catalog(namespace + "/catalog.json")
    if value is None:
        value = {"schema": SCHEMA_VERSION, "namespace": namespace, "shards": {}}
    return {"catalog": _validate_catalog(value, namespace), "etag": etag}


def _component_files(root: Path, component: str) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if path.is_file() and path.name != ENTRY_NAME:
            is_result = path.suffix.lower() in YAML_SUFFIXES
            if is_result == (component == "results"):
                files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _inventory(root: Path, files: list[Path]) -> dict:
    records = [
        {"path": path.relative_to(root).as_posix(), "size": path.stat().st_size, "sha256": _sha256(path)}
        for path in files
    ]
    return {
        "digest": hashlib.sha256(_json_bytes({"files": records})).hexdigest(),
        "unpacked_size": sum(record["size"] for record in records),
        "file_count": len(records),
    }


def _write_archive(root: Path, files: list[Path], output: Path) -> None:
    import zstandard

    threads = min(MAX_COMPRESSION_THREADS, os.cpu_count() or 1)
    compressor = zstandard.ZstdCompressor(level=ZSTD_LEVEL, threads=threads, write_checksum=True)
    with output.open("xb") as raw, compressor.stream_writer(raw, closefd=False) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for path in files:
                info = tarfile.TarInfo(path.relative_to(root).as_posix())
                info.size = path.stat().st_size
                info.mode = 0o644
                # Archive identity is independent of checkout/manifest timestamps.
                info.mtime = 0
                with path.open("rb") as handle:
                    archive.addfile(info, handle)


def _safe_member(name: str) -> Path:
    path = PurePosixPath(name)
    if (
        not name or path.is_absolute() or "\\" in name or ":" in name
        or any(part in ("", ".", "..") for part in name.split("/"))
        or path.name == ENTRY_NAME
    ):
        raise ValueError("Unsafe symbol archive member")
    return Path(*path.parts)


def _restore_component(root: Path, store, ref: dict, component: str) -> None:
    import zstandard

    validate_tree(root)
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".symbol-shard-", dir=root.parent) as directory:
        temporary = Path(directory)
        archive_path = temporary / "archive.tar.zst"
        extracted = temporary / "contents"
        extracted.mkdir()
        store.download(ref["key"], archive_path)
        if archive_path.stat().st_size != ref["archive_size"] or _sha256(archive_path) != ref["archive_sha256"]:
            raise ValueError("Symbol shard checksum or size mismatch")
        seen = set()
        total = 0
        with archive_path.open("rb") as raw, zstandard.ZstdDecompressor().stream_reader(raw) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as archive:
                for member in archive:
                    relative = _safe_member(member.name)
                    if not member.isfile() or member.name.casefold() in seen:
                        raise ValueError("Symbol archive contains a link, directory, or duplicate")
                    seen.add(member.name.casefold())
                    if (relative.suffix.lower() in YAML_SUFFIXES) != (component == "results"):
                        raise ValueError("Symbol archive contains the wrong component")
                    total += member.size
                    if member.size < 0 or total > ref["unpacked_size"]:
                        raise ValueError("Symbol shard exceeds its declared size")
                    target = extracted / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, COPY_BUFFER_SIZE)
        inventory = _inventory(extracted, _component_files(extracted, component))
        if any(inventory[name] != ref[name] for name in ("digest", "file_count", "unpacked_size")):
            raise ValueError("Symbol shard content digest mismatch")
        root.mkdir(parents=True, exist_ok=True)
        for path in extracted.rglob("*"):
            if path.is_file():
                target = root / path.relative_to(extracted)
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(path, target)


def _write_entry(root: Path, namespace: str, shard_id: str, shard: dict, restored: bool) -> None:
    value = {
        "schema": SCHEMA_VERSION, "namespace": namespace, "shard_id": shard_id,
        "shard": shard, "inputs_restored": restored,
    }
    (root / ENTRY_NAME).write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def restore(
    symbols: Path, store, namespace: str, *, mode: str,
    arch: str | None = None, version: str | None = None,
) -> dict:
    if mode not in ("build", "pr"):
        raise ValueError("Invalid cache restore mode")
    if mode == "pr" and (arch not in ARCHES or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version or "")):
        raise ValueError("Invalid PR cache selection")
    validate_tree(symbols)
    symbols.mkdir(parents=True, exist_ok=True)
    base = _read_catalog(store, namespace)
    restored = 0
    for shard_id, shard in sorted(base["catalog"]["shards"].items()):
        metadata = shard["metadata"]
        if mode == "pr" and (
            metadata["arch"] != arch or metadata["file"] != "ntoskrnl.exe" or metadata["version"] != version
        ):
            continue
        root = symbols / shard_id
        component = "results" if mode == "build" else "inputs"
        _restore_component(root, store, shard[component], component)
        if mode == "build":
            _write_entry(root, namespace, shard_id, shard, False)
        restored += 1
    print(f"Restored {restored} {mode} symbol shard(s)", flush=True)
    return base


def ensure_binary_inputs(binary_dir: Path, *, store=None) -> bool:
    entry = load_cached_entry(binary_dir)
    if entry is None or entry["inputs_restored"]:
        return False
    namespace = entry["namespace"]
    _validate_namespace(namespace)
    shard_id = entry["shard_id"]
    shard = entry["shard"]
    _validate_ref(namespace, shard_id, "inputs", shard["inputs"])
    validate_tree(binary_dir)
    if _component_files(binary_dir, "inputs"):
        raise ValueError("Cached inputs are only partially materialized")
    print(f"Hydrating analysis inputs for {shard_id}", flush=True)
    _restore_component(binary_dir, store or S3Store.from_environment(), shard["inputs"], "inputs")
    binary = binary_dir / shard["metadata"]["file"]
    if not binary.is_file() or _sha256(binary) != shard["metadata"]["sha256"]:
        raise ValueError("Restored PE does not match the symbol shard identity")
    _write_entry(binary_dir, namespace, shard_id, shard, True)
    return True


def _metadata_from_pe(binary: Path) -> dict[str, str]:
    import pefile

    pe = pefile.PE(str(binary), fast_load=True)
    try:
        return {"timestamp": hex(pe.FILE_HEADER.TimeDateStamp), "size": hex(pe.OPTIONAL_HEADER.SizeOfImage)}
    finally:
        pe.close()


def _publish_component(root: Path, files: list[Path], store, namespace, shard_id, component, prior):
    inventory = _inventory(root, files)
    if prior is not None and prior["digest"] == inventory["digest"]:
        return prior
    key = f"{namespace}/shards/{shard_id}/{component}/{inventory['digest']}.tar.zst"
    existing = store.head(key)
    if existing is None:
        with tempfile.TemporaryDirectory(prefix="kphtools-symbol-upload-") as directory:
            archive = Path(directory) / "archive.tar.zst"
            _write_archive(root, files, archive)
            if _inventory(root, _component_files(root, component)) != inventory:
                raise ValueError("Symbol shard changed while being archived")
            archive_sha256 = _sha256(archive)
            size = archive.stat().st_size
            store.upload(key, archive, archive_sha256)
            existing = store.head(key)
            if existing != {"size": size, "sha256": archive_sha256}:
                raise ValueError("Published shard verification failed")
    if (
        type(existing.get("size")) is not int or existing["size"] <= 0
        or not isinstance(existing.get("sha256"), str) or not re.fullmatch(SHA256_PATTERN, existing["sha256"])
    ):
        raise ValueError("Existing shard has invalid publication metadata")
    return {**inventory, "key": key, "archive_size": existing["size"], "archive_sha256": existing["sha256"]}


def publish(symbols: Path, store, namespace: str, *, base=None, metadata_reader=None) -> dict:
    validate_tree(symbols)
    base = base if base is not None else _read_catalog(store, namespace)
    previous = _validate_catalog(base["catalog"], namespace)
    catalog = copy.deepcopy(previous)
    directories = sorted(
        root for arch in ARCHES for root in (symbols / arch).glob("*/*") if root.is_dir()
    )
    for root in directories:
        shard_id = root.relative_to(symbols).as_posix()
        identity = parse_shard_id(shard_id)
        prior = previous["shards"].get(shard_id)
        marker = load_cached_entry(root)
        binary = root / identity["file"]
        if binary.is_file():
            if _sha256(binary) != identity["sha256"]:
                raise ValueError(f"PE hash does not match its directory: {shard_id}")
            metadata = {**identity, **(metadata_reader or _metadata_from_pe)(binary)}
        elif marker is not None:
            metadata = marker["shard"]["metadata"]
        else:
            raise ValueError(f"Symbol shard has no PE or cached metadata: {shard_id}")
        validate_metadata(shard_id, metadata)
        results = _publish_component(
            root, _component_files(root, "results"), store, namespace, shard_id, "results",
            prior["results"] if prior else None,
        )
        inputs = _component_files(root, "inputs")
        if marker is not None and not marker["inputs_restored"]:
            if inputs or prior is None or prior != marker["shard"]:
                raise ValueError("Partial symbol inputs cannot replace an existing shard")
            input_ref = prior["inputs"]
        else:
            input_ref = _publish_component(
                root, inputs, store, namespace, shard_id, "inputs", prior["inputs"] if prior else None,
            )
        catalog["shards"][shard_id] = {"metadata": metadata, "inputs": input_ref, "results": results}
    _validate_catalog(catalog, namespace)
    if catalog != previous:
        store.put_catalog(namespace + "/catalog.json", catalog, base["etag"])
    print(f"Catalog contains {len(catalog['shards'])} binary shard(s); changed={catalog != previous}", flush=True)
    return catalog


def download_missing_binaries(xml: Path, symbols: Path) -> None:
    import download_symbols

    for arch in ARCHES:
        for entry in download_symbols.parse_xml(str(xml), arch):
            directory = symbols / arch / f"{entry['file']}.{entry['version']}" / entry["hash"]
            if load_cached_entry(directory) is not None:
                continue
            status = download_symbols.process_entry(entry, str(symbols), fast_mode=True)
            if status == download_symbols.DownloadStatus.FAILED:
                raise RuntimeError("Symbol input download failed")


def sync_oss(symbols: Path, direction: str) -> None:
    from oss_sync import OSSSync, load_config_from_environment

    config = load_config_from_environment(direction)
    config["local_path"] = str(symbols)
    sync = OSSSync(config)
    if direction == "oss2local":
        for obj in sync._iter_oss_objects():
            relative = sync._relative_object_path(obj.key)
            if not relative or sync._should_ignore(relative):
                continue
            # Content-addressed cached PE files already exist virtually in the catalog.
            path = symbols / _safe_member(relative)
            marker = load_cached_entry(path.parent)
            if marker is not None and path.name == marker["shard"]["metadata"]["file"]:
                continue
            if not path.is_file() and not sync._download_file(relative):
                raise RuntimeError(f"OSS input download failed: {relative}")
    else:
        for path in symbols.rglob("*"):
            if path.is_file() and path.name != ENTRY_NAME:
                relative = path.relative_to(symbols).as_posix()
                if not sync._should_ignore(relative) and not sync._upload_file_if_changed(relative):
                    raise RuntimeError(f"OSS publication failed: {relative}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("restore-build", "restore-pr", "publish", "seed", "download", "oss-pull", "oss-push"))
    parser.add_argument("--symbols", type=Path, default=None)
    parser.add_argument("--xml", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "HLND2T/kphtools"))
    parser.add_argument("--platform", default=os.environ.get("RUNNER_OS", "Windows"))
    parser.add_argument("--arch")
    parser.add_argument("--version")
    parser.add_argument("--merge", action="store_true")
    args = parser.parse_args(argv)
    symbols = args.symbols or Path(os.environ["KPHTOOLS_SYMBOLDIR"])
    validate_tree(symbols)
    if args.command == "download":
        if args.xml is None:
            parser.error("download requires --xml")
        download_missing_binaries(args.xml, symbols)
        return 0
    if args.command in ("oss-pull", "oss-push"):
        sync_oss(symbols, "oss2local" if args.command == "oss-pull" else "local2oss")
        return 0
    namespace = cache_namespace(args.repository, args.platform)
    store = S3Store.from_environment()
    if args.command.startswith("restore-"):
        mode = "build" if args.command == "restore-build" else "pr"
        base = restore(symbols, store, namespace, mode=mode, arch=args.arch, version=args.version)
        if mode == "build":
            (symbols.parent / "catalog.local.json").write_text(json.dumps(base), encoding="utf-8")
    elif args.command == "publish":
        base = json.loads((symbols.parent / "catalog.local.json").read_text(encoding="utf-8"))
        publish(symbols, store, namespace, base=base)
    else:
        base = _read_catalog(store, namespace)
        if base["catalog"]["shards"] and not args.merge:
            raise ValueError("Catalog already exists; use --merge only when the seed source is authoritative")
        publish(symbols, store, namespace, base=base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
