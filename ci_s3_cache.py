"""Private S3 endpoint parsing and disposable symbol-cache staging for CI."""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


CACHE_DIRECTORY = ".ci-symbol-cache"
PR_DIRECTORY = ".ci-pr-analysis"
YAML_SUFFIXES = frozenset((".yaml", ".yml"))
KERNEL_PDB_NAMES = ("ntkrnlmp.pdb", "ntoskrnl.pdb")


def parse_endpoint(value: str) -> dict[str, str]:
    if not value or any(character.isspace() for character in value):
        raise ValueError("S3_ENDPOINT_URL must be an HTTP(S) origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or "?" in value
        or "#" in value
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("S3_ENDPOINT_URL must contain only an HTTP(S) origin")
    port = parsed.port
    if port == 0:
        raise ValueError("Invalid S3 endpoint port")
    host = parsed.hostname if parsed.netloc.startswith("[") else parsed.netloc.split(":")[0]
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise ValueError("Invalid S3 endpoint hostname")
    return {
        "endpoint": host,
        "port": str(port or (80 if parsed.scheme == "http" else 443)),
        "insecure": str(parsed.scheme == "http").lower(),
    }


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _check_ancestors(path: Path) -> None:
    for ancestor in (path, *path.parents):
        if _is_link(ancestor):
            raise ValueError(f"CI path traverses a link: {ancestor}")


def _workspace_root(workspace: Path) -> Path:
    workspace = workspace.absolute()
    if any(character in str(workspace) for character in "\r\n"):
        raise ValueError("Invalid workspace path")
    _check_ancestors(workspace)
    if not workspace.is_dir():
        raise ValueError("Workspace is missing")
    return workspace


def validate_tree(root: Path) -> None:
    """Reject links before copying, publishing, or removing a managed tree."""
    _check_ancestors(root)
    if not root.exists():
        return
    if not root.is_dir():
        raise ValueError(f"CI staging must be a directory: {root}")
    def raise_walk_error(error: OSError) -> None:
        raise error

    for directory, directories, files in os.walk(root, onerror=raise_walk_error):
        for name in (*directories, *files):
            path = Path(directory) / name
            if _is_link(path):
                raise ValueError(f"CI staging contains a link: {path}")


def _managed_paths(workspace: Path) -> tuple[Path, Path]:
    workspace = _workspace_root(workspace)
    return workspace / CACHE_DIRECTORY, workspace / PR_DIRECTORY


def cleanup(workspace: Path) -> None:
    paths = _managed_paths(workspace)
    # Validate every target before removing anything; never follow a junction.
    for path in paths:
        validate_tree(path)
    for path in paths:
        if path.exists():
            shutil.rmtree(path)


def prepare(
    workspace: Path, repository: str, platform: str, run_id: str, attempt: str,
) -> dict[str, str]:
    if (
        not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+", repository)
        or repository.split("/")[-1] in (".", "..")
    ):
        raise ValueError("Invalid repository")
    if platform not in ("Windows", "Linux", "macOS"):
        raise ValueError("Invalid runner platform")
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", attempt):
        raise ValueError("Invalid run identity")
    cache, analysis = _managed_paths(workspace)
    cleanup(workspace)
    (cache / "symbols").mkdir(parents=True)
    analysis.mkdir()
    repository_id = hashlib.sha256(repository.lower().encode()).hexdigest()
    return {
        "cache-path": CACHE_DIRECTORY,
        "cache-root": str(cache),
        "analysis-root": str(analysis),
        "symbols-path": str(cache / "symbols"),
        "namespace": f"kphtools-symbols-v2/{repository_id}/{platform.lower()}",
    }


def _version_directory(symbols: Path, arch: str, version: str) -> Path:
    if arch not in ("amd64", "arm64") or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version or ""):
        raise ValueError("Invalid PR architecture or version")
    return symbols / arch / f"ntoskrnl.exe.{version}"


def _ignore_yaml(_directory: str, names: list[str]) -> list[str]:
    return [name for name in names if Path(name).suffix.lower() in YAML_SUFFIXES]


def isolate_pr_inputs(
    workspace: Path, xml_path: Path, arch: str, version: str,
    baseline_xml: Path | None = None,
) -> dict[str, str]:
    cache, analysis = _managed_paths(workspace)
    source = _version_directory(cache / "symbols", arch, version)
    symbols = analysis / "symbols"
    target = _version_directory(symbols, arch, version)
    validate_tree(source)
    validate_tree(analysis)
    if symbols.exists():
        raise ValueError("PR symbols have already been materialized")
    analysis.mkdir(exist_ok=True)
    if source.exists():
        shutil.copytree(source, target, ignore=_ignore_yaml)
    else:
        target.mkdir(parents=True)

    # The download script filters versions by prefix. Give it an exact kernel
    # selection so a cold cache cannot introduce other binaries or versions.
    original = ET.parse(xml_path).getroot()
    selection = ET.Element(original.tag, original.attrib)
    sources = [original]
    if baseline_xml is not None:
        sources.append(ET.parse(baseline_xml).getroot())
    for candidate in sources:
        for entry in candidate.findall("data"):
            if (
                entry.get("arch") == arch
                and entry.get("version") == version
                and entry.get("file", "").lower() == "ntoskrnl.exe"
            ):
                selection.append(copy.deepcopy(entry))
        if len(selection):
            break
    output = analysis / "output"
    output.mkdir(exist_ok=True)
    download_xml = output / "kphdyn.download.xml"
    ET.ElementTree(selection).write(download_xml, encoding="utf-8", xml_declaration=True)
    return {"symbols-path": str(symbols), "download-xml": str(download_xml)}


def verify_pr_inputs(workspace: Path, arch: str, version: str) -> int:
    _, analysis = _managed_paths(workspace)
    symbols = analysis / "symbols"
    selected = _version_directory(symbols, arch, version)
    validate_tree(symbols)
    if any(path.suffix.lower() in YAML_SUFFIXES for path in symbols.rglob("*")):
        raise ValueError("Cached YAML artifacts must not enter PR analysis")
    binaries = list(selected.glob("*/ntoskrnl.exe"))
    if not binaries:
        raise ValueError(f"No ntoskrnl.exe input is available for {arch}/{version}")
    for binary in binaries:
        if not binary.is_file() or binary.stat().st_size == 0:
            raise ValueError(f"Invalid ntoskrnl.exe input: {binary}")
        if not any(
            (binary.parent / name).is_file() and (binary.parent / name).stat().st_size > 0
            for name in KERNEL_PDB_NAMES
        ):
            raise ValueError(f"No kernel PDB input is available for {binary}")
    return len(binaries)


def _export(path: str, values: dict[str, str]) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if any(character in value for character in "\r\n"):
                raise ValueError("Invalid multiline CI output")
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("endpoint", "prepare", "isolate", "verify", "validate", "cleanup"))
    parser.add_argument("--xml", type=Path)
    parser.add_argument("--baseline-xml", type=Path)
    parser.add_argument("--arch")
    parser.add_argument("--version")
    args = parser.parse_args(argv)
    if args.command == "endpoint":
        for name in ("S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"):
            if not os.environ.get(name, "").strip():
                raise ValueError(f"{name} is required")
        outputs = parse_endpoint(os.environ.get("S3_ENDPOINT_URL", ""))
    else:
        workspace = Path(os.environ["GITHUB_WORKSPACE"])
        if args.command == "cleanup":
            cleanup(workspace)
            return 0
        if args.command == "validate":
            cache, _ = _managed_paths(workspace)
            validate_tree(cache)
            return 0
        if args.command == "verify":
            count = verify_pr_inputs(workspace, args.arch, args.version)
            print(f"Verified {count} kernel binary/PDB input(s) without YAML artifacts")
            return 0
        if args.command == "prepare":
            outputs = prepare(
                workspace, os.environ["GITHUB_REPOSITORY"], os.environ["RUNNER_OS"],
                os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"],
            )
            _export(os.environ["GITHUB_ENV"], {
                "WORKSPACE": str(_workspace_root(workspace)),
                "CI_CACHE_ROOT": outputs["cache-root"],
                "CI_PR_ROOT": outputs["analysis-root"],
                "KPHTOOLS_SYMBOLDIR": outputs["symbols-path"],
            })
        else:
            if args.xml is None:
                parser.error("isolate requires --xml")
            outputs = isolate_pr_inputs(workspace, args.xml, args.arch, args.version, args.baseline_xml)
            _export(os.environ["GITHUB_ENV"], {"KPHTOOLS_SYMBOLDIR": outputs["symbols-path"]})
    _export(os.environ["GITHUB_OUTPUT"], outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
