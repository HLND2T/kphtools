# update_symbols syncfile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `update_symbols.py -syncfile` as a pure XML data-entry synchronization mode with default `-xml` and `-symboldir` values.

**Architecture:** Keep the feature local to `update_symbols.py`. Add focused helpers for CLI defaults, symbol-directory scanning, path parsing, XML lookup/insertion, PE metadata extraction, and `syncfile_main()` dispatch while preserving the existing YAML-to-XML export path for non-`-syncfile` runs.

**Tech Stack:** Python 3.10+, `argparse`, `hashlib`, `os.environ`, `pathlib.Path`, `xml.etree.ElementTree`, `pefile`, `unittest`, `unittest.mock`

---

## File Structure

- Modify: `update_symbols.py:1-197`
  - Responsibility: own CLI parsing, current YAML-to-XML export flow, and the new pure `-syncfile` flow.
  - Add small dataclasses for parsed file path information and sync statistics.
  - Add one custom exception for SHA256 mismatch.
- Modify: `tests/test_update_symbols.py:1-159`
  - Responsibility: cover existing YAML export behavior plus new `-syncfile` helpers and dispatch.

No new production module is needed. Splitting would add import surface without reducing meaningful complexity for this narrow CLI feature.

## Task 1: CLI Defaults And Environment Overrides

**Files:**
- Modify: `tests/test_update_symbols.py:1-159`
- Modify: `update_symbols.py:20-40`

- [ ] **Step 1: Write failing tests for default and environment-backed CLI parsing**

Add `import os` near the top of `tests/test_update_symbols.py`.

Add these tests inside `TestUpdateSymbols`:

```python
    def test_parse_args_uses_default_xml_and_symboldir(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            args = update_symbols.parse_args(["-syncfile"])

        self.assertEqual("kphdyn.xml", args.xml)
        self.assertEqual("symbols", args.symboldir)
        self.assertTrue(args.syncfile)

    def test_parse_args_prefers_environment_xml_and_symboldir(self) -> None:
        with patch.dict(
            os.environ,
            {
                "KPHTOOLS_XML": "env.xml",
                "KPHTOOLS_SYMBOLDIR": "env-symbols",
            },
            clear=True,
        ):
            args = update_symbols.parse_args(
                [
                    "-xml",
                    "cli.xml",
                    "-symboldir",
                    "cli-symbols",
                    "-syncfile",
                ]
            )

        self.assertEqual("env.xml", args.xml)
        self.assertEqual("env-symbols", args.symboldir)
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_parse_args_uses_default_xml_and_symboldir \
  tests.test_update_symbols.TestUpdateSymbols.test_parse_args_prefers_environment_xml_and_symboldir \
  -v
```

Expected result before implementation:

```text
ERROR for test_parse_args_uses_default_xml_and_symboldir
FAIL for test_parse_args_prefers_environment_xml_and_symboldir
```

The first test fails because `parse_args(["-syncfile"])` still requires `-xml`
and `-symboldir`.

- [ ] **Step 3: Implement CLI defaults and environment overrides**

In `update_symbols.py`, add imports and constants near the top:

```python
import argparse
import os
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

import pefile

DEFAULT_XML_PATH = "kphdyn.xml"
DEFAULT_SYMBOL_DIR = "symbols"
```

Replace `parse_args()` with:

```python
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export kphdyn.xml from YAML symbol artifacts"
    )
    parser.add_argument("-xml", default=DEFAULT_XML_PATH)
    parser.add_argument("-symboldir", default=DEFAULT_SYMBOL_DIR)
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument("-syncfile", action="store_true")
    parser.add_argument("-outxml")
    args = parser.parse_args(argv)

    env_xml = os.getenv("KPHTOOLS_XML")
    if env_xml:
        args.xml = env_xml

    env_symboldir = os.getenv("KPHTOOLS_SYMBOLDIR")
    if env_symboldir:
        args.symboldir = env_symboldir

    if not args.xml:
        parser.error("-xml cannot be empty")
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")

    return args
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_parse_args_uses_default_xml_and_symboldir \
  tests.test_update_symbols.TestUpdateSymbols.test_parse_args_prefers_environment_xml_and_symboldir \
  -v
```

Expected result:

```text
OK
```

- [ ] **Step 5: Commit the CLI default change**

Run:

```bash
git add update_symbols.py tests/test_update_symbols.py
git commit -m "feat: 添加 update_symbols 默认路径"
```

## Task 2: Symbol Directory Path Parsing And XML Lookup

**Files:**
- Modify: `tests/test_update_symbols.py:1-220`
- Modify: `update_symbols.py:20-120`

- [ ] **Step 1: Write failing tests for path parsing and data lookup**

Add these tests inside `TestUpdateSymbols`:

```python
    def test_parse_file_path_info_parses_symbol_directory_layout(self) -> None:
        sha256 = "a" * 64

        with TemporaryDirectory() as temp_dir:
            binary_path = (
                Path(temp_dir)
                / "amd64"
                / "ntoskrnl.exe.10.0.1"
                / sha256
                / "ntoskrnl.exe"
            )
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"binary")

            info = update_symbols.parse_file_path_info(Path(temp_dir), binary_path)

        self.assertEqual("amd64", info.arch)
        self.assertEqual("ntoskrnl.exe", info.file)
        self.assertEqual("10.0.1", info.version)
        self.assertEqual(sha256, info.sha256)
        self.assertEqual(binary_path.resolve(), info.binary_path)

    def test_find_data_entry_matches_hash_attribute(self) -> None:
        sha256 = "b" * 64
        root = update_symbols.ET.fromstring(
            f'<kphdyn><data arch="amd64" file="ntoskrnl.exe" '
            f'version="10.0.1" hash="{sha256}">1</data></kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256=sha256,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.find_data_entry(root, info)

        self.assertIsNotNone(data_elem)
        self.assertEqual("1", data_elem.text)

    def test_find_data_entry_matches_legacy_sha256_attribute(self) -> None:
        sha256 = "c" * 64
        root = update_symbols.ET.fromstring(
            f'<kphdyn><data arch="amd64" file="ntoskrnl.exe" '
            f'version="10.0.1" sha256="{sha256}" fields="0" /></kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256=sha256,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.find_data_entry(root, info)

        self.assertIsNotNone(data_elem)
        self.assertEqual("0", data_elem.get("fields"))
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_parse_file_path_info_parses_symbol_directory_layout \
  tests.test_update_symbols.TestUpdateSymbols.test_find_data_entry_matches_hash_attribute \
  tests.test_update_symbols.TestUpdateSymbols.test_find_data_entry_matches_legacy_sha256_attribute \
  -v
```

Expected result before implementation:

```text
ERROR: module 'update_symbols' has no attribute 'parse_file_path_info'
```

- [ ] **Step 3: Implement path info, scanning, and XML lookup helpers**

In `update_symbols.py`, add this import:

```python
from dataclasses import dataclass
```

Add these definitions after `parse_args()`:

```python
_SHA256_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class FilePathInfo:
    arch: str
    file: str
    version: str
    sha256: str
    binary_path: Path


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in _SHA256_HEX for char in value.lower())


def parse_file_path_info(symboldir: Path, binary_path: Path) -> FilePathInfo:
    root = Path(symboldir).resolve()
    path = Path(binary_path).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path is outside symboldir: {binary_path}") from exc

    parts = relative.parts
    if len(parts) != 4:
        raise ValueError(f"expected arch/file.version/sha256/file: {relative}")

    arch, version_dir, sha256, file_name = parts
    sha256 = sha256.lower()
    if not _is_sha256(sha256):
        raise ValueError(f"invalid sha256 directory: {sha256}")

    prefix = f"{file_name}."
    if not version_dir.startswith(prefix):
        raise ValueError(f"version directory does not match file name: {version_dir}")

    version = version_dir[len(prefix) :]
    if not version:
        raise ValueError(f"missing version in directory: {version_dir}")

    return FilePathInfo(
        arch=arch,
        file=file_name,
        version=version,
        sha256=sha256,
        binary_path=path,
    )


def scan_symbol_directory(symboldir: Path) -> list[Path]:
    root = Path(symboldir)
    if not root.is_dir():
        return []

    binaries: list[Path] = []
    for arch_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        for version_dir in sorted(path for path in arch_dir.iterdir() if path.is_dir()):
            for sha_dir in sorted(path for path in version_dir.iterdir() if path.is_dir()):
                for binary_path in sorted(path for path in sha_dir.iterdir() if path.is_file()):
                    if version_dir.name.startswith(f"{binary_path.name}."):
                        binaries.append(binary_path)
    return binaries


def find_data_entry(root: ET.Element, info: FilePathInfo) -> ET.Element | None:
    for data_elem in root.findall("data"):
        existing_hash = data_elem.get("hash") or data_elem.get("sha256")
        if (
            data_elem.get("arch") == info.arch
            and data_elem.get("file") == info.file
            and data_elem.get("version") == info.version
            and existing_hash
            and existing_hash.lower() == info.sha256
        ):
            return data_elem
    return None
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_parse_file_path_info_parses_symbol_directory_layout \
  tests.test_update_symbols.TestUpdateSymbols.test_find_data_entry_matches_hash_attribute \
  tests.test_update_symbols.TestUpdateSymbols.test_find_data_entry_matches_legacy_sha256_attribute \
  -v
```

Expected result:

```text
OK
```

- [ ] **Step 5: Commit the parsing helpers**

Run:

```bash
git add update_symbols.py tests/test_update_symbols.py
git commit -m "feat: 添加 syncfile 路径解析"
```

## Task 3: PE Metadata, Data Entry Creation, And Insert Position

**Files:**
- Modify: `tests/test_update_symbols.py:1-280`
- Modify: `update_symbols.py:20-170`

- [ ] **Step 1: Write failing tests for XML creation and insertion**

Add these tests inside `TestUpdateSymbols`:

```python
    def test_create_data_entry_uses_text_fields_id_zero(self) -> None:
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.1",
            sha256="d" * 64,
            binary_path=Path("ntoskrnl.exe"),
        )

        data_elem = update_symbols.create_data_entry(
            info,
            {"timestamp": "0x10", "size": "0x20", "sha256": "d" * 64},
        )

        self.assertEqual("data", data_elem.tag)
        self.assertEqual("amd64", data_elem.get("arch"))
        self.assertEqual("10.0.1", data_elem.get("version"))
        self.assertEqual("ntoskrnl.exe", data_elem.get("file"))
        self.assertEqual("d" * 64, data_elem.get("hash"))
        self.assertEqual("0x10", data_elem.get("timestamp"))
        self.assertEqual("0x20", data_elem.get("size"))
        self.assertEqual("0", data_elem.text)
        self.assertIsNone(data_elem.get("fields"))
        self.assertIsNone(data_elem.get("sha256"))

    def test_find_insert_position_keeps_data_before_fields(self) -> None:
        root = update_symbols.ET.fromstring(
            '<kphdyn>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.1" hash="a">1</data>'
            '<fields id="1" />'
            '</kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.2",
            sha256="e" * 64,
            binary_path=Path("ntoskrnl.exe"),
        )

        insert_index = update_symbols.find_insert_position(root, info)

        self.assertEqual(1, insert_index)

    def test_find_insert_position_orders_versions_within_same_group(self) -> None:
        root = update_symbols.ET.fromstring(
            '<kphdyn>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.1" hash="a">1</data>'
            '<data arch="amd64" file="ntoskrnl.exe" version="10.0.3" hash="b">1</data>'
            '<fields id="1" />'
            '</kphdyn>'
        )
        info = update_symbols.FilePathInfo(
            arch="amd64",
            file="ntoskrnl.exe",
            version="10.0.2",
            sha256="f" * 64,
            binary_path=Path("ntoskrnl.exe"),
        )

        insert_index = update_symbols.find_insert_position(root, info)

        self.assertEqual(1, insert_index)
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_create_data_entry_uses_text_fields_id_zero \
  tests.test_update_symbols.TestUpdateSymbols.test_find_insert_position_keeps_data_before_fields \
  tests.test_update_symbols.TestUpdateSymbols.test_find_insert_position_orders_versions_within_same_group \
  -v
```

Expected result before implementation:

```text
ERROR: module 'update_symbols' has no attribute 'create_data_entry'
```

- [ ] **Step 3: Implement SHA256 calculation, PE metadata, insertion, and data creation**

In `update_symbols.py`, add this import:

```python
import hashlib
```

Add these definitions after `find_data_entry()`:

```python
class HashMismatchError(ValueError):
    pass


def _calculate_sha256(binary_path: Path) -> str:
    digest = hashlib.sha256()
    with Path(binary_path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def parse_pe_info(binary_path: Path, expected_sha256: str) -> dict[str, str]:
    actual_sha256 = _calculate_sha256(binary_path)
    expected = expected_sha256.lower()
    if actual_sha256 != expected:
        raise HashMismatchError(
            f"sha256 mismatch for {binary_path}: expected {expected}, got {actual_sha256}"
        )

    pe = pefile.PE(str(binary_path), fast_load=True)
    try:
        return {
            "timestamp": hex(pe.FILE_HEADER.TimeDateStamp),
            "size": hex(pe.OPTIONAL_HEADER.SizeOfImage),
            "sha256": actual_sha256,
        }
    finally:
        pe.close()


def _version_sort_key(version: str) -> tuple[int, tuple[int, ...] | str]:
    parts = version.split(".")
    if parts and all(part.isdigit() for part in parts):
        return (0, tuple(int(part) for part in parts))
    return (1, version)


def find_insert_position(root: ET.Element, info: FilePathInfo) -> int:
    children = list(root)
    new_key = _version_sort_key(info.version)
    last_group_index: int | None = None

    for index, elem in enumerate(children):
        if elem.tag != "data":
            continue
        if elem.get("arch") != info.arch or elem.get("file") != info.file:
            continue
        last_group_index = index
        existing_key = _version_sort_key(elem.get("version", ""))
        if existing_key > new_key:
            return index

    if last_group_index is not None:
        return last_group_index + 1

    for index, elem in enumerate(children):
        if elem.tag == "fields":
            return index
    return len(children)


def create_data_entry(info: FilePathInfo, pe_info: dict[str, str]) -> ET.Element:
    data_elem = ET.Element("data")
    data_elem.set("arch", info.arch)
    data_elem.set("version", info.version)
    data_elem.set("file", info.file)
    data_elem.set("hash", info.sha256)
    data_elem.set("timestamp", pe_info["timestamp"])
    data_elem.set("size", pe_info["size"])
    data_elem.text = "0"
    return data_elem
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_create_data_entry_uses_text_fields_id_zero \
  tests.test_update_symbols.TestUpdateSymbols.test_find_insert_position_keeps_data_before_fields \
  tests.test_update_symbols.TestUpdateSymbols.test_find_insert_position_orders_versions_within_same_group \
  -v
```

Expected result:

```text
OK
```

- [ ] **Step 5: Commit the XML insertion helpers**

Run:

```bash
git add update_symbols.py tests/test_update_symbols.py
git commit -m "feat: 添加 syncfile XML 插入"
```

## Task 4: syncfile Main Flow And Main Dispatch

**Files:**
- Modify: `tests/test_update_symbols.py:1-360`
- Modify: `update_symbols.py:1-230`

- [ ] **Step 1: Write failing tests for `syncfile_main()` and `main()` dispatch**

Add `redirect_stdout` and `io` imports near the top of `tests/test_update_symbols.py`:

```python
from contextlib import redirect_stdout
import io
```

Add these tests inside `TestUpdateSymbols`:

```python
    def test_syncfile_main_adds_missing_entries_and_skips_existing(self) -> None:
        existing_sha = "1" * 64
        missing_sha = "2" * 64

        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            xml_path = temp_path / "kphdyn.xml"
            symboldir = temp_path / "symbols"

            xml_path.write_text(
                f'<kphdyn>'
                f'<data arch="amd64" file="ntoskrnl.exe" version="10.0.1" '
                f'hash="{existing_sha}" timestamp="0x1" size="0x2">1</data>'
                f'<fields id="1" />'
                f'</kphdyn>',
                encoding="utf-8",
            )

            existing_binary = (
                symboldir
                / "amd64"
                / "ntoskrnl.exe.10.0.1"
                / existing_sha
                / "ntoskrnl.exe"
            )
            missing_binary = (
                symboldir
                / "amd64"
                / "ntoskrnl.exe.10.0.2"
                / missing_sha
                / "ntoskrnl.exe"
            )
            existing_binary.parent.mkdir(parents=True)
            missing_binary.parent.mkdir(parents=True)
            existing_binary.write_bytes(b"existing")
            missing_binary.write_bytes(b"missing")

            def fake_parse_pe_info(binary_path: Path, expected_sha256: str) -> dict[str, str]:
                self.assertEqual(missing_binary.resolve(), binary_path)
                self.assertEqual(missing_sha, expected_sha256)
                return {
                    "timestamp": "0x10",
                    "size": "0x20",
                    "sha256": expected_sha256,
                }

            output = io.StringIO()
            args = SimpleNamespace(
                xml=str(xml_path),
                symboldir=str(symboldir),
                outxml=None,
            )
            with (
                patch.object(update_symbols, "parse_pe_info", side_effect=fake_parse_pe_info) as pe_mock,
                redirect_stdout(output),
            ):
                exit_code = update_symbols.syncfile_main(args)

            self.assertEqual(0, exit_code)
            self.assertEqual(1, pe_mock.call_count)
            self.assertIn("added=1", output.getvalue())
            self.assertIn("existing=1", output.getvalue())

            root = update_symbols.ET.parse(xml_path).getroot()
            data_elems = root.findall("data")
            self.assertEqual(2, len(data_elems))
            self.assertEqual("fields", list(root)[2].tag)

            info = update_symbols.FilePathInfo(
                arch="amd64",
                file="ntoskrnl.exe",
                version="10.0.2",
                sha256=missing_sha,
                binary_path=missing_binary.resolve(),
            )
            new_elem = update_symbols.find_data_entry(root, info)
            self.assertIsNotNone(new_elem)
            self.assertEqual("0", new_elem.text)
            self.assertIsNone(new_elem.get("fields"))

    def test_main_syncfile_dispatch_does_not_load_configyaml(self) -> None:
        with (
            patch.object(update_symbols, "syncfile_main", return_value=0) as sync_mock,
            patch.object(update_symbols, "load_config") as load_config_mock,
        ):
            exit_code = update_symbols.main(["-syncfile"])

        self.assertEqual(0, exit_code)
        sync_mock.assert_called_once()
        load_config_mock.assert_not_called()
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_syncfile_main_adds_missing_entries_and_skips_existing \
  tests.test_update_symbols.TestUpdateSymbols.test_main_syncfile_dispatch_does_not_load_configyaml \
  -v
```

Expected result before implementation:

```text
ERROR: module 'update_symbols' has no attribute 'syncfile_main'
```

- [ ] **Step 3: Implement statistics, `syncfile_main()`, and dispatch**

Add this dataclass after `FilePathInfo`:

```python
@dataclass
class SyncStats:
    scanned: int = 0
    existing: int = 0
    added: int = 0
    invalid_path: int = 0
    hash_mismatch: int = 0
    pe_error: int = 0
    skipped: int = 0
```

Add these helpers before `main()`:

```python
def _print_sync_stats(stats: SyncStats) -> None:
    print(
        "syncfile: "
        f"scanned={stats.scanned} "
        f"existing={stats.existing} "
        f"added={stats.added} "
        f"invalid_path={stats.invalid_path} "
        f"hash_mismatch={stats.hash_mismatch} "
        f"pe_error={stats.pe_error} "
        f"skipped={stats.skipped}"
    )


def syncfile_main(args: argparse.Namespace) -> int:
    xml_path = Path(args.xml)
    symboldir = Path(args.symboldir)
    out_path = Path(args.outxml) if args.outxml else xml_path

    if not xml_path.exists():
        print(f"Error: XML file not found: {xml_path}")
        return 1
    if not symboldir.is_dir():
        print(f"Error: Symbol directory not found: {symboldir}")
        return 1

    tree = ET.parse(xml_path)
    root = tree.getroot()
    stats = SyncStats()

    for binary_path in scan_symbol_directory(symboldir):
        try:
            info = parse_file_path_info(symboldir, binary_path)
        except ValueError as exc:
            stats.invalid_path += 1
            print(f"Warning: skipping invalid symbol path {binary_path}: {exc}")
            continue

        stats.scanned += 1
        if find_data_entry(root, info) is not None:
            stats.existing += 1
            continue

        try:
            pe_info = parse_pe_info(info.binary_path, info.sha256)
        except HashMismatchError as exc:
            stats.hash_mismatch += 1
            print(f"Warning: {exc}")
            continue
        except (OSError, pefile.PEFormatError, ValueError) as exc:
            stats.pe_error += 1
            print(f"Warning: failed to parse PE {info.binary_path}: {exc}")
            continue

        data_elem = create_data_entry(info, pe_info)
        root.insert(find_insert_position(root, info), data_elem)
        stats.added += 1

    if stats.added:
        tree.write(out_path, encoding="utf-8", xml_declaration=True)

    _print_sync_stats(stats)
    return 0
```

Replace `main()` with:

```python
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.syncfile:
        return syncfile_main(args)

    config = load_config(args.configyaml)
    tree = ET.parse(args.xml)
    export_xml(tree, config, Path(args.symboldir))
    out_path = args.outxml or args.xml
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    return 0
```

Update the top module docstring so the parameter section says:

```text
    -xml         输入 XML 路径，默认 `kphdyn.xml`。
    -symboldir   符号产物根目录，默认 `symbols`。脚本会扫描
                 `{symboldir}/{arch}/{binary}.{version}/{sha256}/`。
    -syncfile    纯同步模式：扫描符号目录并补齐 XML 中缺失的 `<data>0</data>`。
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_syncfile_main_adds_missing_entries_and_skips_existing \
  tests.test_update_symbols.TestUpdateSymbols.test_main_syncfile_dispatch_does_not_load_configyaml \
  -v
```

Expected result:

```text
OK
```

- [ ] **Step 5: Commit the main syncfile flow**

Run:

```bash
git add update_symbols.py tests/test_update_symbols.py
git commit -m "feat: 补全 syncfile 同步流程"
```

## Task 5: Regression Check And Scope Review

**Files:**
- Modify: `update_symbols.py:1-260`
- Modify: `tests/test_update_symbols.py:1-380`

- [ ] **Step 1: Run the full `update_symbols` test module**

Run:

```bash
uv run python -m unittest tests.test_update_symbols -v
```

Expected result:

```text
OK
```

- [ ] **Step 2: Check that non-`syncfile` dispatch still calls existing export flow**

Add this test inside `TestUpdateSymbols`:

```python
    def test_main_without_syncfile_keeps_export_flow(self) -> None:
        with TemporaryDirectory() as temp_dir:
            xml_path = Path(temp_dir) / "kphdyn.xml"
            xml_path.write_text("<kphdyn />", encoding="utf-8")

            config = self._build_config()
            with (
                patch.object(update_symbols, "load_config", return_value=config) as load_mock,
                patch.object(update_symbols, "export_xml") as export_mock,
            ):
                exit_code = update_symbols.main(
                    [
                        "-xml",
                        str(xml_path),
                        "-symboldir",
                        str(Path(temp_dir) / "symbols"),
                    ]
                )

        self.assertEqual(0, exit_code)
        load_mock.assert_called_once()
        export_mock.assert_called_once()
```

- [ ] **Step 3: Run the new dispatch regression test and verify it passes**

Run:

```bash
uv run python -m unittest \
  tests.test_update_symbols.TestUpdateSymbols.test_main_without_syncfile_keeps_export_flow \
  -v
```

Expected result:

```text
OK
```

- [ ] **Step 4: Run a syntax compile check for the changed files**

Run:

```bash
uv run python -m py_compile update_symbols.py tests/test_update_symbols.py
```

Expected result:

```text
no output and exit code 0
```

- [ ] **Step 5: Inspect the final diff for scope drift**

Run:

```bash
git diff -- update_symbols.py tests/test_update_symbols.py
```

Expected review result:

```text
Only update_symbols.py and tests/test_update_symbols.py changed.
The diff contains syncfile/default-argument work only.
```

- [ ] **Step 6: Commit final regression coverage**

Run:

```bash
git add update_symbols.py tests/test_update_symbols.py
git commit -m "test: 补充 update_symbols 回归覆盖"
```

## Completion Checklist

- `-syncfile` does not load `config.yaml`.
- `-syncfile` writes new entries as `<data ...>0</data>`.
- Existing entries matched by `hash` or `sha256` are not duplicated.
- SHA256 mismatch raises `HashMismatchError` and is counted as `hash_mismatch`.
- PE parse failures are counted as `pe_error`.
- `-xml` defaults to `kphdyn.xml`.
- `-symboldir` defaults to `symbols`.
- `KPHTOOLS_XML` and `KPHTOOLS_SYMBOLDIR` override parsed values.
- Non-`-syncfile` execution still calls the current YAML-to-XML export path.
