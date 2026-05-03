"""
从 YAML 符号产物生成或更新 `kphdyn.xml` 中的 `<data>/<fields>` 映射。

基本用法:
    uv run python update_symbols.py -xml kphdyn.xml -symboldir symbols
    uv run python update_symbols.py -xml kphdyn.xml -symboldir symbols \
        -configyaml config.yaml -outxml output.xml

可用参数:
    -xml         输入 XML 路径，必填。
    -symboldir   符号产物根目录，必填。脚本会扫描
                 `{symboldir}/{arch}/{binary}.{version}/{sha256}/`。
    -configyaml  符号配置文件路径，默认 `config.yaml`。
    -syncfile    预留兼容参数；当前版本会解析该参数，但主流程未使用。
    -outxml      输出 XML 路径；省略时直接覆盖 `-xml`。
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

import pefile

from symbol_artifacts import load_artifact
from symbol_config import load_config


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export kphdyn.xml from YAML symbol artifacts"
    )
    parser.add_argument("-xml", required=True)
    parser.add_argument("-symboldir", required=True)
    parser.add_argument("-configyaml", default="config.yaml")
    parser.add_argument("-syncfile", action="store_true")
    parser.add_argument("-outxml")
    return parser.parse_args(argv)


def fallback_value(data_type: str) -> int:
    if data_type == "uint16":
        return 0xFFFF
    if data_type == "uint32":
        return 0xFFFFFFFF
    raise ValueError(f"unsupported data_type: {data_type}")


def collect_symbol_values(
    symbol_specs: list[dict[str, Any]], yaml_payloads: dict[str, dict[str, Any]]
) -> dict[str, int]:
    values: dict[str, int] = {}
    for spec in symbol_specs:
        payload = yaml_payloads.get(spec["name"])
        if not payload:
            values[spec["name"]] = fallback_value(spec["data_type"])
            continue
        if spec["category"] == "struct_offset":
            if "bit_offset" in payload:
                values[spec["name"]] = int(payload["offset"]) * 8 + int(
                    payload["bit_offset"]
                )
            else:
                values[spec["name"]] = int(payload["offset"])
        elif spec["category"] == "gv":
            values[spec["name"]] = int(payload["gv_rva"])
        elif spec["category"] == "func":
            values[spec["name"]] = int(payload["func_rva"])
        else:
            raise ValueError(f"unsupported category: {spec['category']}")
    return values


def _load_module_yaml(
    binary_dir: Path, symbol_specs: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    payloads: dict[str, dict[str, Any]] = {}
    for spec in symbol_specs:
        artifact_path = binary_dir / f"{spec['name']}.yaml"
        if artifact_path.exists():
            payloads[spec["name"]] = load_artifact(artifact_path)
    return payloads


def _collect_existing_fields(root: ET.Element) -> dict[tuple[tuple[str, int], ...], str]:
    existing: dict[tuple[tuple[str, int], ...], str] = {}
    for fields_elem in root.findall("fields"):
        values = []
        for key, value in fields_elem.attrib.items():
            if key == "id":
                continue
            values.append((key, int(value, 16)))
        existing[tuple(sorted(values))] = fields_elem.get("id", "0")
    return existing


def _find_or_create_fields_id(root: ET.Element, values: dict[str, int]) -> str:
    existing = _collect_existing_fields(root)
    key = tuple(sorted(values.items()))
    matched = existing.get(key)
    if matched:
        return matched

    next_id = max([0] + [int(elem.get("id", "0")) for elem in root.findall("fields")]) + 1
    fields_elem = ET.SubElement(root, "fields")
    fields_elem.set("id", str(next_id))
    for name, value in sorted(values.items()):
        fields_elem.set(name, hex(value))
    return str(next_id)


def _load_binary_metadata(binary_path: Path) -> dict[str, str]:
    pe = pefile.PE(str(binary_path), fast_load=True)
    try:
        return {
            "timestamp": hex(pe.FILE_HEADER.TimeDateStamp),
            "size": hex(pe.OPTIONAL_HEADER.SizeOfImage),
        }
    finally:
        pe.close()


def _ensure_data_entry(
    root: ET.Element,
    arch: str,
    file_name: str,
    version: str,
    sha256: str,
    metadata: dict[str, str],
) -> ET.Element:
    for data_elem in root.findall("data"):
        existing_hash = data_elem.get("hash") or data_elem.get("sha256")
        if (
            data_elem.get("arch") == arch
            and data_elem.get("file") == file_name
            and data_elem.get("version") == version
            and existing_hash
            and existing_hash.lower() == sha256.lower()
        ):
            if not data_elem.get("hash"):
                data_elem.set("hash", sha256)
            if not data_elem.get("sha256"):
                data_elem.set("sha256", sha256)
            if not data_elem.get("timestamp"):
                data_elem.set("timestamp", metadata["timestamp"])
            if not data_elem.get("size"):
                data_elem.set("size", metadata["size"])
            return data_elem
    data_elem = ET.SubElement(root, "data")
    data_elem.set("arch", arch)
    data_elem.set("file", file_name)
    data_elem.set("version", version)
    data_elem.set("hash", sha256)
    data_elem.set("sha256", sha256)
    data_elem.set("timestamp", metadata["timestamp"])
    data_elem.set("size", metadata["size"])
    data_elem.set("fields", "0")
    return data_elem


def export_xml(tree: ET.ElementTree, config: Any, symboldir: Path) -> ET.ElementTree:
    root = tree.getroot()
    for module in config.modules:
        symbol_specs = [vars(symbol) for symbol in module.symbols]
        for arch in ("amd64", "arm64"):
            arch_dir = symboldir / arch
            for module_path in module.path:
                for version_dir in arch_dir.glob(f"{module_path}.*"):
                    version = version_dir.name[len(module_path) + 1 :]
                    for sha_dir in version_dir.iterdir():
                        if not sha_dir.is_dir():
                            continue
                        metadata = _load_binary_metadata(sha_dir / module_path)
                        payloads = _load_module_yaml(sha_dir, symbol_specs)
                        values = collect_symbol_values(symbol_specs, payloads)
                        fields_id = _find_or_create_fields_id(root, values)
                        data_elem = _ensure_data_entry(
                            root, arch, module_path, version, sha_dir.name, metadata
                        )
                        data_elem.set("fields", fields_id)
    return tree


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = load_config(args.configyaml)
    tree = ET.parse(args.xml)
    export_xml(tree, config, Path(args.symboldir))
    out_path = args.outxml or args.xml
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
