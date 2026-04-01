#!/usr/bin/env python3
"""
Symbol Update Script for KPH Dynamic Data

Updates field offsets in kphdyn.xml by parsing PDB files using llvm-pdbutil.

Usage:
    # Normal mode: Update symbol offsets from PDB files
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -sha256 <hash>
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -pdbutil /path/to/llvm-pdbutil
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -outxml kphdyn_updated.xml

    # Syncfile mode: Sync PE files from symbol directory to XML entries
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -syncfile
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -syncfile -fast
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -syncfile -outxml kphdyn_updated.xml

    # Fixnull mode: Fix null entries (fields ID = 0) using SymbolMapping.yaml
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -fixnull
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -fixnull -debug

    # Fixstruct mode: Fix struct_offset fallback values from closest valid version
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -fixstruct
    uv run python update_symbols.py -xml kphdyn.xml -symboldir C:/Symbols -yaml kphdyn.yaml -fixstruct -debug

YAML Config Format:
    - file:
        - ntoskrnl.exe
        - ntkrla57.exe
      symbols:
        - name: EpObjectTable
          struct_offset: "_EPROCESS->ObjectTable"
          type: uint16
        - name: PspNotify
          var_offset: PspCreateProcessNotifyRoutine
          type: uint32
        - name: ExRefCallback
          fn_offset: ExReferenceCallBackBlock
          type: uint32
        - name: ObDecodeShift
          struct_offset: "_HANDLE_TABLE_ENTRY->ObjectPointerBits"
          type: uint16
          bits: true

Symbol Types:
    - struct_offset: Structure member offset (e.g., "_EPROCESS->ObjectTable")
    - var_offset: Global variable offset (e.g., "PspCreateProcessNotifyRoutine")
    - fn_offset: Function offset (e.g., "ExReferenceCallBackBlock")

Optional Symbol Fields:
    - bits: true - For bitfield members, output offset in bits instead of bytes.
                   The bit offset is calculated as: (byte_offset * 8) + bitfield_bit_offset
                   This is useful for bitfield members like ObjectPointerBits.

Data Types:
    - type: "uint16" - Output as 4-digit hex (0x0000-0xffff), max value 0xffff
    - type: "uint32" - Output as 8-digit hex (0x00000000-0xffffffff), max value 0xffffffff

Optional Arguments:
    -sha256: Only process entries with this SHA256 hash value (case-insensitive)
    -pdbutil: Path to llvm-pdbutil executable (default: search in PATH)
    -outxml: Path to output XML file (default: overwrite input XML file)
    -debug: Enable debug logging for symbol parsing
    -syncfile: Sync PE files from symbol directory to XML (add missing entries)
    -fast: Fast mode for syncfile - only parse PE when entry is missing
    -fixnull: Only process entries with fields ID = 0, using SymbolMapping.yaml
    -fixstruct: Fix struct_offset fallback values by copying from closest valid version

Syncfile Mode:
    Scans the symbol directory for PE files (exe/dll/sys) and adds missing
    entries to the XML. For each PE file found:
    - Extracts arch/file/version/sha256 from the directory path
    - If the entry doesn't exist in XML (matched by arch/file/version/hash),
      parses PE to get timestamp/size
    - Inserts new entry after the closest smaller version
    - Sets fields ID to 0 (not yet resolved)

    Directory structure:
        {symboldir}/{arch}/{filename}.{version}/{sha256}/{filename}
        {symboldir}/{arch}/{filename}.{version}/{sha256}/ntkrnlmp.pdb
        {symboldir}/{arch}/{filename}.{version}/{sha256}/SymbolMapping.yaml

    Example:
        symbols/amd64/ntoskrnl.exe.10.0.28000.1362/68d5867b.../ntoskrnl.exe
        symbols/amd64/ntoskrnl.exe.10.0.28000.1362/68d5867b.../ntkrnlmp.pdb

    The -fast flag skips PE parsing for entries that already exist,
    only parsing when a new entry needs to be added.

Fixnull Mode:
    Processes only data entries with fields ID = 0 (null entries).
    Instead of parsing PDB files for var_offset and fn_offset symbols,
    it reads from SymbolMapping.yaml in the symbol directory.

    SymbolMapping.yaml format:
        sub_140822108: PspSetCreateProcessNotifyRoutine
        stru_140D0C080: PspCreateProcessNotifyRoutine
        sub_1402CC450: ExReferenceCallBackBlock
        '140000000': ImageBase

    The offset is calculated as: symbol_address - ImageBase
    For example: 0x140D0C080 - 0x140000000 = 0xD0C080

    Note: struct_offset symbols still require PDB files. If PDB is not found,
    struct_offset values are set to fallback values (0xffff for uint16,
    0xffffffff for uint32).

Fixstruct Mode:
    Fixes struct_offset fallback values (0xffff for uint16, 0xffffffff for uint32)
    by copying from the closest valid version within the same architecture.

    For each data entry with fallback struct_offset values:
    - Finds the closest version (by version number distance) that has valid
      struct_offset values
    - Copies the struct_offset values from the source entry
    - Creates a new fields section or reuses an existing matching one

    This is useful after running -fixnull on entries without PDB files.

Requirements:
    - llvm-pdbutil must be available in system PATH or specified via -pdbutil
    - Run `uv sync` in the repository root to install Python dependencies from pyproject.toml
"""

import os
import re
import argparse
import subprocess
import sys
import hashlib
import xml.etree.ElementTree as ET

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# XML header with copyright notice
XML_HEADER = """<?xml version="1.0" encoding="utf-8"?>
<!--
Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.

This file is part of System Informer.

THIS IS AN AUTOGENERATED FILE, DO NOT MODIFY
-->
"""


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Updates field offsets in kphdyn.xml by parsing PDB files using llvm-pdbutil"
    )
    parser.add_argument(
        "-xml",
        required=True,
        help="Path to the XML file (e.g., kphdyn.xml)"
    )
    parser.add_argument(
        "-symboldir",
        required=True,
        help="Directory containing symbol files"
    )
    parser.add_argument(
        "-yaml",
        help="Path to the YAML config file (e.g., kphdyn.yaml). Required except in -syncfile mode"
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug logging for symbol parsing"
    )
    parser.add_argument(
        "-sha256",
        help="Only process entries with this SHA256 hash value"
    )
    parser.add_argument(
        "-pdbutil",
        help="Path to llvm-pdbutil executable (default: search in PATH)"
    )
    parser.add_argument(
        "-outxml",
        help="Path to output XML file (default: overwrite input XML file)"
    )
    parser.add_argument(
        "-syncfile",
        action="store_true",
        help="Sync symbol files to XML entries (add missing entries)"
    )
    parser.add_argument(
        "-fast",
        action="store_true",
        help="Fast mode: only parse PE content when entry is missing"
    )
    parser.add_argument(
        "-fixnull",
        action="store_true",
        help="Only process data entries with fields ID = 0 (null entries), using SymbolMapping.yaml"
    )
    parser.add_argument(
        "-fixstruct",
        action="store_true",
        help="Fix struct_offset fallback values by copying from closest valid version"
    )

    args = parser.parse_args()

    if not args.xml:
        parser.error("-xml cannot be empty")
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")
    if not args.syncfile and not args.yaml:
        parser.error("-yaml is required when not using -syncfile mode")

    return args


def load_yaml_config(yaml_path):
    """
    Load YAML configuration file.

    Args:
        yaml_path: Path to YAML file

    Returns:
        Tuple of (file_list, symbols_list)
        - file_list: List of file names to match (e.g., ["ntoskrnl.exe", "ntkrla57.exe"])
        - symbols_list: List of symbol dicts with "name" and "symbol" keys
    """
    if not HAS_YAML:
        print("Error: PyYAML module is required")
        print("Install project dependencies with: uv sync")
        sys.exit(1)

    if not os.path.exists(yaml_path):
        print(f"Error: YAML file not found: {yaml_path}")
        sys.exit(1)

    with open(yaml_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not isinstance(config, list) or len(config) == 0:
        print("Error: YAML config must be a non-empty array")
        sys.exit(1)

    # Use the first entry
    entry = config[0]

    file_list = entry.get("file", [])
    symbols_list = entry.get("symbols", [])

    if not file_list:
        print("Error: YAML config missing 'file' array")
        sys.exit(1)

    if not symbols_list:
        print("Error: YAML config missing 'symbols' array")
        sys.exit(1)

    # Validate symbols
    for sym in symbols_list:
        if "name" not in sym:
            print(f"Error: Each symbol must have 'name' key: {sym}")
            sys.exit(1)
        # Must have exactly one of: struct_offset, var_offset, fn_offset
        offset_keys = ["struct_offset", "var_offset", "fn_offset"]
        found_keys = [k for k in offset_keys if k in sym]
        if len(found_keys) != 1:
            print(f"Error: Each symbol must have exactly one of {offset_keys}: {sym}")
            sys.exit(1)
        # Validate type field
        if "type" not in sym:
            print(f"Error: Each symbol must have 'type' key: {sym}")
            sys.exit(1)
        if sym["type"] not in ["uint16", "uint32"]:
            print(f"Error: 'type' must be 'uint16' or 'uint32': {sym}")
            sys.exit(1)

    return file_list, symbols_list


def parse_symbol(symbol_str):
    """
    Parse a single symbol string into structure name and member name.

    Args:
        symbol_str: Symbol string like "_EPROCESS->SectionObject" or "_ALPC_PORT->u1.State"

    Returns:
        Tuple of (struct_name, member_name)
    """
    if "->" not in symbol_str:
        print(f"Error: Invalid symbol format '{symbol_str}'. Expected format: STRUCT->Member")
        sys.exit(1)

    parts = symbol_str.split("->", 1)
    if len(parts) != 2:
        print(f"Error: Invalid symbol format '{symbol_str}'. Expected format: STRUCT->Member")
        sys.exit(1)

    struct_name = parts[0].strip()
    member_name = parts[1].strip()

    # Add underscore prefix if not present (Windows kernel structures use _EPROCESS format)
    if not struct_name.startswith("_"):
        struct_name = "_" + struct_name

    return struct_name, member_name


def parse_symbol_with_fallback(symbol_str):
    """
    Parse symbol string that may contain fallback alternatives.

    Args:
        symbol_str: Symbol string, optionally with comma-separated fallbacks
                   e.g., "_SECTION->u1.ControlArea,_SECTION_OBJECT->Segment"

    Returns:
        List of (struct_name, member_name) tuples
    """
    alternatives = [s.strip() for s in symbol_str.split(",")]
    return [parse_symbol(alt) for alt in alternatives]


def get_all_entries_for_files(root, file_list, sha256_filter=None):
    """
    Get all <data> elements matching any file in file_list.

    Args:
        root: XML root element
        file_list: List of file names to match
        sha256_filter: Optional SHA256 hash to filter entries (case-insensitive)

    Returns:
        List of matching data elements
    """
    entries = []
    for data_elem in root.findall("data"):
        file_name = data_elem.get("file")
        if file_name in file_list:
            # If SHA256 filter is specified, check if it matches
            if sha256_filter:
                entry_hash = data_elem.get("hash", "").lower()
                if entry_hash != sha256_filter.lower():
                    continue
            entries.append(data_elem)
    return entries


def collect_existing_fields(root):
    """
    Collect all existing <fields> elements.

    Args:
        root: XML root element

    Returns:
        Dict mapping fields ID (int) to dict of {name: offset_int}
    """
    fields_map = {}
    for fields_elem in root.findall("fields"):
        fields_id = fields_elem.get("id")
        if fields_id is None:
            continue

        try:
            fields_id_int = int(fields_id)
        except ValueError:
            continue

        field_dict = {}
        for field_elem in fields_elem.findall("field"):
            name = field_elem.get("name")
            value = field_elem.get("value")
            if name and value:
                # Parse hex value like "0x0418" or "0x00001234"
                try:
                    offset = int(value, 16)
                    field_dict[name] = offset
                except ValueError:
                    pass

        fields_map[fields_id_int] = field_dict

    return fields_map


def get_pdb_path(symboldir, arch, version, sha256):
    """
    Build the path to the PDB file.

    Args:
        symboldir: Base symbol directory
        arch: Architecture (amd64, arm64, etc.)
        version: Windows version string
        sha256: SHA256 hash of the PE file (lowercase)

    Returns:
        Path to the PDB file
    """
    symbol_subdir = os.path.join(symboldir, arch, f"ntoskrnl.exe.{version}", sha256)
    pdb_path = os.path.join(symbol_subdir, "ntkrnlmp.pdb")
    return pdb_path


def run_llvm_pdbutil(pdb_path, pdbutil_path=None):
    """
    Run llvm-pdbutil to dump type information.

    Args:
        pdb_path: Path to the PDB file
        pdbutil_path: Optional path to llvm-pdbutil executable

    Returns:
        Output string, or None on failure
    """
    if not os.path.exists(pdb_path):
        return None

    # Use custom path or search in PATH
    pdbutil_cmd = pdbutil_path if pdbutil_path else "llvm-pdbutil"

    try:
        result = subprocess.run(
            [pdbutil_cmd, "dump", "-types", pdb_path],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode != 0:
            print(f"  llvm-pdbutil failed: {result.stderr}")
            return None

        return result.stdout

    except FileNotFoundError:
        if pdbutil_path:
            print(f"Error: llvm-pdbutil not found at: {pdbutil_path}")
        else:
            print("Error: llvm-pdbutil not found in PATH")
            print("Please install LLVM tools and ensure llvm-pdbutil is in your PATH")
            print("Or use -pdbutil to specify the path explicitly")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"  Timeout while parsing PDB: {pdb_path}")
        return None
    except Exception as e:
        print(f"  Error running llvm-pdbutil: {e}")
        return None


def parse_llvm_pdbutil_output(output, struct_name, member_name, need_bits=False, debug=False):
    """
    Parse llvm-pdbutil dump output to find member offset.

    Handles nested members like "u1.State" by finding the first part (u1)
    in the parent struct, then looking for the nested member in the union/struct type.

    Args:
        output: llvm-pdbutil output string
        struct_name: Structure name to find (e.g., _EPROCESS)
        member_name: Member name to find offset for (e.g., Protection or u1.State)
        need_bits: If True, return offset in bits (for bitfield members)
        debug: Enable debug logging

    Returns:
        If need_bits is False: Offset in bytes as integer, or None if not found
        If need_bits is True: Offset in bits as integer, or None if not found
    """
    lines = output.split('\n')

    # Handle nested members (e.g., u1.State)
    if '.' in member_name:
        parts = member_name.split('.', 1)
        parent_member = parts[0]
        nested_member = parts[1]

        if debug:
            print(f"    [DEBUG] Nested member: {struct_name}->{parent_member}.{nested_member}")

        # First, find the parent member's offset and type
        parent_offset = find_member_offset(lines, struct_name, parent_member, debug)
        if parent_offset is None:
            if debug:
                print(f"    [DEBUG] Parent member '{parent_member}' not found in '{struct_name}'")
            return None

        if debug:
            print(f"    [DEBUG] Parent offset: {parent_offset} (0x{parent_offset:x})")

        # Find the type of the parent member to get nested member offset
        parent_type_name, parent_type_id = find_member_type(lines, struct_name, parent_member, debug)

        if parent_type_id is None:
            if debug:
                print(f"    [DEBUG] Parent type ID not found, trying direct member search")
            # Try to find nested member by searching for it as a direct member
            # This handles anonymous unions/structs
            nested_offset = find_member_offset(lines, struct_name, nested_member, debug)
            if nested_offset is not None:
                if debug:
                    print(f"    [DEBUG] Found nested member as direct member: offset={nested_offset}")
                if need_bits:
                    return nested_offset * 8
                return nested_offset
            if debug:
                print(f"    [DEBUG] Nested member '{nested_member}' not found as direct member")
            return None

        if debug:
            print(f"    [DEBUG] Parent type: {parent_type_name} (ID: {parent_type_id})")

        # Get the offset of nested member within the parent type using type ID
        nested_offset = find_member_offset_by_type_id(lines, parent_type_id, nested_member, debug)
        if nested_offset is None:
            if debug:
                print(f"    [DEBUG] Nested member '{nested_member}' not found in type {parent_type_id}")
            return None

        if debug:
            print(f"    [DEBUG] Nested offset: {nested_offset}, total: {parent_offset + nested_offset}")

        total_offset = parent_offset + nested_offset
        if need_bits:
            return total_offset * 8
        return total_offset

    # Simple member (no nesting) - use bitfield-aware function if need_bits is True
    if need_bits:
        return find_member_offset_and_bitfield(lines, struct_name, member_name, need_bits=True, debug=debug)
    return find_member_offset(lines, struct_name, member_name, debug)


def find_member_offset(lines, struct_name, member_name, debug=False):
    """
    Find the offset of a member within a structure.

    Args:
        lines: List of output lines
        struct_name: Structure name
        member_name: Member name
        debug: Enable debug logging

    Returns:
        Offset as integer, or None if not found
    """
    # Step 1: Find the structure definition and get its field list ID
    field_list_id = None

    # Try LF_STRUCTURE or LF_STRUCTURE2 first
    for i, line in enumerate(lines):
        if ("LF_STRUCTURE " in line or "LF_STRUCTURE2 " in line) and f"`{struct_name}`" in line:
            if debug:
                lf_type = "LF_STRUCTURE2" if "LF_STRUCTURE2" in line else "LF_STRUCTURE"
                print(f"    [DEBUG] Found {lf_type} for '{struct_name}' at line {i}")
            for j in range(i + 1, min(i + 10, len(lines))):
                next_line = lines[j]
                if "forward ref" in next_line:
                    if debug:
                        print(f"    [DEBUG] Skipping forward reference")
                    break
                field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                if field_list_match:
                    field_list_id = field_list_match.group(1)
                    if debug:
                        print(f"    [DEBUG] Found field list ID: {field_list_id}")
                    break

            if field_list_id:
                break

    # Also check for LF_UNION or LF_UNION2
    if not field_list_id:
        for i, line in enumerate(lines):
            if ("LF_UNION " in line or "LF_UNION2 " in line) and f"`{struct_name}`" in line:
                if debug:
                    lf_type = "LF_UNION2" if "LF_UNION2" in line else "LF_UNION"
                    print(f"    [DEBUG] Found {lf_type} for '{struct_name}' at line {i}")
                for j in range(i + 1, min(i + 10, len(lines))):
                    next_line = lines[j]
                    if "forward ref" in next_line:
                        if debug:
                            print(f"    [DEBUG] Skipping forward reference")
                        break
                    field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                    if field_list_match:
                        field_list_id = field_list_match.group(1)
                        if debug:
                            print(f"    [DEBUG] Found field list ID: {field_list_id}")
                        break

                if field_list_id:
                    break

    # Try LF_CLASS or LF_CLASS2 as fallback
    if not field_list_id:
        for i, line in enumerate(lines):
            if ("LF_CLASS " in line or "LF_CLASS2 " in line) and f"`{struct_name}`" in line:
                if debug:
                    lf_type = "LF_CLASS2" if "LF_CLASS2" in line else "LF_CLASS"
                    print(f"    [DEBUG] Found {lf_type} for '{struct_name}' at line {i}")
                for j in range(i + 1, min(i + 10, len(lines))):
                    next_line = lines[j]
                    if "forward ref" in next_line:
                        if debug:
                            print(f"    [DEBUG] Skipping forward reference")
                        break
                    field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                    if field_list_match:
                        field_list_id = field_list_match.group(1)
                        if debug:
                            print(f"    [DEBUG] Found field list ID: {field_list_id}")
                        break

                if field_list_id:
                    break

    if not field_list_id:
        if debug:
            print(f"    [DEBUG] No field list ID found for '{struct_name}'")
            # Try to find any mention of the struct name for debugging
            for i, line in enumerate(lines):
                if struct_name in line:
                    print(f"    [DEBUG] Found '{struct_name}' mention at line {i}: {line.strip()[:100]}")
                    if i < 5:  # Only show first few matches
                        continue
                    break
        return None

    # Step 2: Find the LF_FIELDLIST with this ID and search for the member
    in_field_list = False

    for line in lines:
        if f"{field_list_id} | LF_FIELDLIST" in line:
            in_field_list = True
            if debug:
                print(f"    [DEBUG] Entered field list {field_list_id}")
            continue

        if in_field_list and re.match(r'\s*0x[0-9a-fA-F]+\s*\|\s*LF_', line):
            in_field_list = False
            continue

        if in_field_list:
            match = re.search(
                rf'LF_MEMBER\s*\[name\s*=\s*`{re.escape(member_name)}`.*offset\s*=\s*(\d+)',
                line
            )
            if match:
                offset = int(match.group(1))
                if debug:
                    print(f"    [DEBUG] Found member '{member_name}' with offset {offset}")
                return offset

    if debug:
        print(f"    [DEBUG] Member '{member_name}' not found in field list {field_list_id}")
    return None


def find_member_type(lines, struct_name, member_name, debug=False):
    """
    Find the type of a member within a structure.

    Args:
        lines: List of output lines
        struct_name: Structure name
        member_name: Member name
        debug: Enable debug logging

    Returns:
        Tuple of (type_name, type_id) or (None, None) if not found
    """
    # Find the structure's field list ID
    field_list_id = None

    for i, line in enumerate(lines):
        if ("LF_STRUCTURE " in line or "LF_STRUCTURE2 " in line) and f"`{struct_name}`" in line:
            for j in range(i + 1, min(i + 10, len(lines))):
                next_line = lines[j]
                if "forward ref" in next_line:
                    break
                field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                if field_list_match:
                    field_list_id = field_list_match.group(1)
                    break

            if field_list_id:
                break

    if not field_list_id:
        if debug:
            print(f"    [DEBUG] find_member_type: No field list for '{struct_name}'")
        return None, None

    # Find the member and extract its type
    in_field_list = False
    type_id = None

    for line in lines:
        if f"{field_list_id} | LF_FIELDLIST" in line:
            in_field_list = True
            continue

        if in_field_list and re.match(r'\s*0x[0-9a-fA-F]+\s*\|\s*LF_', line):
            in_field_list = False
            continue

        if in_field_list:
            match = re.search(
                rf'LF_MEMBER\s*\[name\s*=\s*`{re.escape(member_name)}`.*Type\s*=\s*(0x[0-9a-fA-F]+)',
                line
            )
            if match:
                type_id = match.group(1)
                if debug:
                    print(f"    [DEBUG] find_member_type: Found type ID {type_id} for '{member_name}'")
                break

    if not type_id:
        if debug:
            print(f"    [DEBUG] find_member_type: No type ID found for '{member_name}'")
        return None, None

    # Find the type definition to get its name
    for i, line in enumerate(lines):
        if f"{type_id} | LF_" in line:
            # Extract type name from the line
            name_match = re.search(r'`([^`]+)`', line)
            if name_match:
                type_name = name_match.group(1)
                if debug:
                    print(f"    [DEBUG] find_member_type: Type {type_id} is '{type_name}'")
                return type_name, type_id
            else:
                if debug:
                    print(f"    [DEBUG] find_member_type: Type {type_id} has no name, line: {line.strip()}")
                return None, type_id

    if debug:
        print(f"    [DEBUG] find_member_type: Type definition for {type_id} not found")
    return None, None


def get_bitfield_bit_offset(lines, type_id, debug=False):
    """
    Get the bit offset from an LF_BITFIELD type.

    Args:
        lines: List of output lines
        type_id: Type ID (e.g., 0x2AE3)
        debug: Enable debug logging

    Returns:
        Bit offset as integer, or None if not a bitfield or not found
    """
    for i, line in enumerate(lines):
        if f"{type_id} | LF_BITFIELD" in line:
            # Look at the next line for bit offset
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                bit_offset_match = re.search(r'bit offset\s*=\s*(\d+)', next_line)
                if bit_offset_match:
                    bit_offset = int(bit_offset_match.group(1))
                    if debug:
                        print(f"    [DEBUG] Found LF_BITFIELD {type_id} with bit offset = {bit_offset}")
                    return bit_offset
            break
    return None


def find_member_offset_and_bitfield(lines, struct_name, member_name, need_bits=False, debug=False):
    """
    Find the offset of a member within a structure, optionally with bitfield bit offset.

    Args:
        lines: List of output lines
        struct_name: Structure name
        member_name: Member name
        need_bits: If True, also calculate bitfield offset and return total bits offset
        debug: Enable debug logging

    Returns:
        If need_bits is False: Offset in bytes as integer, or None if not found
        If need_bits is True: Offset in bits as integer (byte_offset * 8 + bit_offset), or None if not found
    """
    # Step 1: Find the structure definition and get its field list ID
    field_list_id = None

    # Try LF_STRUCTURE or LF_STRUCTURE2 first
    for i, line in enumerate(lines):
        if ("LF_STRUCTURE " in line or "LF_STRUCTURE2 " in line) and f"`{struct_name}`" in line:
            if debug:
                lf_type = "LF_STRUCTURE2" if "LF_STRUCTURE2" in line else "LF_STRUCTURE"
                print(f"    [DEBUG] Found {lf_type} for '{struct_name}' at line {i}")
            for j in range(i + 1, min(i + 10, len(lines))):
                next_line = lines[j]
                if "forward ref" in next_line:
                    if debug:
                        print(f"    [DEBUG] Skipping forward reference")
                    break
                field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                if field_list_match:
                    field_list_id = field_list_match.group(1)
                    if debug:
                        print(f"    [DEBUG] Found field list ID: {field_list_id}")
                    break

            if field_list_id:
                break

    # Also check for LF_UNION or LF_UNION2
    if not field_list_id:
        for i, line in enumerate(lines):
            if ("LF_UNION " in line or "LF_UNION2 " in line) and f"`{struct_name}`" in line:
                if debug:
                    lf_type = "LF_UNION2" if "LF_UNION2" in line else "LF_UNION"
                    print(f"    [DEBUG] Found {lf_type} for '{struct_name}' at line {i}")
                for j in range(i + 1, min(i + 10, len(lines))):
                    next_line = lines[j]
                    if "forward ref" in next_line:
                        if debug:
                            print(f"    [DEBUG] Skipping forward reference")
                        break
                    field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                    if field_list_match:
                        field_list_id = field_list_match.group(1)
                        if debug:
                            print(f"    [DEBUG] Found field list ID: {field_list_id}")
                        break

                if field_list_id:
                    break

    # Try LF_CLASS or LF_CLASS2 as fallback
    if not field_list_id:
        for i, line in enumerate(lines):
            if ("LF_CLASS " in line or "LF_CLASS2 " in line) and f"`{struct_name}`" in line:
                if debug:
                    lf_type = "LF_CLASS2" if "LF_CLASS2" in line else "LF_CLASS"
                    print(f"    [DEBUG] Found {lf_type} for '{struct_name}' at line {i}")
                for j in range(i + 1, min(i + 10, len(lines))):
                    next_line = lines[j]
                    if "forward ref" in next_line:
                        if debug:
                            print(f"    [DEBUG] Skipping forward reference")
                        break
                    field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                    if field_list_match:
                        field_list_id = field_list_match.group(1)
                        if debug:
                            print(f"    [DEBUG] Found field list ID: {field_list_id}")
                        break

                if field_list_id:
                    break

    if not field_list_id:
        if debug:
            print(f"    [DEBUG] No field list ID found for '{struct_name}'")
        return None

    # Step 2: Find the LF_FIELDLIST with this ID and search for the member
    in_field_list = False

    for line in lines:
        if f"{field_list_id} | LF_FIELDLIST" in line:
            in_field_list = True
            if debug:
                print(f"    [DEBUG] Entered field list {field_list_id}")
            continue

        if in_field_list and re.match(r'\s*0x[0-9a-fA-F]+\s*\|\s*LF_', line):
            in_field_list = False
            continue

        if in_field_list:
            # Match LF_MEMBER with name, Type, and offset
            match = re.search(
                rf'LF_MEMBER\s*\[name\s*=\s*`{re.escape(member_name)}`.*Type\s*=\s*(0x[0-9a-fA-F]+).*offset\s*=\s*(\d+)',
                line
            )
            if match:
                type_id = match.group(1)
                byte_offset = int(match.group(2))
                if debug:
                    print(f"    [DEBUG] Found member '{member_name}' with Type={type_id}, byte offset={byte_offset}")

                if not need_bits:
                    return byte_offset

                # Check if the type is LF_BITFIELD
                bit_offset = get_bitfield_bit_offset(lines, type_id, debug)
                if bit_offset is not None:
                    total_bits = byte_offset * 8 + bit_offset
                    if debug:
                        print(f"    [DEBUG] Bitfield: byte_offset={byte_offset}, bit_offset={bit_offset}, total_bits={total_bits}")
                    return total_bits
                else:
                    # Not a bitfield, just return byte offset converted to bits
                    if debug:
                        print(f"    [DEBUG] Not a bitfield, returning byte offset * 8 = {byte_offset * 8}")
                    return byte_offset * 8

    if debug:
        print(f"    [DEBUG] Member '{member_name}' not found in field list {field_list_id}")
    return None


def find_member_offset_by_type_id(lines, type_id, member_name, debug=False):
    """
    Find the offset of a member within a structure/union identified by type ID.

    Args:
        lines: List of output lines
        type_id: Type ID (e.g., 0x1B3D)
        member_name: Member name
        debug: Enable debug logging

    Returns:
        Offset as integer, or None if not found
    """
    # Find the type definition and get its field list ID
    field_list_id = None

    # Match LF_STRUCTURE, LF_STRUCTURE2, LF_UNION, LF_UNION2
    for i, line in enumerate(lines):
        if f"{type_id} | LF_" in line:
            is_struct_or_union = ("LF_STRUCTURE " in line or "LF_STRUCTURE2 " in line or
                                  "LF_UNION " in line or "LF_UNION2 " in line)
            if is_struct_or_union:
                if debug:
                    print(f"    [DEBUG] Found type {type_id} at line {i}: {line.strip()[:80]}")
                for j in range(i + 1, min(i + 10, len(lines))):
                    next_line = lines[j]
                    if "forward ref" in next_line:
                        if debug:
                            print(f"    [DEBUG] Skipping forward reference for {type_id}")
                        break
                    field_list_match = re.search(r'field list:\s*(0x[0-9a-fA-F]+)', next_line)
                    if field_list_match:
                        field_list_id = field_list_match.group(1)
                        if debug:
                            print(f"    [DEBUG] Type {type_id} has field list ID: {field_list_id}")
                        break

                if field_list_id:
                    break

    if not field_list_id:
        if debug:
            print(f"    [DEBUG] No field list ID found for type {type_id}")
        return None

    # Find the LF_FIELDLIST with this ID and search for the member
    in_field_list = False

    for line in lines:
        if f"{field_list_id} | LF_FIELDLIST" in line:
            in_field_list = True
            if debug:
                print(f"    [DEBUG] Entered field list {field_list_id} for type {type_id}")
            continue

        if in_field_list and re.match(r'\s*0x[0-9a-fA-F]+\s*\|\s*LF_', line):
            in_field_list = False
            continue

        if in_field_list:
            match = re.search(
                rf'LF_MEMBER\s*\[name\s*=\s*`{re.escape(member_name)}`.*offset\s*=\s*(\d+)',
                line
            )
            if match:
                offset = int(match.group(1))
                if debug:
                    print(f"    [DEBUG] Found member '{member_name}' in type {type_id} with offset {offset}")
                return offset

    if debug:
        print(f"    [DEBUG] Member '{member_name}' not found in type {type_id} field list {field_list_id}")
    return None


def run_llvm_pdbutil_publics(pdb_path, pdbutil_path=None):
    """
    Run llvm-pdbutil to dump public symbols (for global variables and functions).

    Args:
        pdb_path: Path to the PDB file
        pdbutil_path: Optional path to llvm-pdbutil executable

    Returns:
        Output string, or None on failure
    """
    if not os.path.exists(pdb_path):
        return None

    # Use custom path or search in PATH
    pdbutil_cmd = pdbutil_path if pdbutil_path else "llvm-pdbutil"

    try:
        result = subprocess.run(
            [pdbutil_cmd, "dump", "-publics", pdb_path],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode != 0:
            print(f"  llvm-pdbutil (publics) failed: {result.stderr}")
            return None

        return result.stdout

    except FileNotFoundError:
        if pdbutil_path:
            print(f"Error: llvm-pdbutil not found at: {pdbutil_path}")
        else:
            print("Error: llvm-pdbutil not found in PATH")
            print("Please install LLVM tools and ensure llvm-pdbutil is in your PATH")
            print("Or use -pdbutil to specify the path explicitly")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"  Timeout while parsing PDB (publics): {pdb_path}")
        return None
    except Exception as e:
        print(f"  Error running llvm-pdbutil (publics): {e}")
        return None


def run_llvm_pdbutil_sections(pdb_path, pdbutil_path=None):
    """
    Run llvm-pdbutil to dump section headers.

    Args:
        pdb_path: Path to the PDB file
        pdbutil_path: Optional path to llvm-pdbutil executable

    Returns:
        Output string, or None on failure
    """
    if not os.path.exists(pdb_path):
        return None

    pdbutil_cmd = pdbutil_path if pdbutil_path else "llvm-pdbutil"

    try:
        result = subprocess.run(
            [pdbutil_cmd, "dump", "-section-headers", pdb_path],
            capture_output=True,
            timeout=300
        )

        if result.returncode != 0:
            stderr = result.stderr.decode('utf-8', errors='replace')
            print(f"  llvm-pdbutil (sections) failed: {stderr}")
            return None

        # Decode with error handling for non-UTF8 section names
        return result.stdout.decode('utf-8', errors='replace')

    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        print(f"  Timeout while parsing PDB (sections): {pdb_path}")
        return None
    except Exception as e:
        print(f"  Error running llvm-pdbutil (sections): {e}")
        return None


def parse_section_headers(output, debug=False):
    """
    Parse llvm-pdbutil section headers output to get section virtual addresses.

    Args:
        output: llvm-pdbutil section-headers dump output string
        debug: Enable debug logging

    Returns:
        Dict mapping section number (1-based) to virtual address
    """
    sections = {}
    lines = output.split('\n')

    current_section = None
    for line in lines:
        # Match "SECTION HEADER #N"
        section_match = re.search(r'SECTION HEADER #(\d+)', line)
        if section_match:
            current_section = int(section_match.group(1))
            continue

        # Match "virtual address" line (hex value followed by "virtual address")
        if current_section is not None:
            va_match = re.search(r'^\s*([0-9a-fA-F]+)\s+virtual address', line)
            if va_match:
                va = int(va_match.group(1), 16)
                sections[current_section] = va
                if debug:
                    print(f"    [DEBUG] Section {current_section}: VA = 0x{va:08x}")
                current_section = None

    return sections


def parse_public_symbol_offset(output, symbol_name, symbol_type, section_vas, debug=False):
    """
    Parse llvm-pdbutil publics dump output to find a symbol's RVA.

    Args:
        output: llvm-pdbutil publics dump output string
        symbol_name: Symbol name to find (e.g., PspCreateProcessNotifyRoutine)
        symbol_type: Type of symbol ('var' for variable, 'fn' for function)
        section_vas: Dict mapping section number to virtual address
        debug: Enable debug logging

    Returns:
        RVA offset as integer, or None if not found
    """
    lines = output.split('\n')

    # Pattern for public symbols:
    # For variables: "     4 | S_PUB32 [size = 36] `PspCreateProcessNotifyRoutine`"
    #                "           flags = none, addr = 0026:1068896"
    # For functions: "     4 | S_PUB32 [size = 44] `ExReferenceCallBackBlock`"
    #                "           flags = function, addr = 0008:123456"
    # Note: segment and offset are in decimal format

    expected_flags = "function" if symbol_type == "fn" else "none"

    for i, line in enumerate(lines):
        # Look for the symbol name in S_PUB32 record
        if "S_PUB32" in line and f"`{symbol_name}`" in line:
            if debug:
                print(f"    [DEBUG] Found S_PUB32 for '{symbol_name}' at line {i}")

            # Look at the next line for flags and addr
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if debug:
                    print(f"    [DEBUG] Next line: {next_line.strip()}")

                # Check flags match expected type
                flags_match = re.search(r'flags\s*=\s*(\w+)', next_line)
                if flags_match:
                    actual_flags = flags_match.group(1)
                    if actual_flags != expected_flags:
                        if debug:
                            print(f"    [DEBUG] Skipping: flags={actual_flags}, expected={expected_flags}")
                        continue

                # Extract address (segment:offset format, both in decimal)
                addr_match = re.search(r'addr\s*=\s*(\d+):(\d+)', next_line)
                if addr_match:
                    segment = int(addr_match.group(1), 10)
                    offset = int(addr_match.group(2), 10)
                    if debug:
                        print(f"    [DEBUG] Found addr: segment={segment}, offset={offset} (0x{offset:x})")

                    # Calculate RVA: section VA + offset within section
                    if segment in section_vas:
                        section_va = section_vas[segment]
                        rva = section_va + offset
                        if debug:
                            print(f"    [DEBUG] RVA = section_va(0x{section_va:x}) + offset(0x{offset:x}) = 0x{rva:x}")
                        return rva
                    else:
                        if debug:
                            print(f"    [DEBUG] Section {segment} not found in section_vas")
                        return None

    if debug:
        print(f"    [DEBUG] Symbol '{symbol_name}' not found in publics")
    return None


def parse_pdb_all_symbols(pdb_path, symbols_list, pdbutil_path=None, debug=False):
    """
    Parse PDB file to get offsets for all symbols.

    Supports three types of symbols:
    - struct_offset: Structure member offsets (e.g., "_EPROCESS->ObjectTable")
    - var_offset: Global variable offsets (e.g., "PspCreateProcessNotifyRoutine")
    - fn_offset: Function offsets (e.g., "ExReferenceCallBackBlock")

    Args:
        pdb_path: Path to the PDB file
        symbols_list: List of symbol dicts with "name" and one of
                      struct_offset/var_offset/fn_offset keys
        pdbutil_path: Optional path to llvm-pdbutil executable
        debug: Enable debug logging

    Returns:
        Dict mapping symbol name to offset (0xffffffff if symbol not found)
    """
    # Check which types of symbols we need
    need_types = any("struct_offset" in sym for sym in symbols_list)
    need_publics = any("var_offset" in sym or "fn_offset" in sym for sym in symbols_list)

    types_output = None
    publics_output = None
    section_vas = None

    if need_types:
        types_output = run_llvm_pdbutil(pdb_path, pdbutil_path)
        if types_output is None:
            return None

    if need_publics:
        publics_output = run_llvm_pdbutil_publics(pdb_path, pdbutil_path)
        if publics_output is None:
            return None

        # Get section headers for RVA calculation
        sections_output = run_llvm_pdbutil_sections(pdb_path, pdbutil_path)
        if sections_output is None:
            return None
        section_vas = parse_section_headers(sections_output, debug)

    offsets = {}
    for sym in symbols_list:
        name = sym["name"]
        sym_type = sym["type"]
        max_value = 0xffff if sym_type == "uint16" else 0xffffffff
        offset = None

        if "struct_offset" in sym:
            # Handle structure member offset
            symbol_str = sym["struct_offset"]
            need_bits = sym.get("bits", False)

            # Parse symbol with fallback support
            alternatives = parse_symbol_with_fallback(symbol_str)

            if debug:
                bits_str = " (bits mode)" if need_bits else ""
                if len(alternatives) > 1:
                    print(f"    [DEBUG] Parsing struct_offset: {symbol_str} (with {len(alternatives)} alternatives){bits_str}")
                else:
                    struct_name, member_name = alternatives[0]
                    print(f"    [DEBUG] Parsing struct_offset: {symbol_str} -> {struct_name}->{member_name}{bits_str}")

            used_alternative = None
            for struct_name, member_name in alternatives:
                offset = parse_llvm_pdbutil_output(types_output, struct_name, member_name, need_bits=need_bits, debug=debug)
                if offset is not None:
                    used_alternative = f"{struct_name}->{member_name}"
                    break

            if offset is None:
                print(f"  Warning: struct_offset not found: {symbol_str}, using {max_value:#x}")
                offset = max_value
            elif offset > max_value:
                print(f"  Warning: offset {offset:#x} exceeds {sym_type} max ({max_value:#x}), clamping to {max_value:#x}")
                offset = max_value

            if debug:
                if len(alternatives) > 1 and used_alternative:
                    width = 4 if sym_type == "uint16" else 8
                    print(f"    [DEBUG] Result: {name} = {offset:#0{width+2}x} (using {used_alternative})")
                else:
                    width = 4 if sym_type == "uint16" else 8
                    print(f"    [DEBUG] Result: {name} = {offset:#0{width+2}x}")

        elif "var_offset" in sym:
            # Handle global variable offset
            symbol_name = sym["var_offset"]

            if debug:
                print(f"    [DEBUG] Parsing var_offset: {symbol_name}")

            offset = parse_public_symbol_offset(publics_output, symbol_name, "var", section_vas, debug)

            if offset is None:
                print(f"  Warning: var_offset not found: {symbol_name}, using {max_value:#x}")
                offset = max_value
            elif offset > max_value:
                print(f"  Warning: offset {offset:#x} exceeds {sym_type} max ({max_value:#x}), clamping to {max_value:#x}")
                offset = max_value

            if debug:
                width = 4 if sym_type == "uint16" else 8
                print(f"    [DEBUG] Result: {name} = {offset:#0{width+2}x}")

        elif "fn_offset" in sym:
            # Handle function offset
            symbol_name = sym["fn_offset"]

            if debug:
                print(f"    [DEBUG] Parsing fn_offset: {symbol_name}")

            offset = parse_public_symbol_offset(publics_output, symbol_name, "fn", section_vas, debug)

            if offset is None:
                print(f"  Warning: fn_offset not found: {symbol_name}, using {max_value:#x}")
                offset = max_value
            elif offset > max_value:
                print(f"  Warning: offset {offset:#x} exceeds {sym_type} max ({max_value:#x}), clamping to {max_value:#x}")
                offset = max_value

            if debug:
                width = 4 if sym_type == "uint16" else 8
                print(f"    [DEBUG] Result: {name} = {offset:#0{width+2}x}")

        offsets[name] = offset

    return offsets


def find_matching_fields_id(existing_fields, new_offsets):
    """
    Find an existing fields ID that matches the new offsets exactly.

    Args:
        existing_fields: Dict mapping fields ID to {name: offset}
        new_offsets: Dict of {name: offset} to match

    Returns:
        Matching fields ID (int), or None if no match
    """
    for fields_id, field_dict in existing_fields.items():
        if field_dict == new_offsets:
            return fields_id
    return None


def allocate_new_fields_id(existing_ids):
    """
    Allocate a new fields ID that doesn't conflict with existing ones.

    Searches from 1 upwards to find the smallest available ID, preventing
    ID explosion over time when entries are added and removed.

    Args:
        existing_ids: Set of existing IDs (integers) that are in use

    Returns:
        New ID (int)
    """
    new_id = 1
    while new_id in existing_ids:
        new_id += 1
    return new_id


def create_fields_element(root, fields_id, offsets, symbols_list):
    """
    Create a new <fields> element with the given offsets.

    Args:
        root: XML root element
        fields_id: ID for the new fields element
        offsets: Dict of {name: offset}
        symbols_list: List of symbol dicts to preserve order
    """
    fields_elem = ET.SubElement(root, "fields")
    fields_elem.set("id", str(fields_id))

    # Add fields in the order specified in symbols_list
    for sym in symbols_list:
        name = sym["name"]
        if name in offsets:
            field_elem = ET.SubElement(fields_elem, "field")
            # Format based on type
            sym_type = sym["type"]
            offset_value = offsets[name]
            if sym_type == "uint16":
                # uint16: 4-digit hex with max 0xffff
                field_elem.set("value", f"0x{offset_value:04x}")
            else:  # uint32
                # uint32: 8-digit hex with max 0xffffffff
                field_elem.set("value", f"0x{offset_value:08x}")
            field_elem.set("name", name)


def collect_all_referenced_ids(root):
    """
    Collect all fields IDs referenced by any <data> entry in the XML.

    Args:
        root: XML root element

    Returns:
        Set of referenced fields IDs (integers)
    """
    referenced_ids = set()
    for data_elem in root.findall("data"):
        text = data_elem.text
        if text:
            try:
                fields_id = int(text.strip())
                referenced_ids.add(fields_id)
            except ValueError:
                pass
    return referenced_ids


def remove_orphan_fields(root):
    """
    Remove <fields> elements that are not referenced by any <data> entry.

    This function scans ALL <data> entries in the XML to determine which
    fields are still in use, ensuring that fields referenced by entries
    not processed in the current run (e.g., lxcore.sys) are preserved.

    Args:
        root: XML root element

    Returns:
        Number of fields elements removed
    """
    # Collect ALL referenced IDs from ALL data entries
    referenced_ids = collect_all_referenced_ids(root)

    fields_to_remove = []
    for fields_elem in root.findall("fields"):
        fields_id = fields_elem.get("id")
        if fields_id is not None:
            try:
                fields_id_int = int(fields_id)
                if fields_id_int not in referenced_ids:
                    fields_to_remove.append(fields_elem)
            except ValueError:
                pass

    for fields_elem in fields_to_remove:
        root.remove(fields_elem)

    return len(fields_to_remove)


# =============================================================================
# Fixnull Mode Functions
# =============================================================================

def get_symbol_mapping_path(symboldir, arch, file_name, version, sha256):
    """
    Build the path to the SymbolMapping.yaml file.

    Args:
        symboldir: Base symbol directory
        arch: Architecture (amd64, arm64, etc.)
        file_name: File name (e.g., ntoskrnl.exe)
        version: Windows version string
        sha256: SHA256 hash of the PE file (lowercase)

    Returns:
        Path to the SymbolMapping.yaml file
    """
    symbol_subdir = os.path.join(symboldir, arch, f"{file_name}.{version}", sha256)
    mapping_path = os.path.join(symbol_subdir, "SymbolMapping.yaml")
    return mapping_path


def load_symbol_mapping(mapping_path):
    """
    Load SymbolMapping.yaml file and parse symbol addresses.

    The file format is:
        sub_140822108: PspSetCreateProcessNotifyRoutine
        stru_140D0C080: PspCreateProcessNotifyRoutine
        '140000000': ImageBase

    Args:
        mapping_path: Path to SymbolMapping.yaml file

    Returns:
        Dict mapping symbol name to address (int), or None on failure
    """
    if not HAS_YAML:
        print("Error: PyYAML module is required for -fixnull mode")
        print("Install project dependencies with: uv sync")
        sys.exit(1)

    if not os.path.exists(mapping_path):
        return None

    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            mapping = yaml.safe_load(f)

        if not isinstance(mapping, dict):
            print(f"  Warning: Invalid SymbolMapping.yaml format")
            return None

        # Build reverse mapping: symbol_name -> address
        symbol_to_addr = {}
        image_base = None

        for key, value in mapping.items():
            # Handle ImageBase
            if value == "ImageBase":
                # Key is the address (e.g., '140000000')
                try:
                    image_base = int(str(key), 16)
                except ValueError:
                    print(f"  Warning: Invalid ImageBase address: {key}")
                    continue
            else:
                # Key is like "sub_140822108" or "stru_140D0C080"
                # Extract address from key
                key_str = str(key)
                addr_match = re.search(r'_([0-9a-fA-F]+)$', key_str)
                if addr_match:
                    try:
                        addr = int(addr_match.group(1), 16)
                        symbol_to_addr[value] = addr
                    except ValueError:
                        pass

        if image_base is None:
            print(f"  Warning: ImageBase not found in SymbolMapping.yaml")
            return None

        # Calculate RVA (offset from ImageBase) for each symbol
        result = {}
        for name, addr in symbol_to_addr.items():
            rva = addr - image_base
            result[name] = rva

        return result

    except Exception as e:
        print(f"  Warning: Failed to load SymbolMapping.yaml: {e}")
        return None


def parse_symbols_from_mapping(mapping, symbols_list, debug=False):
    """
    Extract symbol offsets from SymbolMapping.yaml data.

    Only processes var_offset and fn_offset symbols.
    struct_offset symbols are skipped (they need PDB parsing).

    Args:
        mapping: Dict mapping symbol name to RVA offset
        symbols_list: List of symbol dicts from YAML config
        debug: Enable debug logging

    Returns:
        Dict mapping symbol name to offset, or None if any required symbol is missing
    """
    offsets = {}

    for sym in symbols_list:
        name = sym["name"]
        sym_type = sym["type"]
        max_value = 0xffff if sym_type == "uint16" else 0xffffffff
        offset = None

        if "struct_offset" in sym:
            # struct_offset symbols are handled separately via PDB
            continue

        elif "var_offset" in sym:
            symbol_name = sym["var_offset"]
            if symbol_name in mapping:
                offset = mapping[symbol_name]
                if debug:
                    print(f"    [DEBUG] var_offset '{symbol_name}' = 0x{offset:08x}")
            else:
                if debug:
                    print(f"    [DEBUG] var_offset '{symbol_name}' not found in mapping")
                return None

        elif "fn_offset" in sym:
            symbol_name = sym["fn_offset"]
            if symbol_name in mapping:
                offset = mapping[symbol_name]
                if debug:
                    print(f"    [DEBUG] fn_offset '{symbol_name}' = 0x{offset:08x}")
            else:
                if debug:
                    print(f"    [DEBUG] fn_offset '{symbol_name}' not found in mapping")
                return None

        if offset is not None:
            if offset > max_value:
                print(f"  Warning: offset 0x{offset:x} exceeds {sym_type} max (0x{max_value:x}), clamping")
                offset = max_value
            offsets[name] = offset

    return offsets


def get_null_entries_for_files(root, file_list):
    """
    Get all <data> elements with fields ID = 0 matching any file in file_list.

    Args:
        root: XML root element
        file_list: List of file names to match

    Returns:
        List of matching data elements with fields ID = 0
    """
    entries = []
    for data_elem in root.findall("data"):
        file_name = data_elem.get("file")
        if file_name in file_list:
            # Check if fields ID is 0
            text = data_elem.text
            if text and text.strip() == "0":
                entries.append(data_elem)
    return entries


def fixnull_main(args, root, file_list, symbols_list):
    """
    Main function for -fixnull mode.

    Args:
        args: Parsed command line arguments
        root: XML root element
        file_list: List of file names to match
        symbols_list: List of symbol dicts from YAML config

    Returns:
        Tuple of (success_count, skip_count, fail_count)
    """
    symboldir = args.symboldir
    debug = args.debug
    pdbutil_path = args.pdbutil

    # Check if we have symbols that require SymbolMapping.yaml
    # (var_offset or fn_offset)
    mapping_symbols = [s for s in symbols_list if "var_offset" in s or "fn_offset" in s]
    struct_symbols = [s for s in symbols_list if "struct_offset" in s]

    if not mapping_symbols:
        print("Error: -fixnull requires symbols with var_offset or fn_offset")
        sys.exit(1)

    # Get null entries
    null_entries = get_null_entries_for_files(root, file_list)
    print(f"  Found {len(null_entries)} null entries (fields ID = 0)")

    if not null_entries:
        print("No null entries found.")
        return 0, 0, 0

    # Collect existing fields
    existing_fields = collect_existing_fields(root)

    success_count = 0
    skip_count = 0
    fail_count = 0

    referenced_ids = set()
    new_fields = {}
    mapping_cache = {}

    for i, data_entry in enumerate(null_entries):
        arch = data_entry.get("arch")
        version = data_entry.get("version")
        file_name = data_entry.get("file")
        sha256 = data_entry.get("hash", "").lower()

        print(f"\n[{i+1}/{len(null_entries)}] Processing {file_name} {version} ({arch})")

        if not sha256:
            print(f"  Warning: No hash attribute in data entry, skipping")
            skip_count += 1
            continue

        cache_key = (arch, version, sha256)
        offsets = None

        # Try to get offsets from cache first
        if cache_key in mapping_cache:
            offsets = mapping_cache[cache_key]
            print(f"  Using cached offsets")
        else:
            # Load SymbolMapping.yaml
            mapping_path = get_symbol_mapping_path(symboldir, arch, file_name, version, sha256)

            if not os.path.exists(mapping_path):
                print(f"  SymbolMapping.yaml not found: {mapping_path}")
                skip_count += 1
                continue

            print(f"  Loading SymbolMapping.yaml")
            mapping = load_symbol_mapping(mapping_path)

            if mapping is None:
                print(f"  Failed to load SymbolMapping.yaml")
                skip_count += 1
                continue

            if debug:
                print(f"    [DEBUG] Loaded {len(mapping)} symbols from mapping")

            # Get offsets for var_offset and fn_offset symbols
            mapping_offsets = parse_symbols_from_mapping(mapping, mapping_symbols, debug)

            if mapping_offsets is None:
                print(f"  Failed to get all mapping symbols")
                skip_count += 1
                continue

            # If there are struct_offset symbols, try PDB or fallback to max values
            if struct_symbols:
                pdb_path = get_pdb_path(symboldir, arch, version, sha256)
                struct_offsets = None

                if os.path.exists(pdb_path):
                    print(f"  Parsing PDB for struct symbols")
                    struct_offsets = parse_pdb_all_symbols(pdb_path, struct_symbols, pdbutil_path, debug)

                    if struct_offsets is None:
                        print(f"  Failed to extract struct symbols from PDB, using fallback values")
                else:
                    print(f"  PDB not found: {pdb_path}, using fallback values for struct symbols")

                # If PDB parsing failed or PDB not found, use fallback values
                if struct_offsets is None:
                    struct_offsets = {}
                    for sym in struct_symbols:
                        name = sym["name"]
                        sym_type = sym["type"]
                        max_value = 0xffff if sym_type == "uint16" else 0xffffffff
                        struct_offsets[name] = max_value
                        if debug:
                            width = 4 if sym_type == "uint16" else 8
                            print(f"    [DEBUG] struct_offset '{name}' fallback = 0x{max_value:0{width}x}")

                # Merge offsets
                offsets = {**struct_offsets, **mapping_offsets}
            else:
                offsets = mapping_offsets

            mapping_cache[cache_key] = offsets

        # Find matching fields ID
        fields_id = find_matching_fields_id(existing_fields, offsets)

        if fields_id is None:
            # Check new fields
            for new_id, new_offsets in new_fields.items():
                if new_offsets == offsets:
                    fields_id = new_id
                    break

        if fields_id is None:
            # Allocate new ID
            all_ids = set(existing_fields.keys()) | set(new_fields.keys())
            fields_id = allocate_new_fields_id(all_ids)
            new_fields[fields_id] = offsets
            print(f"  Created new fields id={fields_id}")
        else:
            print(f"  Using existing fields id={fields_id}")

        # Update data entry
        data_entry.text = str(fields_id)
        referenced_ids.add(fields_id)
        success_count += 1

    # Add new fields elements to the XML
    for fields_id, offsets in sorted(new_fields.items()):
        create_fields_element(root, fields_id, offsets, symbols_list)

    return success_count, skip_count, fail_count


# =============================================================================
# Fixstruct Mode Functions
# =============================================================================

def is_fallback_value(value, sym_type):
    """
    Check if a value is the fallback/reserved value.

    Args:
        value: The offset value (int)
        sym_type: Symbol type ("uint16" or "uint32")

    Returns:
        True if value is the fallback value
    """
    if sym_type == "uint16":
        return value == 0xffff
    else:  # uint32
        return value == 0xffffffff


def version_distance(v1_str, v2_str):
    """
    Calculate distance between two version strings.

    Args:
        v1_str: First version string (e.g., "10.0.19041.2545")
        v2_str: Second version string

    Returns:
        Distance as a float (smaller = closer)
    """
    t1 = parse_version(v1_str)
    t2 = parse_version(v2_str)
    # Weight: major > minor > build > revision
    return (abs(t1[0] - t2[0]) * 1e12 +
            abs(t1[1] - t2[1]) * 1e8 +
            abs(t1[2] - t2[2]) * 1e4 +
            abs(t1[3] - t2[3]))


def get_entries_needing_struct_fix(root, file_list, struct_symbols, existing_fields):
    """
    Get all data entries with fields ID > 0 that have fallback struct_offset values.

    Args:
        root: XML root element
        file_list: List of file names to match
        struct_symbols: List of struct_offset symbol dicts
        existing_fields: Dict mapping fields ID to {name: offset}

    Returns:
        List of (data_elem, fields_id, fields_to_fix)
        where fields_to_fix is a list of (field_name, sym_type) tuples
    """
    entries = []

    for data_elem in root.findall("data"):
        file_name = data_elem.get("file")
        if file_name not in file_list:
            continue

        # Get fields ID
        text = data_elem.text
        if not text:
            continue

        try:
            fields_id = int(text.strip())
        except ValueError:
            continue

        # Skip null entries (fields ID = 0)
        if fields_id == 0:
            continue

        # Get the fields dict for this entry
        if fields_id not in existing_fields:
            continue

        field_dict = existing_fields[fields_id]

        # Check which struct_offset fields have fallback values
        fields_to_fix = []
        for sym in struct_symbols:
            name = sym["name"]
            sym_type = sym["type"]

            if name in field_dict:
                value = field_dict[name]
                if is_fallback_value(value, sym_type):
                    fields_to_fix.append((name, sym_type))

        if fields_to_fix:
            entries.append((data_elem, fields_id, fields_to_fix))

    return entries


def find_closest_valid_entry(root, arch, file_list, target_version, struct_symbols, existing_fields):
    """
    Find the closest version entry that has valid (non-fallback) struct_offset values.

    Args:
        root: XML root element
        arch: Architecture to match
        file_list: List of file names to match
        target_version: Target version string to find closest to
        struct_symbols: List of struct_offset symbol dicts
        existing_fields: Dict mapping fields ID to {name: offset}

    Returns:
        Tuple of (fields_id, fields_dict) or (None, None) if not found
    """
    candidates = []

    for data_elem in root.findall("data"):
        elem_arch = data_elem.get("arch")
        elem_file = data_elem.get("file")
        elem_version = data_elem.get("version")

        # Must match arch and be in file_list
        if elem_arch != arch or elem_file not in file_list:
            continue

        # Skip the target version itself
        if elem_version == target_version:
            continue

        # Get fields ID
        text = data_elem.text
        if not text:
            continue

        try:
            fields_id = int(text.strip())
        except ValueError:
            continue

        # Skip null entries
        if fields_id == 0:
            continue

        if fields_id not in existing_fields:
            continue

        field_dict = existing_fields[fields_id]

        # Check if ALL struct_offset fields have valid (non-fallback) values
        all_valid = True
        for sym in struct_symbols:
            name = sym["name"]
            sym_type = sym["type"]

            if name not in field_dict:
                all_valid = False
                break

            value = field_dict[name]
            if is_fallback_value(value, sym_type):
                all_valid = False
                break

        if all_valid:
            distance = version_distance(target_version, elem_version)
            candidates.append((distance, elem_version, fields_id, field_dict))

    if not candidates:
        return None, None

    # Sort by distance, pick the closest
    candidates.sort(key=lambda x: x[0])
    _, closest_version, fields_id, field_dict = candidates[0]

    return fields_id, field_dict, closest_version


def fixstruct_main(args, root, file_list, symbols_list):
    """
    Main function for -fixstruct mode.

    Fixes struct_offset fallback values by copying from the closest valid version.

    Args:
        args: Parsed command line arguments
        root: XML root element
        file_list: List of file names to match
        symbols_list: List of symbol dicts from YAML config

    Returns:
        Tuple of (success_count, skip_count, unchanged_count)
    """
    debug = args.debug

    # Get struct_offset symbols only
    struct_symbols = [s for s in symbols_list if "struct_offset" in s]

    if not struct_symbols:
        print("No struct_offset symbols found in YAML config")
        return 0, 0, 0

    print(f"  struct_offset symbols to check: {len(struct_symbols)}")

    # Collect existing fields
    existing_fields = collect_existing_fields(root)
    print(f"  Found {len(existing_fields)} existing fields sections")

    # Get entries that need fixing
    entries_to_fix = get_entries_needing_struct_fix(root, file_list, struct_symbols, existing_fields)
    print(f"  Found {len(entries_to_fix)} entries with fallback struct_offset values")

    if not entries_to_fix:
        print("No entries need fixing.")
        return 0, 0, 0

    success_count = 0
    skip_count = 0
    unchanged_count = 0

    new_fields = {}  # new_fields_id -> offsets

    for i, (data_entry, old_fields_id, fields_to_fix) in enumerate(entries_to_fix):
        arch = data_entry.get("arch")
        version = data_entry.get("version")
        file_name = data_entry.get("file")

        field_names_to_fix = [f[0] for f in fields_to_fix]
        print(f"\n[{i+1}/{len(entries_to_fix)}] {file_name} {version} ({arch})")
        print(f"  Fields to fix: {', '.join(field_names_to_fix)}")

        # Find closest valid entry
        result = find_closest_valid_entry(root, arch, file_list, version, struct_symbols, existing_fields)

        if result[0] is None:
            print(f"  No valid source entry found, skipping")
            skip_count += 1
            continue

        source_fields_id, source_field_dict, source_version = result
        print(f"  Found source: version {source_version} (fields id={source_fields_id})")

        if debug:
            for name, sym_type in fields_to_fix:
                source_value = source_field_dict.get(name, 0)
                width = 4 if sym_type == "uint16" else 8
                print(f"    [DEBUG] {name}: 0x{source_value:0{width}x}")

        # Build new offsets by merging current fields with source struct_offset values
        current_field_dict = existing_fields[old_fields_id]
        new_offsets = dict(current_field_dict)  # Copy current values

        # Override struct_offset fields with source values
        for sym in struct_symbols:
            name = sym["name"]
            if name in source_field_dict:
                new_offsets[name] = source_field_dict[name]

        # Check if anything actually changed
        if new_offsets == current_field_dict:
            print(f"  No changes needed")
            unchanged_count += 1
            continue

        # Find matching fields ID
        fields_id = find_matching_fields_id(existing_fields, new_offsets)

        if fields_id is None:
            # Check new fields
            for new_id, new_off in new_fields.items():
                if new_off == new_offsets:
                    fields_id = new_id
                    break

        if fields_id is None:
            # Allocate new ID
            all_ids = set(existing_fields.keys()) | set(new_fields.keys())
            fields_id = allocate_new_fields_id(all_ids)
            new_fields[fields_id] = new_offsets
            print(f"  Created new fields id={fields_id}")
        else:
            print(f"  Using existing fields id={fields_id}")

        # Update data entry
        data_entry.text = str(fields_id)
        success_count += 1

    # Add new fields elements to the XML
    for fields_id, offsets in sorted(new_fields.items()):
        create_fields_element(root, fields_id, offsets, symbols_list)

    # Remove orphan fields
    removed_count = remove_orphan_fields(root)
    if removed_count > 0:
        print(f"\nRemoved {removed_count} orphan fields sections")

    return success_count, skip_count, unchanged_count


# =============================================================================
# Syncfile Mode Functions
# =============================================================================

def parse_version(version_str):
    """
    Parse version string into comparable tuple.

    Args:
        version_str: Version string like "10.0.16299.551"

    Returns:
        Tuple of integers (major, minor, build, revision)
    """
    parts = version_str.split(".")
    result = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            result.append(0)
    # Pad to 4 elements
    while len(result) < 4:
        result.append(0)
    return tuple(result[:4])


def parse_file_path_info(file_path, symboldir):
    """
    Extract arch, filename, version, and sha256 from file path.

    Args:
        file_path: Full path to PE file
        symboldir: Base symbol directory

    Returns:
        Dict with 'arch', 'file', 'version', 'sha256' keys, or None if parsing fails

    Example:
        Input: "symbols/amd64/ntoskrnl.exe.10.0.16299.551/68d5867b.../ntoskrnl.exe"
        Output: {'arch': 'amd64', 'file': 'ntoskrnl.exe', 'version': '10.0.16299.551',
                 'sha256': '68d5867b...'}
    """
    # Normalize paths
    file_path = os.path.normpath(file_path)
    symboldir = os.path.normpath(symboldir)

    # Get relative path from symboldir
    try:
        rel_path = os.path.relpath(file_path, symboldir)
    except ValueError:
        return None

    # Split into components
    parts = rel_path.replace("\\", "/").split("/")
    if len(parts) < 4:
        return None

    arch = parts[0]
    version_dir = parts[1]  # e.g., "ntoskrnl.exe.10.0.16299.551"
    sha256 = parts[2]       # e.g., "68d5867b..."
    filename = parts[3]     # e.g., "ntoskrnl.exe"

    # Validate sha256 format (should be 64 hex characters)
    if len(sha256) != 64 or not all(c in '0123456789abcdef' for c in sha256.lower()):
        return None

    # Parse version from directory name
    # Format: filename.version (e.g., "ntoskrnl.exe.10.0.16299.551")
    if not version_dir.startswith(filename + "."):
        return None

    version = version_dir[len(filename) + 1:]  # Remove "filename." prefix

    return {
        "arch": arch,
        "file": filename,
        "version": version,
        "sha256": sha256.lower()
    }


def parse_pe_info(pe_path):
    """
    Parse PE file to extract hash, timestamp, and size.

    Args:
        pe_path: Path to PE file

    Returns:
        Dict with 'sha256', 'timestamp', 'size' keys, or None on failure
    """
    if not HAS_PEFILE:
        print("Error: pefile module is required for -syncfile mode")
        print("Install project dependencies with: uv sync")
        sys.exit(1)

    try:
        # Calculate SHA256
        with open(pe_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        # Parse PE
        pe = pefile.PE(pe_path, fast_load=True)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        size = pe.OPTIONAL_HEADER.SizeOfImage
        pe.close()

        return {
            "sha256": sha256,
            "timestamp": timestamp,
            "size": size
        }
    except Exception as e:
        print(f"  Warning: Failed to parse PE file: {e}")
        return None


def find_data_entry(root, arch, file_name, version, sha256):
    """
    Find a data entry matching arch, file, version, and hash.

    Args:
        root: XML root element
        arch: Architecture (e.g., "amd64")
        file_name: File name (e.g., "ntoskrnl.exe")
        version: Version string (e.g., "10.0.16299.551")
        sha256: SHA256 hash of the PE file (lowercase)

    Returns:
        Matching data element, or None if not found
    """
    for data_elem in root.findall("data"):
        if (data_elem.get("arch") == arch and
            data_elem.get("file") == file_name and
            data_elem.get("version") == version and
            data_elem.get("hash", "").lower() == sha256.lower()):
            return data_elem
    return None


def find_insert_position(root, arch, file_name, version):
    """
    Find the position to insert a new data entry.

    The new entry should be inserted after the entry with the closest
    smaller version that has the same arch and file.

    Args:
        root: XML root element
        arch: Architecture
        file_name: File name
        version: Version string

    Returns:
        Tuple of (index, after_elem) where:
        - index: Position to insert (for list.insert())
        - after_elem: Element to insert after (for reference), or None
    """
    target_ver = parse_version(version)
    data_elems = root.findall("data")

    best_idx = -1
    best_ver = None
    best_elem = None

    for i, data_elem in enumerate(data_elems):
        elem_arch = data_elem.get("arch")
        elem_file = data_elem.get("file")
        elem_ver_str = data_elem.get("version")

        if elem_arch == arch and elem_file == file_name:
            elem_ver = parse_version(elem_ver_str)
            # Find the largest version that is smaller than target
            if elem_ver < target_ver:
                if best_ver is None or elem_ver > best_ver:
                    best_ver = elem_ver
                    best_idx = i
                    best_elem = data_elem

    if best_idx >= 0:
        return best_idx + 1, best_elem
    else:
        # No smaller version found, find the first entry with same arch+file
        # to insert before, or insert at the end
        for i, data_elem in enumerate(data_elems):
            if data_elem.get("arch") == arch and data_elem.get("file") == file_name:
                return i, None
        # No matching arch+file at all, insert at the end of data elements
        return len(data_elems), None


def create_data_entry(root, arch, file_name, version, hash_val, timestamp, size, insert_idx):
    """
    Create and insert a new data entry at the specified position.

    Args:
        root: XML root element
        arch: Architecture
        file_name: File name
        version: Version string
        hash_val: SHA256 hash
        timestamp: TimeDateStamp from PE header
        size: SizeOfImage from PE header
        insert_idx: Index to insert at

    Returns:
        The newly created data element
    """
    data_elem = ET.Element("data")
    data_elem.set("arch", arch)
    data_elem.set("version", version)
    data_elem.set("file", file_name)
    data_elem.set("hash", hash_val)
    data_elem.set("timestamp", f"0x{timestamp:08x}")
    data_elem.set("size", f"0x{size:08x}")
    data_elem.text = "0"  # Fields ID = 0 (not yet resolved)

    # Insert at the correct position
    root.insert(insert_idx, data_elem)

    return data_elem


def scan_symbol_directory(symboldir):
    """
    Scan symbol directory for PE files.

    Args:
        symboldir: Base symbol directory

    Returns:
        List of PE file paths
    """
    pe_files = []
    pe_extensions = {".exe", ".dll", ".sys"}

    for arch_dir in os.listdir(symboldir):
        arch_path = os.path.join(symboldir, arch_dir)
        if not os.path.isdir(arch_path):
            continue

        for version_dir in os.listdir(arch_path):
            version_path = os.path.join(arch_path, version_dir)
            if not os.path.isdir(version_path):
                continue

            for sha256_dir in os.listdir(version_path):
                sha256_path = os.path.join(version_path, sha256_dir)
                if not os.path.isdir(sha256_path):
                    continue

                # Validate sha256 format (should be 64 hex characters)
                if len(sha256_dir) != 64 or not all(c in '0123456789abcdef' for c in sha256_dir.lower()):
                    continue

                for file_name in os.listdir(sha256_path):
                    file_ext = os.path.splitext(file_name)[1].lower()
                    if file_ext in pe_extensions:
                        pe_files.append(os.path.join(sha256_path, file_name))

    return pe_files


def syncfile_main(args, root):
    """
    Main function for -syncfile mode.

    Args:
        args: Parsed command line arguments
        root: XML root element

    Returns:
        Tuple of (added_count, skipped_count, failed_count)
    """
    symboldir = args.symboldir
    fast_mode = args.fast

    print(f"\nScanning symbol directory: {symboldir}")
    pe_files = scan_symbol_directory(symboldir)
    print(f"  Found {len(pe_files)} PE files")

    if not pe_files:
        print("No PE files found.")
        return 0, 0, 0

    added_count = 0
    skipped_count = 0
    failed_count = 0

    # Sort PE files for consistent ordering
    pe_files.sort()

    for i, pe_path in enumerate(pe_files):
        # Parse path info
        path_info = parse_file_path_info(pe_path, symboldir)
        if path_info is None:
            print(f"\n[{i+1}/{len(pe_files)}] {pe_path}")
            print(f"  Warning: Failed to parse path")
            failed_count += 1
            continue

        arch = path_info["arch"]
        file_name = path_info["file"]
        version = path_info["version"]
        sha256 = path_info["sha256"]

        # Check if entry exists (now using sha256 from path)
        existing = find_data_entry(root, arch, file_name, version, sha256)
        if existing is not None:
            skipped_count += 1
            continue

        # Entry doesn't exist, need to add it
        print(f"\n[{i+1}/{len(pe_files)}] {arch}/{file_name} v{version}")
        print(f"  Entry missing (sha256: {sha256[:16]}...), parsing PE...")

        # Parse PE to get timestamp/size (sha256 already known from path)
        pe_info = parse_pe_info(pe_path)
        if pe_info is None:
            print(f"  Failed to parse PE")
            failed_count += 1
            continue

        # Verify sha256 matches (optional sanity check)
        if pe_info["sha256"].lower() != sha256.lower():
            print(f"  Warning: SHA256 mismatch! Path says {sha256}, PE file has {pe_info['sha256']}")
            failed_count += 1
            continue

        # Find insert position
        insert_idx, after_elem = find_insert_position(root, arch, file_name, version)

        # Create new entry
        create_data_entry(
            root, arch, file_name, version,
            sha256, pe_info["timestamp"], pe_info["size"],
            insert_idx
        )

        if after_elem is not None:
            after_ver = after_elem.get("version")
            print(f"  Added new entry after version {after_ver}")
        else:
            print(f"  Added new entry")
        added_count += 1

    return added_count, skipped_count, failed_count


def save_xml_with_header(root, xml_path):
    """
    Save XML with proper header and formatting.

    Args:
        root: XML root element
        xml_path: Path to save the XML file
    """
    # Build the XML content manually to preserve formatting
    lines = [XML_HEADER.rstrip()]
    lines.append("<dyn>")

    # Add data elements first
    for data_elem in root.findall("data"):
        attrs = []
        for attr in ["arch", "version", "file", "hash", "timestamp", "size"]:
            val = data_elem.get(attr)
            if val is not None:
                attrs.append(f'{attr}="{val}"')
        attrs_str = " ".join(attrs)
        text = data_elem.text or ""
        lines.append(f"    <data {attrs_str}>{text}</data>")

    # Add fields elements
    for fields_elem in root.findall("fields"):
        fields_id = fields_elem.get("id")
        lines.append(f'    <fields id="{fields_id}">')

        for field_elem in fields_elem.findall("field"):
            value = field_elem.get("value")
            name = field_elem.get("name")
            lines.append(f'        <field value="{value}" name="{name}"/>')

        lines.append("    </fields>")

    lines.append("</dyn>")
    lines.append("")  # Final newline

    with open(xml_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    """Main entry point."""
    args = parse_args()

    xml_path = args.xml
    symboldir = args.symboldir
    outxml_path = args.outxml if args.outxml else args.xml  # Use outxml if provided, otherwise overwrite input

    # Validate paths
    if not os.path.exists(xml_path):
        print(f"Error: XML file not found: {xml_path}")
        sys.exit(1)

    if not os.path.exists(symboldir):
        print(f"Error: Symbol directory not found: {symboldir}")
        sys.exit(1)

    # Parse XML
    print(f"Parsing XML: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Handle syncfile mode
    if args.syncfile:
        print(f"Running in syncfile mode")
        if args.fast:
            print(f"  Fast mode: enabled")

        added, skipped, failed = syncfile_main(args, root)

        # Save XML
        print(f"\nSaving XML to: {outxml_path}")
        save_xml_with_header(root, outxml_path)

        # Summary
        print(f"\n{'='*50}")
        print(f"Summary: {added} added, {skipped} skipped, {failed} failed")

        if failed > 0:
            sys.exit(1)
        return

    # Handle fixnull mode
    if args.fixnull:
        print(f"Running in fixnull mode")

        yaml_path = args.yaml
        debug = args.debug

        if debug:
            print(f"  Debug mode: enabled")

        # Load YAML config
        print(f"Loading YAML config: {yaml_path}")
        file_list, symbols_list = load_yaml_config(yaml_path)
        print(f"  Files to process: {file_list}")
        print(f"  Symbols to extract: {len(symbols_list)}")

        success, skipped, failed = fixnull_main(args, root, file_list, symbols_list)

        # Save XML
        print(f"\nSaving XML to: {outxml_path}")
        save_xml_with_header(root, outxml_path)

        # Summary
        print(f"\n{'='*50}")
        print(f"Summary: {success} fixed, {skipped} skipped, {failed} failed")

        if failed > 0:
            sys.exit(1)
        return

    # Handle fixstruct mode
    if args.fixstruct:
        print(f"Running in fixstruct mode")

        yaml_path = args.yaml
        debug = args.debug

        if debug:
            print(f"  Debug mode: enabled")

        # Load YAML config
        print(f"Loading YAML config: {yaml_path}")
        file_list, symbols_list = load_yaml_config(yaml_path)
        print(f"  Files to process: {file_list}")
        print(f"  Symbols to extract: {len(symbols_list)}")

        success, skipped, unchanged = fixstruct_main(args, root, file_list, symbols_list)

        # Save XML
        print(f"\nSaving XML to: {outxml_path}")
        save_xml_with_header(root, outxml_path)

        # Summary
        print(f"\n{'='*50}")
        print(f"Summary: {success} fixed, {skipped} skipped, {unchanged} unchanged")

        return

    # Normal mode: update symbols from PDB
    yaml_path = args.yaml
    debug = args.debug
    sha256_filter = args.sha256
    pdbutil_path = args.pdbutil

    if pdbutil_path and not os.path.exists(pdbutil_path):
        print(f"Error: llvm-pdbutil not found at: {pdbutil_path}")
        sys.exit(1)

    # Load YAML config
    print(f"Loading YAML config: {yaml_path}")
    file_list, symbols_list = load_yaml_config(yaml_path)
    print(f"  Files to process: {file_list}")
    print(f"  Symbols to extract: {len(symbols_list)}")

    if sha256_filter:
        print(f"  SHA256 filter: {sha256_filter}")

    if pdbutil_path:
        print(f"  Using llvm-pdbutil: {pdbutil_path}")

    if debug:
        print(f"  Debug mode: enabled")

    # Parse XML
    print(f"\nParsing XML: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Collect existing fields
    existing_fields = collect_existing_fields(root)
    print(f"  Found {len(existing_fields)} existing fields sections")

    # Get all data entries for the specified files
    data_entries = get_all_entries_for_files(root, file_list, sha256_filter)
    print(f"  Found {len(data_entries)} data entries to process")

    if not data_entries:
        print("No data entries found for the specified files.")
        sys.exit(0)

    # Process each data entry
    referenced_ids = set()
    new_fields = {}  # id -> offsets
    pdb_cache = {}  # (arch, version, sha256) -> offsets

    success_count = 0
    skip_count = 0
    fail_count = 0

    for i, data_entry in enumerate(data_entries):
        arch = data_entry.get("arch")
        version = data_entry.get("version")
        file_name = data_entry.get("file")
        sha256 = data_entry.get("hash", "").lower()

        print(f"\n[{i+1}/{len(data_entries)}] Processing {file_name} {version} ({arch})")

        if not sha256:
            print(f"  Warning: No hash attribute in data entry, skipping")
            skip_count += 1
            continue

        # Check cache first
        cache_key = (arch, version, sha256)
        if cache_key in pdb_cache:
            offsets = pdb_cache[cache_key]
            print(f"  Using cached offsets")
        else:
            # Find and parse PDB
            pdb_path = get_pdb_path(symboldir, arch, version, sha256)

            if not os.path.exists(pdb_path):
                print(f"  PDB not found: {pdb_path}")
                skip_count += 1
                continue

            print(f"  Parsing PDB: {pdb_path}")
            offsets = parse_pdb_all_symbols(pdb_path, symbols_list, pdbutil_path, debug)

            if offsets is None:
                print(f"  Failed to extract all symbols")
                fail_count += 1
                sys.exit(1)  # Exit on symbol not found

            pdb_cache[cache_key] = offsets

        # Find matching fields ID
        fields_id = find_matching_fields_id(existing_fields, offsets)

        if fields_id is None:
            # Check new fields
            for new_id, new_offsets in new_fields.items():
                if new_offsets == offsets:
                    fields_id = new_id
                    break

        if fields_id is None:
            # Allocate new ID
            all_ids = set(existing_fields.keys()) | set(new_fields.keys())
            fields_id = allocate_new_fields_id(all_ids)
            new_fields[fields_id] = offsets
            print(f"  Created new fields id={fields_id}")
        else:
            print(f"  Using existing fields id={fields_id}")

        # Update data entry
        data_entry.text = str(fields_id)
        referenced_ids.add(fields_id)
        success_count += 1

    # Add new fields elements to the XML
    for fields_id, offsets in sorted(new_fields.items()):
        create_fields_element(root, fields_id, offsets, symbols_list)

    # Remove orphan fields (scans ALL data entries, not just processed ones)
    removed_count = remove_orphan_fields(root)
    if removed_count > 0:
        print(f"\nRemoved {removed_count} orphan fields sections")

    # Save XML
    print(f"\nSaving XML to: {outxml_path}")
    save_xml_with_header(root, outxml_path)

    # Summary
    print(f"\n{'='*50}")
    print(f"Summary: {success_count} updated, {skip_count} skipped, {fail_count} failed")
    print(f"Total fields sections: {len(referenced_ids)}")

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
