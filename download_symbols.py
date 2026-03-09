#!/usr/bin/env python3
"""
Symbol Download Script for KPH Dynamic Data

Downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server
based on entries in kphdyn.xml.

Usage:
    python download_symbols.py -xml=kphdyn.xml -symboldir=C:/Symbols [-arch=amd64] [-version=10.0.19041] [-symbol_server=URL]

    The XML path can also be set via KPHTOOLS_XML environment variable.
    If KPHTOOLS_XML is set, it takes precedence over -xml argument.

    The symboldir can also be set via KPHTOOLS_SYMBOLDIR environment variable.
    If KPHTOOLS_SYMBOLDIR is set, it takes precedence over -symboldir argument.

    The symbol_server can also be set via KPHTOOLS_SYMBOL_SERVER environment variable.
    If KPHTOOLS_SYMBOL_SERVER is set, it takes precedence over -symbol_server argument.

Requirements:
    pip install pefile requests
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import pefile
    import requests
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required packages: pip install pefile requests")
    sys.exit(1)


DEFAULT_SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"

# Global variable for symbol server URL (set by parse_args)
SYMBOL_SERVER_URL = DEFAULT_SYMBOL_SERVER_URL


def parse_args():
    """Parse command line arguments."""
    global SYMBOL_SERVER_URL
    
    parser = argparse.ArgumentParser(
        description="Download PE and PDB files from Microsoft Symbol Server"
    )
    parser.add_argument(
        "-xml",
        required=False,
        help="Path to the XML file (e.g., kphdyn.xml). Can be overridden by KPHTOOLS_XML environment variable."
    )
    parser.add_argument(
        "-symboldir",
        required=False,
        help="Directory to save downloaded symbols (can be overridden by KPHTOOLS_SYMBOLDIR environment variable)"
    )
    parser.add_argument(
        "-arch",
        default=None,
        help="Filter by architecture (e.g., amd64, arm64, x86)"
    )
    parser.add_argument(
        "-version",
        default=None,
        help="Filter by version prefix (e.g., 10.0.19041)"
    )
    parser.add_argument(
        "-symbol_server",
        default=DEFAULT_SYMBOL_SERVER_URL,
        help=f"Symbol server URL (default: {DEFAULT_SYMBOL_SERVER_URL}). Can be overridden by KPHTOOLS_SYMBOL_SERVER environment variable."
    )
    parser.add_argument(
        "-fast",
        action="store_true",
        help="Fast mode: skip entries if known PDB files already exist (ntoskrnl.exe -> ntkrnlmp.pdb/ntoskrnl.pdb, ntkrla57.exe -> ntkrla57.pdb)"
    )

    args = parser.parse_args()
    
    # Check XML environment variable first, then fallback to command line argument
    xml_path_env = os.getenv("KPHTOOLS_XML")
    if xml_path_env:
        args.xml = xml_path_env
    elif not args.xml:
        parser.error("Either KPHTOOLS_XML environment variable or -xml argument must be provided")
    
    if not args.xml:
        parser.error("-xml cannot be empty")
    
    # Check symbol directory environment variable first, then fallback to command line argument
    symbol_dir = os.getenv("KPHTOOLS_SYMBOLDIR")
    if symbol_dir:
        # Environment variable takes precedence
        args.symboldir = symbol_dir
    elif not args.symboldir:
        # Neither environment variable nor command line argument provided
        parser.error("Either KPHTOOLS_SYMBOLDIR environment variable or -symboldir argument must be provided")
    
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")
    
    # Check symbol server environment variable first, then fallback to command line argument
    symbol_server_env = os.getenv("KPHTOOLS_SYMBOL_SERVER")
    if symbol_server_env:
        # Environment variable takes precedence
        args.symbol_server = symbol_server_env
    
    # Set global symbol server URL
    SYMBOL_SERVER_URL = args.symbol_server.rstrip("/")
    
    return args


def parse_xml(xml_path, arch_filter=None, version_filter=None):
    """
    Parse the XML file and extract data entries.

    Args:
        xml_path: Path to the XML file
        arch_filter: Optional architecture filter
        version_filter: Optional version prefix filter

    Returns:
        List of dictionaries containing entry data
    """
    entries = []

    tree = ET.parse(xml_path)
    root = tree.getroot()

    for data_elem in root.findall("data"):
        arch = data_elem.get("arch")
        version = data_elem.get("version")
        file_name = data_elem.get("file")
        timestamp = data_elem.get("timestamp")
        size = data_elem.get("size")
        file_hash = data_elem.get("hash", "").lower()

        # Apply filters
        if arch_filter and arch != arch_filter:
            continue
        if version_filter and not version.startswith(version_filter):
            continue

        # Skip lxcore.sys
        if file_name and file_name.lower() == "lxcore.sys":
            continue

        # Skip entries without hash
        if not file_hash:
            print(f"  Warning: Skipping entry without hash: {file_name} {version} ({arch})")
            continue

        entries.append({
            "arch": arch,
            "version": version,
            "file": file_name,
            "timestamp": timestamp,
            "size": size,
            "hash": file_hash
        })

    return entries


def build_pe_url(entry):
    """
    Build the download URL for a PE file.
    
    URL format: https://msdl.microsoft.com/download/symbols/{file}/{timestamp}{size}/{file}
    - timestamp: uppercase hex without 0x prefix
    - size: uppercase hex without 0x prefix, no leading zeros
    
    Example:
        timestamp=0x57a1781c, size=0x00851000
        -> https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/57A1781C851000/ntoskrnl.exe
    """
    file_name = entry["file"]
    
    # Remove 0x prefix and convert to uppercase
    timestamp = entry["timestamp"].replace("0x", "").replace("0X", "").upper()
    # Remove 0x prefix, leading zeros, and convert to uppercase
    size_int = int(entry["size"], 16)
    size = f"{size_int:X}"
    
    # Build the key: timestamp + size (both uppercase, no 0x, no leading zeros on size)
    key = f"{timestamp}{size}"
    
    url = f"{SYMBOL_SERVER_URL}/{file_name}/{key}/{file_name}"
    return url


def download_file(url, target_path):
    """
    Download a file from URL to target path.

    Downloads the entire file content to memory first, then writes to disk
    to prevent corrupted files from incomplete downloads.

    Args:
        url: Download URL
        target_path: Local path to save the file

    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"  Downloading: {url}")
        response = requests.get(url, timeout=600)
        response.raise_for_status()

        # Cache content in memory first
        content = response.content

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        # Write to file only after full download completed
        with open(target_path, "wb") as f:
            f.write(content)

        print(f"  Saved to: {target_path}")
        return True

    except requests.exceptions.RequestException as e:
        print(f"  Download failed: {e}")
        return False


def download_pe(entry, symbol_dir):
    """
    Download a PE file based on the entry data.

    Args:
        entry: Dictionary with file info (file, version, timestamp, size, arch, hash)
        symbol_dir: Base directory to save symbols

    Returns:
        Path to the downloaded PE file, or None if failed
    """
    file_name = entry["file"]
    version = entry["version"]
    arch = entry["arch"]
    file_hash = entry["hash"]

    # Build target path: {symboldir}/{arch}/{file}.{version}/{hash}/{file}
    target_dir = os.path.join(symbol_dir, arch, f"{file_name}.{version}", file_hash)
    target_path = os.path.join(target_dir, file_name)

    # Skip if already exists
    if os.path.exists(target_path):
        print(f"  PE file already exists: {target_path}")
        return target_path

    url = build_pe_url(entry)

    if download_file(url, target_path):
        return target_path

    return None


def parse_pdb_info(pe_path):
    """
    Parse PDB information from a PE file.
    Uses pefile's built-in Signature_String for correct GUID format.
    
    Args:
        pe_path: Path to the PE file
        
    Returns:
        Dictionary with pdb_name, signature, or None if not found
    """
    try:
        pe = pefile.PE(pe_path, fast_load=False)
        
        # Look for debug directory
        if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            print(f"  No debug directory found in {pe_path}")
            pe.close()
            return None
        
        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            # Look for CodeView debug info (type 2)
            if debug_entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                # Get the CodeView data
                codeview_data = debug_entry.entry
                
                if codeview_data is not None and hasattr(codeview_data, "PdbFileName"):
                    # PDB 7.0 format (RSDS signature)
                    pdb_name = codeview_data.PdbFileName.strip(b'\x00').decode("utf-8")
                    # If an absolute path is embedded, use just the filename
                    pdb_name = pdb_name.split("\\")[-1]
                    
                    # Use pefile's built-in Signature_String (includes GUID + Age)
                    signature = codeview_data.Signature_String
                    
                    pe.close()
                    return {
                        "pdb_name": pdb_name,
                        "signature": signature
                    }
        
        pe.close()
        print(f"  No CodeView debug info found in {pe_path}")
        return None
        
    except Exception as e:
        print(f"  Error parsing PE file {pe_path}: {e}")
        return None


def build_pdb_url(pdb_info):
    """
    Build the download URL for a PDB file.
    
    URL format: https://msdl.microsoft.com/download/symbols/{pdb_name}/{signature}/{pdb_name}
    - signature: GUID + Age string from pefile's Signature_String
    
    Example:
        https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/4E2373352CFB49379C722CF0C7DC43501/ntkrnlmp.pdb
    """
    pdb_name = pdb_info["pdb_name"]
    signature = pdb_info["signature"]
    
    url = f"{SYMBOL_SERVER_URL}/{pdb_name}/{signature.upper()}/{pdb_name}"
    return url


def download_pdb(pdb_info, target_dir):
    """
    Download a PDB file based on parsed PDB info.
    
    Args:
        pdb_info: Dictionary with pdb_name, signature
        target_dir: Directory to save the PDB file
        
    Returns:
        True if successful, False otherwise
    """
    pdb_name = pdb_info["pdb_name"]
    target_path = os.path.join(target_dir, pdb_name)
    
    # Skip if already exists
    if os.path.exists(target_path):
        print(f"  PDB file already exists: {target_path}")
        return True
    
    url = build_pdb_url(pdb_info)
    return download_file(url, target_path)


def check_fast_skip(entry, symbol_dir):
    """
    Check if an entry can be skipped in fast mode.

    Args:
        entry: Dictionary with file info
        symbol_dir: Base directory to save symbols

    Returns:
        True if the entry should be skipped, False otherwise
    """
    file_name = entry["file"].lower()
    version = entry["version"]
    arch = entry["arch"]
    file_hash = entry["hash"]

    target_dir = os.path.join(symbol_dir, arch, f"{entry['file']}.{version}", file_hash)

    if file_name == "ntoskrnl.exe":
        # Check for ntkrnlmp.pdb or ntoskrnl.pdb
        if os.path.exists(os.path.join(target_dir, "ntkrnlmp.pdb")):
            return True
        if os.path.exists(os.path.join(target_dir, "ntoskrnl.pdb")):
            return True
    elif file_name == "ntkrla57.exe":
        # Check for ntkrla57.pdb
        if os.path.exists(os.path.join(target_dir, "ntkrla57.pdb")):
            return True

    return False


def process_entry(entry, symbol_dir, fast_mode=False):
    """
    Process a single entry: download PE, parse PDB info, download PDB.

    Args:
        entry: Dictionary with file info
        symbol_dir: Base directory to save symbols
        fast_mode: If True, skip entries where known PDB files already exist

    Returns:
        True if successful, False otherwise
    """
    file_name = entry["file"]
    version = entry["version"]
    arch = entry["arch"]
    file_hash = entry["hash"]

    print(f"\nProcessing: {file_name} {version} ({arch}) [{file_hash[:16]}...]")

    # Fast mode: skip if known PDB files already exist
    if fast_mode and check_fast_skip(entry, symbol_dir):
        print(f"  [Fast mode] PDB already exists, skipping")
        return True

    # Step 1: Download PE file
    pe_path = download_pe(entry, symbol_dir)
    if not pe_path:
        print(f"  Failed to download PE file")
        return False

    # Step 2: Parse PDB info from PE
    pdb_info = parse_pdb_info(pe_path)
    if not pdb_info:
        print(f"  Failed to parse PDB info from PE")
        return False

    print(f"  PDB: {pdb_info['pdb_name']} (Signature: {pdb_info['signature']})")

    # Step 3: Download PDB file to same directory as PE
    target_dir = os.path.dirname(pe_path)
    if not download_pdb(pdb_info, target_dir):
        print(f"  Failed to download PDB file")
        return False

    print(f"  Success!")
    return True


def main():
    """Main entry point."""
    args = parse_args()

    xml_path = args.xml
    symbol_dir = args.symboldir
    arch_filter = args.arch
    version_filter = args.version
    fast_mode = args.fast

    # Validate XML file exists
    if not os.path.exists(xml_path):
        print(f"Error: XML file not found: {xml_path}")
        sys.exit(1)

    # Create symbol directory if needed
    os.makedirs(symbol_dir, exist_ok=True)

    print(f"XML file: {xml_path}")
    print(f"Symbol directory: {symbol_dir}")
    if arch_filter:
        print(f"Architecture filter: {arch_filter}")
    if version_filter:
        print(f"Version filter: {version_filter}")
    if fast_mode:
        print(f"Fast mode: enabled")

    # Parse XML
    print("\nParsing XML...")
    entries = parse_xml(xml_path, arch_filter, version_filter)
    print(f"Found {len(entries)} entries to process")

    if not entries:
        print("No entries match the specified filters.")
        sys.exit(0)

    # Process each entry
    success_count = 0
    fail_count = 0

    for entry in entries:
        if process_entry(entry, symbol_dir, fast_mode):
            success_count += 1
        else:
            fail_count += 1
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Completed: {success_count} successful, {fail_count} failed")
    
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

