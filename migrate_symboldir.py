#!/usr/bin/env python3
"""
Symbol Directory Migration Script

Migrates files from {symboldir}/{arch}/{filename}.{fileversion}/
to {symboldir}/{arch}/{filename}.{fileversion}/{sha256}/

This avoids conflicts when PE files have the same arch, filename, and fileversion
but different SHA256 hashes.

Usage:
    uv run python migrate_symboldir.py -symboldir=D:/kphtools/symbols

Example:
    Before:
        D:/symbols/amd64/ntoskrnl.exe.10.0.28000.1362/ntoskrnl.exe
        D:/symbols/amd64/ntoskrnl.exe.10.0.28000.1362/ntkrnlmp.pdb

    After:
        D:/symbols/amd64/ntoskrnl.exe.10.0.28000.1362/68d5867b5e66fce.../ntoskrnl.exe
        D:/symbols/amd64/ntoskrnl.exe.10.0.28000.1362/68d5867b5e66fce.../ntkrnlmp.pdb
"""

import os
import sys
import argparse
import hashlib
import shutil


PE_EXTENSIONS = {".exe", ".dll", ".sys"}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Migrates symbol directory structure to use SHA256 subdirectories"
    )
    parser.add_argument(
        "-symboldir",
        required=True,
        help="Directory containing symbol files"
    )

    args = parser.parse_args()

    if not args.symboldir:
        parser.error("-symboldir cannot be empty")

    return args


def calculate_sha256(file_path):
    """
    Calculate SHA256 hash of a file.

    Args:
        file_path: Path to the file

    Returns:
        Lowercase hex string of SHA256 hash
    """
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def find_pe_file(directory):
    """
    Find PE file in directory.

    Args:
        directory: Directory to search

    Returns:
        Path to first PE file found, or None if not found
    """
    try:
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):
                file_ext = os.path.splitext(file_name)[1].lower()
                if file_ext in PE_EXTENSIONS:
                    return file_path
    except OSError:
        pass
    return None


def is_already_migrated(version_dir):
    """
    Check if directory has already been migrated.

    A directory is considered migrated if:
    - It contains no PE files directly
    - It contains subdirectories that contain PE files

    Args:
        version_dir: Path to the version directory

    Returns:
        True if already migrated, False otherwise
    """
    # Check for PE files directly in version_dir
    pe_file = find_pe_file(version_dir)
    if pe_file is not None:
        # Found PE file directly in version_dir, not migrated
        return False

    # Check if there are subdirectories with PE files
    try:
        for item in os.listdir(version_dir):
            item_path = os.path.join(version_dir, item)
            if os.path.isdir(item_path):
                if find_pe_file(item_path) is not None:
                    # Found PE file in subdirectory, already migrated
                    return True
    except OSError:
        pass

    # No PE files found anywhere, treat as not migrated (empty or invalid)
    return False


def migrate_version_directory(version_dir):
    """
    Migrate a single version directory.

    Args:
        version_dir: Path to the version directory

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Find PE file
    pe_file = find_pe_file(version_dir)
    if pe_file is None:
        return (False, "No PE file found")

    # Calculate SHA256
    try:
        sha256 = calculate_sha256(pe_file)
    except OSError as e:
        return (False, f"Failed to calculate SHA256: {e}")

    # Create target directory
    target_dir = os.path.join(version_dir, sha256)

    if os.path.exists(target_dir):
        return (False, f"Target directory already exists: {sha256}")

    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as e:
        return (False, f"Failed to create directory: {e}")

    # Move all files to target directory
    try:
        for item in os.listdir(version_dir):
            item_path = os.path.join(version_dir, item)
            # Skip the newly created target directory
            if item_path == target_dir:
                continue
            # Skip subdirectories (shouldn't exist in old structure, but be safe)
            if os.path.isdir(item_path):
                continue
            # Move file
            shutil.move(item_path, os.path.join(target_dir, item))
    except OSError as e:
        return (False, f"Failed to move files: {e}")

    return (True, sha256)


def scan_and_migrate(symboldir):
    """
    Scan and migrate entire symbol directory.

    Args:
        symboldir: Base symbol directory path

    Returns:
        Tuple of (migrated_count, skipped_count, failed_count)
    """
    migrated_count = 0
    skipped_count = 0
    failed_count = 0

    # Collect all version directories first
    version_dirs = []

    try:
        arch_dirs = os.listdir(symboldir)
    except OSError as e:
        print(f"Error: Cannot read symbol directory: {e}")
        return (0, 0, 1)

    for arch_dir in arch_dirs:
        arch_path = os.path.join(symboldir, arch_dir)
        if not os.path.isdir(arch_path):
            continue

        try:
            version_entries = os.listdir(arch_path)
        except OSError:
            continue

        for version_dir in version_entries:
            version_path = os.path.join(arch_path, version_dir)
            if not os.path.isdir(version_path):
                continue
            version_dirs.append((arch_dir, version_dir, version_path))

    print(f"Found {len(version_dirs)} version directories")

    # Process each version directory
    for i, (arch, version, version_path) in enumerate(version_dirs):
        # Check if already migrated
        if is_already_migrated(version_path):
            skipped_count += 1
            continue

        # Migrate
        success, message = migrate_version_directory(version_path)

        if success:
            print(f"[{i+1}/{len(version_dirs)}] {arch}/{version} -> {message}")
            migrated_count += 1
        else:
            if message != "No PE file found":
                print(f"[{i+1}/{len(version_dirs)}] {arch}/{version} FAILED: {message}")
                failed_count += 1
            else:
                skipped_count += 1

    return (migrated_count, skipped_count, failed_count)


def main():
    """Main entry point."""
    args = parse_args()

    symboldir = args.symboldir

    # Validate symbol directory
    if not os.path.exists(symboldir):
        print(f"Error: Symbol directory not found: {symboldir}")
        sys.exit(1)

    if not os.path.isdir(symboldir):
        print(f"Error: Not a directory: {symboldir}")
        sys.exit(1)

    print(f"Symbol directory: {symboldir}")
    print(f"Scanning and migrating...")

    migrated, skipped, failed = scan_and_migrate(symboldir)

    # Summary
    print(f"\n{'='*50}")
    print(f"Summary: {migrated} migrated, {skipped} skipped, {failed} failed")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
