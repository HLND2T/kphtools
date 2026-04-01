#!/usr/bin/env python3
"""
Reverse Symbols Script for KPH Dynamic Data

Scans symbol directory for PE files missing PDB, uses IDA and LLM to recover symbols
by comparing with similar versions that have PDB files.

Directory Structure:
    {symboldir}/{arch}/{filename}.{version}/{sha256}/{files}
    Example: symbols/amd64/ntoskrnl.exe.10.0.16299.551/68d5867b.../ntoskrnl.exe

Usage:
    uv run python reverse_symbols.py -symboldir=C:/Symbols -reverse=PsSetCreateProcessNotifyRoutine -provider=openai -api_key="YOUR_KEY"

    # With custom model and API base
    uv run python reverse_symbols.py -symboldir=C:/Symbols -reverse=PsSetCreateProcessNotifyRoutine \
        -provider=openai -api_key="YOUR_KEY" -model="deepseek-chat" -api_base="https://api.deepseek.com"

Environment Variables:
    KPHTOOLS_SYMBOLDIR     - Symbol directory path
    OPENAI_API_KEY         - OpenAI API key
    OPENAI_API_BASE        - OpenAI API base URL (optional)
    ANTHROPIC_API_KEY      - Anthropic API key
    ANTHROPIC_API_BASE     - Anthropic API base URL (optional)
    IDA64_PATH             - Path to ida64.exe

Arguments:
    -symboldir     Symbol directory containing PE files (required)
    -reverse       Function name to reverse engineer (required)
    -provider      LLM provider: openai or anthropic (default: openai)
    -api_key       API key (or use environment variable)
    -model         LLM model name (optional)
    -api_base      API base URL (optional)
    -ida           Path to ida64.exe (optional, searches PATH by default)
    -debug         Enable debug output

Workflow:
    For each PE file missing PDB:
    1. Find the closest lower version with PDB as reference
    2. Run IDA disasm on target PE (missing PDB)
    3. Run IDA disasm on reference PE (with PDB)
    4. Call generate_mapping.py to create symbol mappings via LLM
    5. Run IDA symbol_remap to apply mappings

Requirements:
    - IDA Pro with ida64.exe
    - Run `uv sync` in the repository root to install Python dependencies from pyproject.toml
"""

import argparse
import os
import shutil
import subprocess
import sys


# Supported LLM providers
PROVIDERS = ["openai", "anthropic"]


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Reverse engineer symbols for PE files missing PDB using IDA and LLM"
    )
    parser.add_argument(
        "-symboldir",
        required=False,
        help="Directory containing symbol files (can be set via KPHTOOLS_SYMBOLDIR)"
    )
    parser.add_argument(
        "-reverse",
        required=True,
        help="Function name to reverse engineer (e.g., PsSetCreateProcessNotifyRoutine)"
    )
    parser.add_argument(
        "-provider",
        choices=PROVIDERS,
        default="openai",
        help="LLM provider: openai or anthropic (default: openai)"
    )
    parser.add_argument(
        "-api_key",
        help="API key (or use OPENAI_API_KEY/ANTHROPIC_API_KEY environment variable)"
    )
    parser.add_argument(
        "-model",
        help="LLM model name (optional)"
    )
    parser.add_argument(
        "-api_base",
        help="API base URL (or use OPENAI_API_BASE/ANTHROPIC_API_BASE environment variable)"
    )
    parser.add_argument(
        "-ida",
        help="Path to ida64.exe (default: search in PATH or IDA64_PATH environment variable)"
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug output"
    )
    parser.add_argument(
        "-signature",
        help="Signature pattern for function search (e.g., FB488D05????????4989)"
    )
    parser.add_argument(
        "-no_procedure",
        action="store_true",
        help="Skip pseudocode output in IDA disasm"
    )
    parser.add_argument(
        "-disasm_lines",
        type=int,
        help="Limit disassembly output to N lines"
    )
    parser.add_argument(
        "-template",
        help="Custom PROMPT_TEMPLATE file path for generate_mapping.py"
    )

    args = parser.parse_args()

    # Check symboldir: environment variable takes precedence
    symbol_dir = os.getenv("KPHTOOLS_SYMBOLDIR")
    if symbol_dir:
        args.symboldir = symbol_dir
    elif not args.symboldir:
        parser.error("Either KPHTOOLS_SYMBOLDIR environment variable or -symboldir argument must be provided")

    if not args.symboldir:
        parser.error("-symboldir cannot be empty")

    return args


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
    Extract arch, filename, version, sha256 from file path.

    Args:
        file_path: Full path to PE file
        symboldir: Base symbol directory

    Returns:
        Dict with 'arch', 'file', 'version', 'sha256' keys, or None if parsing fails

    Example:
        Input: "symbols/amd64/ntoskrnl.exe.10.0.16299.551/68d5867b.../ntoskrnl.exe"
        Output: {'arch': 'amd64', 'file': 'ntoskrnl.exe', 'version': '10.0.16299.551', 'sha256': '68d5867b...'}
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
    sha256 = parts[2]       # e.g., "68d5867b5e66fce486c863c11cf69020658cadbbacbbda1e167766f236fefe78"
    filename = parts[3]      # e.g., "ntoskrnl.exe"

    # Validate sha256 format (64 lowercase hex characters)
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


def check_pdb_exists(pe_dir):
    """
    Check if PDB file exists in the directory.

    Args:
        pe_dir: Directory to check

    Returns:
        True if any PDB file exists, False otherwise
    """
    pdb_extensions = [".pdb"]
    try:
        for filename in os.listdir(pe_dir):
            if os.path.splitext(filename)[1].lower() in pdb_extensions:
                return True
    except OSError:
        pass
    return False


def scan_symbol_directory(symboldir):
    """
    Scan symbol directory for PE files.

    Args:
        symboldir: Base symbol directory

    Returns:
        List of PE file paths

    Directory structure: {symboldir}/{arch}/{filename}.{version}/{sha256}/{filename}
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

                # Validate sha256 format (64 hex characters)
                if len(sha256_dir) != 64 or not all(c in '0123456789abcdef' for c in sha256_dir.lower()):
                    continue

                for file_name in os.listdir(sha256_path):
                    file_ext = os.path.splitext(file_name)[1].lower()
                    if file_ext in pe_extensions:
                        pe_files.append(os.path.join(sha256_path, file_name))

    return pe_files


def build_pe_index(pe_files, symboldir):
    """
    Build PE index grouped by (arch, filename).

    Args:
        pe_files: List of PE file paths
        symboldir: Base symbol directory

    Returns:
        Dict mapping (arch, filename) to list of (version_tuple, pe_path, has_pdb, sha256)
    """
    index = {}

    for pe_path in pe_files:
        info = parse_file_path_info(pe_path, symboldir)
        if info is None:
            continue

        arch = info["arch"]
        filename = info["file"]
        version = info["version"]
        sha256 = info["sha256"]
        version_tuple = parse_version(version)

        pe_dir = os.path.dirname(pe_path)
        has_pdb = check_pdb_exists(pe_dir)

        key = (arch, filename)
        if key not in index:
            index[key] = []

        index[key].append({
            "version": version,
            "version_tuple": version_tuple,
            "path": pe_path,
            "has_pdb": has_pdb,
            "arch": arch,
            "file": filename,
            "sha256": sha256
        })

    # Sort each group by version
    for key in index:
        index[key].sort(key=lambda x: x["version_tuple"])

    return index


def find_reference_pe(pe_index, arch, filename, target_version_tuple):
    """
    Find the closest lower version with PDB.

    Args:
        pe_index: PE index from build_pe_index()
        arch: Architecture
        filename: File name
        target_version_tuple: Target version as tuple

    Returns:
        Dict with PE info, or None if no suitable reference found
    """
    key = (arch, filename)
    if key not in pe_index:
        return None

    candidates = []
    for pe_info in pe_index[key]:
        # Only consider versions with PDB that are lower than target
        if pe_info["has_pdb"] and pe_info["version_tuple"] < target_version_tuple:
            candidates.append(pe_info)

    if not candidates:
        return None

    # Return the highest version among candidates (closest to target)
    return max(candidates, key=lambda x: x["version_tuple"])


def get_ida_path(ida_arg):
    """
    Get path to ida64.exe.

    Priority:
    1. Command line argument -ida
    2. Environment variable IDA64_PATH
    3. System PATH

    Args:
        ida_arg: Path specified via command line

    Returns:
        Full path to ida64.exe

    Raises:
        SystemExit: If ida64.exe not found
    """
    # 1. Command line argument
    if ida_arg:
        if os.path.exists(ida_arg):
            return ida_arg
        print(f"Error: Specified IDA path does not exist: {ida_arg}")
        sys.exit(1)

    # 2. Environment variable
    env_path = os.environ.get("IDA64_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    # 3. System PATH
    ida_in_path = shutil.which("ida64.exe") or shutil.which("ida64")
    if ida_in_path:
        return ida_in_path

    print("Error: ida64.exe not found")
    print("Please specify IDA path using one of the following methods:")
    print("  1. Use -ida argument: -ida=\"C:\\IDA\\ida64.exe\"")
    print("  2. Set environment variable: set IDA64_PATH=C:\\IDA\\ida64.exe")
    print("  3. Add IDA directory to system PATH")
    sys.exit(1)


def get_api_config(provider, api_key_arg, api_base_arg):
    """
    Get API configuration.

    Priority:
    1. Command line arguments
    2. Environment variables

    Args:
        provider: API provider (openai or anthropic)
        api_key_arg: API key from command line
        api_base_arg: API base URL from command line

    Returns:
        (api_key, api_base) tuple

    Raises:
        SystemExit: If API key not configured
    """
    if provider == "openai":
        env_key = "OPENAI_API_KEY"
        env_base = "OPENAI_API_BASE"
    else:  # anthropic
        env_key = "ANTHROPIC_API_KEY"
        env_base = "ANTHROPIC_API_BASE"

    # API Key
    api_key = api_key_arg or os.environ.get(env_key)
    if not api_key:
        print(f"Error: {provider.upper()} API Key not configured")
        print("Please specify using one of the following methods:")
        print(f"  1. Use -api_key argument: -api_key=\"your-key\"")
        print(f"  2. Set environment variable: set {env_key}=your-key")
        sys.exit(1)

    # API Base (optional)
    api_base = api_base_arg or os.environ.get(env_base)

    return api_key, api_base


def get_yaml_path(pe_path, func_name):
    """
    Get YAML output file path for a PE file.

    Args:
        pe_path: PE file path
        func_name: Function name

    Returns:
        YAML file path
    """
    pe_dir = os.path.dirname(pe_path)
    return os.path.join(pe_dir, f"{func_name}.yaml")


def run_ida_disasm(ida_path, func_name, pe_path, signature=None, no_procedure=False, disasm_lines=None, debug=False):
    """
    Run IDA to generate function disassembly.

    Args:
        ida_path: Path to ida64.exe
        func_name: Function name
        pe_path: PE file path
        signature: Signature pattern for function search (optional)
        no_procedure: Skip pseudocode output (optional)
        disasm_lines: Limit disassembly output lines (optional)
        debug: Enable debug output

    Returns:
        True if successful, False otherwise
    """
    # Get ida.py script path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ida_script = os.path.join(script_dir, "ida", "ida.py")

    if not os.path.exists(ida_script):
        print(f"  Error: IDA script not found: {ida_script}")
        return False

    yaml_path = get_yaml_path(pe_path, func_name)

    # Check if output already exists
    if os.path.exists(yaml_path):
        print(f"  Skipping IDA disasm (output exists): {yaml_path}")
        return True

    # Build IDA command
    script_arg = f'{ida_script} --mode disasm --func {func_name}'
    if signature:
        script_arg += f' --signature {signature}'
    if no_procedure:
        script_arg += ' --no_procedure'
    if disasm_lines:
        script_arg += f' --disasm_lines {disasm_lines}'
    cmd = [
        ida_path,
        "-A",  # Autonomous mode
        "-P",  # Pack database and save
        f"-S{script_arg}",
        pe_path
    ]

    if debug:
        print(f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        if debug:
            if result.stdout:
                print(f"  IDA stdout: {result.stdout[:500]}")
            if result.stderr:
                print(f"  IDA stderr: {result.stderr[:500]}")

        # Check if output file was generated
        if not os.path.exists(yaml_path):
            print(f"  Error: IDA failed to generate output: {yaml_path}")
            if result.returncode != 0:
                print(f"  Return code: {result.returncode}")
            return False

        return True

    except subprocess.TimeoutExpired:
        print(f"  Error: IDA execution timeout (10 minutes)")
        return False
    except Exception as e:
        print(f"  Error: IDA execution failed: {e}")
        return False


def run_ida_symbol_remap(ida_path, pe_path, debug=False):
    """
    Run IDA to apply symbol remapping.

    Args:
        ida_path: Path to ida64.exe
        pe_path: PE file path
        debug: Enable debug output

    Returns:
        True if successful, False otherwise
    """
    # Get ida.py script path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ida_script = os.path.join(script_dir, "ida", "ida.py")

    if not os.path.exists(ida_script):
        print(f"  Error: IDA script not found: {ida_script}")
        return False

    # Check if SymbolMapping.yaml exists
    pe_dir = os.path.dirname(pe_path)
    mapping_file = os.path.join(pe_dir, "SymbolMapping.yaml")
    if not os.path.exists(mapping_file):
        print(f"  Skipping symbol remap (no mapping file)")
        return True

    # Build IDA command
    script_arg = f'{ida_script} --mode symbol_remap'
    cmd = [
        ida_path,
        "-A",  # Autonomous mode
        "-P",  # Pack database and save
        f"-S{script_arg}",
        pe_path
    ]

    if debug:
        print(f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        if debug:
            if result.stdout:
                print(f"  IDA stdout: {result.stdout[:500]}")
            if result.stderr:
                print(f"  IDA stderr: {result.stderr[:500]}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"  Error: IDA execution timeout (10 minutes)")
        return False
    except Exception as e:
        print(f"  Error: IDA execution failed: {e}")
        return False


def run_generate_mapping(func_name, reference_pe, reverse_pe, provider, api_key, api_base, model, template=None, debug=False):
    """
    Run generate_mapping.py to create symbol mappings.

    Args:
        func_name: Function name
        reference_pe: Reference PE path (with PDB)
        reverse_pe: Target PE path (missing PDB)
        provider: LLM provider
        api_key: API key
        api_base: API base URL (optional)
        model: Model name (optional)
        template: Custom PROMPT_TEMPLATE file path (optional)
        debug: Enable debug output

    Returns:
        True if successful, False otherwise
    """
    # Get generate_mapping.py path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mapping_script = os.path.join(script_dir, "ida", "generate_mapping.py")

    if not os.path.exists(mapping_script):
        print(f"  Error: generate_mapping.py not found: {mapping_script}")
        return False

    # Build command
    cmd = [
        sys.executable,
        mapping_script,
        f"-func={func_name}",
        f"-reference={reference_pe}",
        f"-reverse={reverse_pe}",
        f"-provider={provider}",
        f"-api_key={api_key}"
    ]

    if model:
        cmd.append(f"-model={model}")
    if api_base:
        cmd.append(f"-api_base={api_base}")
    if template:
        cmd.append(f"-template={template}")
    if debug:
        cmd.append("-debug")

    if debug:
        # Don't print API key in debug output
        safe_cmd = [c if not c.startswith("-api_key=") else "-api_key=***" for c in cmd]
        print(f"  Command: {' '.join(safe_cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if debug or result.returncode != 0:
            if result.stdout:
                print(f"  generate_mapping stdout:\n{result.stdout}")
            if result.stderr:
                print(f"  generate_mapping stderr:\n{result.stderr}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"  Error: generate_mapping.py execution timeout (5 minutes)")
        return False
    except Exception as e:
        print(f"  Error: generate_mapping.py execution failed: {e}")
        return False


def process_pe(pe_info, reference_info, func_name, ida_path, provider, api_key, api_base, model,
               signature=None, no_procedure=False, disasm_lines=None, template=None, debug=False):
    """
    Process a single PE file (complete workflow).

    Args:
        pe_info: Target PE info dict
        reference_info: Reference PE info dict
        func_name: Function name to reverse
        ida_path: Path to ida64.exe
        provider: LLM provider
        api_key: API key
        api_base: API base URL (optional)
        model: Model name (optional)
        signature: Signature pattern for function search (optional)
        no_procedure: Skip pseudocode output (optional)
        disasm_lines: Limit disassembly output lines (optional)
        template: Custom PROMPT_TEMPLATE file path (optional)
        debug: Enable debug output

    Returns:
        True if successful, False otherwise
    """
    target_pe = pe_info["path"]
    reference_pe = reference_info["path"]

    # Step 1: Run IDA disasm on target PE
    print(f"  Step 1: Running IDA disasm on target PE...")
    if not run_ida_disasm(ida_path, func_name, target_pe, signature, no_procedure, disasm_lines, debug):
        print(f"  Step 1 failed!")
        return False

    # Step 2: Run IDA disasm on reference PE
    print(f"  Step 2: Running IDA disasm on reference PE...")
    if not run_ida_disasm(ida_path, func_name, reference_pe, signature, no_procedure, disasm_lines, debug):
        print(f"  Step 2 failed!")
        return False

    # Step 3: Generate symbol mapping via LLM
    print(f"  Step 3: Generating symbol mapping via LLM...")
    if not run_generate_mapping(func_name, reference_pe, target_pe, provider, api_key, api_base, model, template, debug):
        print(f"  Step 3 failed!")
        return False

    # Step 4: Apply symbol remap in IDA
    print(f"  Step 4: Applying symbol remap in IDA...")
    if not run_ida_symbol_remap(ida_path, target_pe, debug):
        print(f"  Step 4 failed!")
        return False

    print(f"  Done!")
    return True


def main():
    """Main entry point."""
    args = parse_args()

    symboldir = args.symboldir
    func_name = args.reverse
    provider = args.provider
    debug = args.debug
    signature = args.signature
    no_procedure = args.no_procedure
    disasm_lines = args.disasm_lines
    template = args.template

    # Validate symbol directory
    if not os.path.exists(symboldir):
        print(f"Error: Symbol directory not found: {symboldir}")
        sys.exit(1)

    # Get IDA path
    ida_path = get_ida_path(args.ida)

    # Get API configuration
    api_key, api_base = get_api_config(provider, args.api_key, args.api_base)
    model = args.model

    # Print configuration
    print(f"Symbol directory: {symboldir}")
    print(f"Function: {func_name}")
    print(f"IDA64 path: {ida_path}")
    print(f"API provider: {provider}")
    if model:
        print(f"Model: {model}")
    if api_base:
        print(f"API base: {api_base}")
    if debug:
        print(f"Debug mode: enabled")
    if signature:
        print(f"Signature: {signature}")
    if no_procedure:
        print(f"No procedure: enabled")
    if disasm_lines:
        print(f"Disasm lines: {disasm_lines}")
    if template:
        print(f"Template: {template}")

    # Scan symbol directory
    print(f"\nScanning symbol directory...")
    pe_files = scan_symbol_directory(symboldir)
    print(f"  Found {len(pe_files)} PE files")

    if not pe_files:
        print("No PE files found.")
        sys.exit(0)

    # Build PE index
    pe_index = build_pe_index(pe_files, symboldir)

    # Find PEs missing PDB
    missing_pdb = []
    with_pdb = []

    for key, pe_list in pe_index.items():
        for pe_info in pe_list:
            if pe_info["has_pdb"]:
                with_pdb.append(pe_info)
            else:
                missing_pdb.append(pe_info)

    print(f"  Missing PDB: {len(missing_pdb)} files")
    print(f"  With PDB: {len(with_pdb)} files")

    if not missing_pdb:
        print("\nNo PE files missing PDB. Nothing to process.")
        sys.exit(0)

    # Process each PE missing PDB
    success_count = 0
    fail_count = 0
    skip_count = 0

    for i, pe_info in enumerate(missing_pdb):
        arch = pe_info["arch"]
        filename = pe_info["file"]
        version = pe_info["version"]
        version_tuple = pe_info["version_tuple"]
        sha256 = pe_info["sha256"]

        print(f"\n[{i+1}/{len(missing_pdb)}] Processing {arch}/{filename} v{version} [{sha256[:16]}...]")

        # Find reference PE
        reference = find_reference_pe(pe_index, arch, filename, version_tuple)
        if reference is None:
            print(f"  No suitable reference version found (need lower version with PDB)")
            skip_count += 1
            continue

        print(f"  Reference version: {reference['version']} [{reference['sha256'][:16]}...]")

        # Process this PE
        if process_pe(pe_info, reference, func_name, ida_path, provider, api_key, api_base, model,
                      signature, no_procedure, disasm_lines, template, debug):
            success_count += 1
        else:
            fail_count += 1

    # Summary
    print(f"\n{'='*50}")
    print(f"Summary: {len(missing_pdb)} total, {success_count} success, {fail_count} failed, {skip_count} skipped")

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
