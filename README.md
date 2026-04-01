# Toolkits for KPH Dynamic Data

Several scripts are included to generate offsets for [SystemInformer](https://github.com/winsiderss/systeminformer)'s [kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml), adding your own "struct_offset", or even "func_offset" to it (can be customized via `kphdyn.yaml`).

## Get kphdyn.xml

```bash
wget https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
```

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
```

```powershell
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.xml"
```

## Requirements

Requirements are managed by `pyproject.toml`:

```bash
uv sync
```

System dependencies (for signify library, required on Linux):
- **Ubuntu/Debian:**
  ```bash
  sudo apt-get update
  sudo apt-get install -y libssl-dev
  ```
- **CentOS/RHEL/Fedora:**
  ```bash
  sudo yum install -y openssl-devel
  # or on newer versions:
  sudo dnf install -y openssl-devel
  ```

- Fix oscrypto issue - `Error detecting the version of libcrypto` : `uv pip install -I "git+https://github.com/wbond/oscrypto.git"`

## Download PE & Symbol listed

Downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server
based on entries from `kphdyn.xml`

### Usage, [] for optional

```bash
uv run python download_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https//msdl.microsoft.com/download/symbols"]
```

### Possible environment variables

```bash
export KPHTOOLS_XML="path/to/kphdyn.xml"
export KPHTOOLS_SYMBOLDIR="C:/Symbols"
```

```bash
set KPHTOOLS_XML=path/to/kphdyn.xml
set KPHTOOLS_SYMBOLDIR=C:/Symbols
```

### Expected downloads

```
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntkrnlmp.pdb
...others
```

Where `{sha256}` is the lowercase SHA256 hash of the PE file (e.g., `68d5867b5e66fce486c863c11cf69020658cadbbacbbda1e167766f236fefe78`).

## Update symbols in kphdyn.xml

Updates field offsets in `kphdyn.xml` by parsing PDB files using `llvm-pdbutil`.

Also supports **syncfile mode** to scan symbol directory and add missing entries to XML.

### Requirements

- `llvm-pdbutil` must be available in system PATH (part of LLVM tools)

### Usage

**Normal mode** - Update symbol offsets from PDB files:

```bash
uv run python update_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" -yaml="path/to/kphdyn.yaml"
```

**Syncfile mode** - Scan symbol directory and add missing entries:

```bash
uv run python update_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" -syncfile
```

**Fixnull mode** - Fix null entries (fields ID = 0) using SymbolMapping.yaml:

```bash
uv run python update_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" -fixnull
```

**Fixstruct mode** - Fix struct_offset fallback values from closest valid version:

```bash
uv run python update_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" -fixstruct
```

### Optional Arguments

- `-sha256`: Only process entries with this SHA256 hash value (case-insensitive)
- `-pdbutil`: Path to llvm-pdbutil executable (default: search in PATH)
- `-outxml`: Path to output XML file (default: overwrite input XML file)
- `-debug`: Enable debug logging for symbol parsing
- `-syncfile`: Sync PE files from symbol directory to XML (add missing entries)
- `-fast`: Fast mode for syncfile - only parse PE when entry is missing

### Examples

**Normal mode examples:**

Update and overwrite the original file:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -yaml="kphdyn.yaml"
```

Save to a different output file:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -yaml="kphdyn.yaml" -outxml="kphdyn_updated.xml"
```

Process only a specific SHA256 hash:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -yaml="kphdyn.yaml" -sha256="abc123..."
```

Use custom llvm-pdbutil path:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -yaml="kphdyn.yaml" -pdbutil="/path/to/llvm-pdbutil"
```

**Syncfile mode examples:**

Scan symbol directory and add missing entries:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile
```

Use fast mode (only parse PE when entry is missing):

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile -fast
```

Save to a different output file:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile -outxml="kphdyn_updated.xml"
```

### Syncfile Mode Details

The syncfile mode scans the symbol directory for PE files (exe/dll/sys) and adds missing entries to the XML:

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile
```

**How it works:**

1. Scans all PE files in the symbol directory (e.g., `C:/Symbols/amd64/ntoskrnl.exe.10.0.16299.551/{sha256}/ntoskrnl.exe`)
2. Extracts metadata from file path: `arch`, `file`, `version`, `sha256`
3. Checks if a matching `<data>` entry exists in XML (by arch + file + version + sha256)
4. If the entry doesn't exist:
   - Parses PE file to extract `hash` (SHA256), `timestamp`, and `size`
   - Finds the insertion position (after the closest smaller version)
   - Creates new entry with `fields id="0"` (not yet resolved)
5. Skips entries that already exist in XML

**Fast mode (`-fast`):**

In normal syncfile mode, all PE files are parsed upfront. With `-fast` flag, PE parsing is deferred until an entry is confirmed to be missing, which can significantly speed up the process when most entries already exist.

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -syncfile -syncfile -fast
```

**Expected symbol directory structure:**

```text
C:/Symbols/
├── amd64/
│   ├── ntoskrnl.exe.10.0.16299.551/
│   │   └── 68d5867b5e66fce486c863c11cf69020658cadbbacbbda1e167766f236fefe78/
│   │       ├── ntoskrnl.exe
│   │       └── ntkrnlmp.pdb
│   └── ntkrla57.exe.10.0.20348.4529/
│       └── a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456/
│           ├── ntkrla57.exe
│           └── ntkrla57.pdb
└── arm64/
    └── ntoskrnl.exe.10.0.16299.1004/
        └── f1e2d3c4b5a6978012345678901234567890fedcba1234567890fedcba123456/
            ├── ntoskrnl.exe
            └── ntkrnlmp.pdb
```

**Output example:**

```text
Scanning symbol directory: C:/Symbols
  Found 3071 PE files

[1457/3071] amd64/ntoskrnl.exe v10.0.19041.5070
  Entry missing, parsing PE...
  Added new entry after version 10.0.19041.5007

Summary: 2 added, 3069 skipped, 0 failed
```

### Configuration (kphdyn.yaml)

The yaml config file specifies which files to process and which symbols to extract

```yaml
  symbols:
    - name: EgeGuid
      struct_offset: "_ETW_GUID_ENTRY->Guid"
      type: uint16

    - name: EpObjectTable
      struct_offset: "_EPROCESS->ObjectTable"
      type: uint16
```

### Output

For each `<data>` entry matching the specified files, the script:
1. Parses the corresponding PDB file to extract all symbol offsets
2. Assigns a `<fields>` ID (reuses existing ID if offsets match exactly)
3. Updates the `<data>` entry to reference the correct `<fields>` ID
4. Removes orphan `<fields>` elements that are no longer referenced

```xml
<data arch="amd64" version="10.0.10240.16384" file="ntoskrnl.exe" ...>1</data>
<fields id="1">
    <field value="0x0418" name="EpObjectTable"/>
    <field value="0x03b8" name="EpSectionObject"/>
</fields>
```

## HTTP server for collecting ntoskrnl.exe 

HTTP server that handles file uploads, validates PE files and digital signatures, and stores files in the symbol directory structure.

**Note:** On Linux systems (Ubuntu/Debian/CentOS), you must install OpenSSL development libraries before running this server. See Requirements section above.

The server will:
- Accept POST requests to `/upload` endpoint
- Validate uploaded files (must be PE files)
- Verify FileDescription must be "NT Kernel & System"
- Verify Authenticode signature (Signer must be "Microsoft Windows", Issuer must be "Microsoft Windows Production PCA 2011")
- Extract OriginalFilename and FileVersion from FileResource
- Determine architecture (x86/amd64/arm64) from PE header
- Store files to: `{symboldir}/{arch}/{FileName}.{FileVersion}/{FileSHA256}/{FileName}`

Example:
- If `-symboldir="C:/Symbols"`, `arch=amd64`, `FileName=ntoskrnl.exe`, `FileVersion=10.0.22621.741`
- File will be stored at: `C:/Symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe`

### Usage, [] for optional

```bash
uv run python upload_server.py -symboldir="C:/Symbols" [-port=8000]
```

### Possible environment variables

```bash
export KPHTOOLS_SYMBOLDIR="C:/Symbols"
export KPHTOOLS_SERVER_PORT=8000
```

```bash
set KPHTOOLS_SYMBOLDIR=C:/Symbols
set KPHTOOLS_SERVER_PORT=8000
```

### API: Checks if your ntoskrnl already exists:

```
curl "http://localhost:8000/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.7462&sha256=710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a"
```

Found:
```
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "sha256": "710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a", "exists": true, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a/ntoskrnl.exe", "file_size": 12993992}
```

Not found:
```
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "sha256": "710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a", "exists": false, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a/ntoskrnl.exe", "file_size": 12993992}
```

### API: Upload your ntoskrnl to localhost server:

```
curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@C:/Windows/System32/ntoskrnl.exe" http://localhost:8000/upload
```

* `Content-Type: application/octet-stream` is expected
* File size limit: 20MB
* If the target file already exists, it will not be overwritten
* Header "X-File-Compressed: gzip" supported. with this header given, client should gzip the ntoskrnl payload before uploading.

### API: Healthy Check

```
curl "http://localhost:8000/health"
curl "http://localhost:8000/"
```

```
{"status": "healthy"}
```

## Reverse engineer symbols using IDA and LLM

Reverse engineers symbols for PE files missing PDB by comparing with similar versions that have PDB files using IDA Pro and LLM (OpenAI or Anthropic).

**Directory Structure:**

- Works with: `{symboldir}/{arch}/{filename}.{version}/{sha256}/{files}`
- Requires IDA Pro with `ida64.exe`

### Basic Usage

```bash
uv run python reverse_symbols.py -symboldir=C:/Symbols -reverse=PsSetCreateProcessNotifyRoutine -provider=openai -api_key="YOUR_KEY"
```

With custom model and API base:

```bash
uv run python reverse_symbols.py -symboldir=C:/Symbols -reverse=PsSetCreateProcessNotifyRoutune \
    -provider=openai -api_key="YOUR_KEY" -model="deepseek-chat" -api_base="https://api.deepseek.com"
```

### Command Arguments

- `-symboldir`: Symbol directory containing PE files (required, or set `KPHTOOLS_SYMBOLDIR`)
- `-reverse`: Function name to reverse engineer (required, e.g., `PsSetCreateProcessNotifyRoutine`)
- `-provider`: LLM provider: `openai` or `anthropic` (default: `openai`)
- `-api_key`: API key (or use `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` environment variable)
- `-model`: LLM model name (optional)
- `-api_base`: API base URL (optional, or use `OPENAI_API_BASE`/`ANTHROPIC_API_BASE`)
- `-ida`: Path to `ida64.exe` (optional, searches PATH or uses `IDA64_PATH` environment variable)
- `-debug`: Enable debug output

### Processing Workflow

For each PE file missing PDB:

1. Find the closest lower version with PDB as reference
2. Run IDA disasm on target PE (missing PDB)
3. Run IDA disasm on reference PE (with PDB)
4. Call `generate_mapping.py` to create symbol mappings via LLM
5. Run IDA `symbol_remap` to apply mappings

### Tool Requirements

- IDA Pro with `ida64.exe`
- Python 依赖由 `pyproject.toml` 管理，请先执行 `uv sync`

## Reference workflow in Jenkins (Windows)

 - First run may takes hours downloading PE and PDB files.
 - A typical run takes ~20 mins
 - Output file: `kphdyn.xml`
 - All steps are running via Windows Command Prompt

```shell
@echo Get latest kphdyn.xml

powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.official.xml"

copy kphdyn.official.xml kphdyn.xml /y
```

```shell
@echo Sync unmanaged ntoskrnl to kphdyn.xml

uv run python update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -syncfile -fast
```

```shell
@echo Download ntoskrnl via kphdyn.xml, this may takes hours for the first run

uv sync

uv run python download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast

exit 0
```

```shell

@echo Generate SymbolMapping.yaml for missing-pdb ntoskrnl

set IDA64_PATH=C:\Program Files\IDA Professional 9.0\ida64.exe
set LLM_PROVIDER=openai
set LLM_API_BASE=https://api.deepseek.com
set LLM_MODEL=deepseek-chat
set LLM_API_KEY=

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PsSetCreateProcessNotifyRoutine -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PspSetCreateProcessNotifyRoutine -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PsSetCreateThreadNotifyRoutine -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PspSetCreateThreadNotifyRoutine -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PsSetLoadImageNotifyRoutine -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PsSetLoadImageNotifyRoutineEx -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

uv run python reverse_symbols.py -symboldir="%WORKSPACE%\symbols" -reverse=PgInitContextFillPtr -signature=FB488D05????????4989 -no_procedure -disasm_lines=200 -template="%WORKSPACE%\ida\GenerateMappingDisasmOnly.md" -provider=%LLM_PROVIDER% -api_base="%LLM_API_BASE%" -model="%LLM_MODEL%" -api_key="%LLM_API_KEY%"

```

```shell
@echo Generate strut function and variable RVA via ntoskrnl pdb, llvm-pdbutil assumed in PATH

uv run python update_symbols.py -xml kphdyn.xml -symboldir "%WORKSPACE%\symbols" -yaml kphdyn.yaml
```

```shell
@echo Fix function and variable RVA via SymbolMapping.yaml

uv run python update_symbols.py -xml kphdyn.xml -symboldir "%WORKSPACE%\symbols" -yaml kphdyn.yaml -fixnull
```

```shell
@echo Fix struct offset

uv run python update_symbols.py -xml kphdyn.xml -symboldir "%WORKSPACE%\symbols" -yaml kphdyn.yaml -fixstruct
```
