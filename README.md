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
uv run download_symbols.py [-xml="path/to/kphdyn.xml"] [-symboldir="path/to/symbols"] [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https://msdl.microsoft.com/download/symbols"] [-fast]
```

### Possible environment variables

```bash
export KPHTOOLS_XML="path/to/kphdyn.xml"
export KPHTOOLS_SYMBOLDIR="path/to/symbols"
```

```bash
set KPHTOOLS_XML=path/to/kphdyn.xml
set KPHTOOLS_SYMBOLDIR=path/to/symbols
```

### Example

```bash
uv run download_symbols.py -fast -symboldir="C:\\Symbols"
```

```
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntkrnlmp.pdb
...others
```

Where `{sha256}` is the lowercase SHA256 hash of the PE file (e.g., `68d5867b5e66fce486c863c11cf69020658cadbbacbbda1e167766f236fefe78`).

## Dump YAML artifacts

`dump_symbols.py` is the primary analysis entry point.

```bash
uv run dump_symbols.py [-symboldir="path/to/symbols"] [-configyaml="config.yaml"] [-version=10.0.26100.8246] [-arch=amd64] [-debug]
```

The script scans `<symboldir>/<arch>/<file>.<version>/<sha256>/`, resolves symbols into `{symbol}.yaml`, and writes them next to the corresponding PE/PDB files.

LLM fallback options are shared by preprocessor scripts that declare `LLM_DECOMPILE`:

```bash
uv run dump_symbols.py \
  -llm_model=gpt-5.4 \
  -llm_apikey=sk-xxxxxxxxxxxxxxxx \
  -llm_baseurl=https://api.example.com/v1 \
  -llm_temperature=0.2 \
  -llm_effort=medium \
  -llm_fake_as=codex
```

The same values can be provided by `.env` or environment variables:

```bash
KPHTOOLS_LLM_MODEL=gpt-5.4
KPHTOOLS_LLM_APIKEY=sk-xxxxxxxxxxxxxxxx
KPHTOOLS_LLM_BASEURL=https://api.example.com/v1
KPHTOOLS_LLM_TEMPERATURE=0.2
KPHTOOLS_LLM_EFFORT=high
KPHTOOLS_LLM_FAKE_AS=codex
```

Normal providers use the OpenAI-compatible Chat Completions API. `-llm_effort` defaults to `medium`; `-llm_temperature` is omitted when unset.

When `-llm_fake_as=codex` is set, the helper uses a direct `/responses` SSE transport. A non-empty `-llm_baseurl` is required and should point at the provider's `/v1` base URL. The Codex transport preserves conversation message IDs and one prompt cache key across validation and transport retries.

Each skill's `max_retries` is the total number of LLM attempts, including the first request. Schema/validation correction and transient transport failures share that budget. The same config field still controls the existing agent fallback using its established runner semantics.

## Generate reference YAML for LLM_DECOMPILE

`generate_reference_yaml.py` creates a single reference YAML at:

`ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml`

Attach to an existing MCP session:

```bash
uv run generate_reference_yaml.py -func_name="ExReferenceCallBackBlock"
```

Auto-start `idalib-mcp` for a specific binary:

```bash
uv run generate_reference_yaml.py \
  -func_name="ExReferenceCallBackBlock" \
  -auto_start_mcp \
  -binary="symbols/amd64/ntoskrnl.exe.10.0.26100.1/{sha256}/ntoskrnl.exe"
```

Check the generated YAML:

- `func_va` is credible
- `disasm_code` is non-empty and includes any available comments
- `disasm_code` includes discontinuous function chunks when IDA associates them with the same function
- `procedure` is present; it may be an empty string if Hex-Rays is unavailable

Attach the reference to a preprocessor script with prompt:

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "AlpcAttributes",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/AlpcpDeletePort.{arch}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {"AlpcpDeletePort.yaml": "required"},
    },
    {
        "symbol_name": "MmCreateProcessAddressSpace",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/ntoskrnl/PspAllocateProcess.{arch}.yaml",
        ],
        "expected_result_sections": ["found_call", "found_funcptr"],
        "dependency_policy": {"PspAllocateProcess.yaml": "required"},
    },
]
```

Every entry must contain exactly the five fields shown above. Legacy tuples and unknown fields fail closed. `dependency_policy` must map every reference YAML `func_name` to its current artifact basename; `required` targets must be declared in the skill's `expected_input`, while `optional` targets must be declared in `optional_input`. Architecture-specific input fields are supported.

`symbol_name` is the kphtools artifact name. Function/global semantic names use that value directly. Struct-member semantic names come from the finder metadata's `symbol_expr`, such as `_ALPC_PORT->PortAttributes`, without adding a non-standard field to the spec.

The validated response contract supports only:

- `found_call`: direct calls, direct tail jumps, and jump thunks
- `found_funcptr`: direct references to regular function addresses
- `found_gv`: global-variable references
- `found_struct_offset`: regular struct-member accesses, including function-pointer fields

`found_vcall` is currently unsupported and is rejected as a schema mismatch. Every non-empty result must match a requested symbol, its declared result section, and a real `(insn_va, insn_disasm)` pair from the target code. The canonical empty response is:

```yaml
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Pass the list to `preprocess_common_skill(..., llm_decompile_specs=LLM_DECOMPILE)`. Validated direct call/function-pointer/global-variable results are resolved through IDA references; validated struct results use the finder metadata and bit-offset constraints.

## Export kphdyn.xml

`update_symbols.py` is now a YAML-to-XML exporter.

```bash
uv run update_symbols.py [-xml="kphdyn.xml"] [-symboldir="path/to/symbols"] [-configyaml="config.yaml"] -syncfile
```

If a symbol YAML is missing or unresolved, `update_symbols.py` exports:

- `0xffff` for `uint16`
- `0xffffffff` for `uint32`

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
- Write the HTTP POST upload code yourself (or ask LLM agent).
- Check nginx / CDN for https support

Example:
- If `-symboldir="C:/Symbols"`, `arch=amd64`, `FileName=ntoskrnl.exe`, `FileVersion=10.0.22621.741`
- File will be stored at: `C:/Symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe`

### Usage, [] for optional

```bash
uv run upload_server.py [-symboldir="path/to/symbols"] [-port=8000]
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

## Reference workflow in Jenkins (Windows)

 - First run may takes hours downloading PE and PDB files.
 - A typical run takes ~20 mins
 - Output file: `kphdyn.xml`
 - All steps are running via Windows Command Prompt

```shell
@echo Download latest kphdyn.xml from upstream

powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.official.xml"

copy kphdyn.official.xml kphdyn.xml /y
```

```shell
@echo Sync unmanaged ntoskrnl to kphdyn.xml

uv run update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -syncfile
```

```shell
@echo Download ntoskrnl exe and pdb, this may takes hours for the first run

uv sync

uv run download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast
```

```shell
@echo Analyze symbols and dump YAML artifacts

uv run dump_symbols.py -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```

```shell
@echo Update kphdyn.xml with offsets from YAML artifacts

uv run update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```
