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
uv run python download_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https://msdl.microsoft.com/download/symbols"]
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

## Dump YAML artifacts

`dump_symbols.py` is the primary analysis entry point.

```bash
uv run python dump_symbols.py
```

By default it uses `./symbols`, `config.yaml`, and scans both `amd64,arm64`. Use `-symboldir`, `-configyaml`, or `-arch=amd64` to override.

The script scans `symboldir/<arch>/<file>.<version>/<sha256>/`, resolves symbols into `{symbol}.yaml`, and writes them next to the corresponding PE/PDB files.

## Export kphdyn.xml

`update_symbols.py` is now a YAML-to-XML exporter.

```bash
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -configyaml="config.yaml" -syncfile
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

## Migrated symbol analysis workflow

Use the migrated workflow:

```bash
uv run python dump_symbols.py
uv run python update_symbols.py -xml="kphdyn.xml" -symboldir="C:/Symbols" -configyaml="config.yaml" -syncfile
```

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

uv run python update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -syncfile
```

```shell
@echo Download ntoskrnl via kphdyn.xml, this may takes hours for the first run

uv sync

uv run python download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast

exit 0
```

```shell
@echo Analyze symbols and dump YAML artifacts

uv run python dump_symbols.py -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```

```shell
@echo Export kphdyn.xml from YAML artifacts

uv run python update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml" -syncfile
```
