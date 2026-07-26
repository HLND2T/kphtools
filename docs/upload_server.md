# Upload Server

[Back to README](../README.md)

`upload_server.py` accepts file uploads, validates PE files and digital signatures, and stores accepted files in the symbol directory structure.

On Linux, install the OpenSSL development libraries described in [Requirements](requirements.md) before running the server.

## Behavior

The server will:

- Accept POST requests at `/upload`.
- Validate that uploaded files are PE files.
- Verify that `FileDescription` is `NT Kernel & System`.
- Verify the Authenticode signature. The signer must be `Microsoft Windows` and the issuer must be `Microsoft Windows Production PCA 2011`.
- Extract `OriginalFilename` and `FileVersion` from `FileResource`.
- Determine the `x86`, `amd64`, or `arm64` architecture from the PE header.
- Store files at `{symboldir}/{arch}/{FileName}.{FileVersion}/{FileSHA256}/{FileName}`.

Clients must provide the HTTP POST upload request. Use nginx or a CDN when HTTPS support is required.

For example, with `-symboldir="C:/Symbols"`, `arch=amd64`, `FileName=ntoskrnl.exe`, and `FileVersion=10.0.22621.741`, the file is stored at:

```text
C:/Symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe
```

## Usage

Arguments in brackets are optional:

```bash
uv run upload_server.py [-symboldir="path/to/symbols"] [-port=8000]
```

## Environment variables

On Linux or macOS:

```bash
export KPHTOOLS_SYMBOLDIR="C:/Symbols"
export KPHTOOLS_SERVER_PORT=8000
```

On Windows Command Prompt:

```bat
set KPHTOOLS_SYMBOLDIR=C:/Symbols
set KPHTOOLS_SERVER_PORT=8000
```

## Check whether a file exists

```bash
curl "http://localhost:8000/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.7462&sha256=710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a"
```

Found response:

```json
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "sha256": "710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a", "exists": true, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a/ntoskrnl.exe", "file_size": 12993992}
```

Not found response:

```json
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "sha256": "710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a", "exists": false, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a/ntoskrnl.exe"}
```

## Upload a file

```bash
curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@C:/Windows/System32/ntoskrnl.exe" http://localhost:8000/upload
```

- `Content-Type: application/octet-stream` is required.
- The file size limit is 20 MB.
- Existing target files are not overwritten.
- The `X-File-Compressed: gzip` header is supported when the payload is gzip-compressed before upload.

## Health check

```bash
curl "http://localhost:8000/health"
curl "http://localhost:8000/"
```

```json
{"status": "healthy"}
```
