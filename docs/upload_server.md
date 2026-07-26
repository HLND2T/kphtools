# Upload Server

[Back to README](../README.md)

`upload_server.py` accepts file uploads, validates PE files and digital signatures, and stores accepted files on local disk or Alibaba Cloud OSS.

On Linux, install the OpenSSL development libraries described in [Requirements](requirements.md) before running the server.

## Behavior

The server will:

- Accept POST requests at `/upload`.
- Validate that uploaded files are PE files.
- Verify that `FileDescription` is `NT Kernel & System`.
- Verify the Authenticode signature. The signer must be `Microsoft Windows` and the issuer must be `Microsoft Windows Production PCA 2011`.
- Extract `OriginalFilename` and `FileVersion` from `FileResource`.
- Determine the `x86`, `amd64`, or `arm64` architecture from the PE header.
- Select the storage backend with `KPHTOOLS_SERVER_STORAGE=disk|oss`.
- Store files using `{arch}/{FileName}.{FileVersion}/{FileSHA256}/{FileName}` as the backend-relative path.

Clients must provide the HTTP POST upload request. Use nginx or a CDN when HTTPS support is required.

For example, with disk storage, `-symboldir="C:/Symbols"`, `arch=amd64`, `FileName=ntoskrnl.exe`, and `FileVersion=10.0.22621.741`, the file is stored at:

```text
C:/Symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe
```

## Usage

Disk storage remains the default when `KPHTOOLS_SERVER_STORAGE` is unset:

```bash
export KPHTOOLS_SERVER_STORAGE=disk
export KPHTOOLS_SYMBOLDIR="$HOME/kphtools/symbols"
cd "$HOME/kphtools"
uv run python upload_server.py [-port=8000]
```

OSS storage writes uploaded files directly from memory to OSS and does not create a local symbol directory:

```bash
export KPHTOOLS_SERVER_STORAGE=oss
export KPHTOOLS_SERVER_OSS_REGION="cn-hangzhou"
export KPHTOOLS_SERVER_OSS_BUCKET="kernel-symbols"
export KPHTOOLS_SERVER_OSS_ENDPOINT="oss-cn-hangzhou-internal.aliyuncs.com"
export KPHTOOLS_SERVER_OSS_PREFIX="symbols"
export OSS_ACCESS_KEY_ID="your-access-key-id"
export OSS_ACCESS_KEY_SECRET="your-access-key-secret"
cd "$HOME/kphtools"
uv run python upload_server.py [-port=8000]
```

## Environment variables

Common server variables:

- `KPHTOOLS_SERVER_STORAGE`: `disk` or `oss`; defaults to `disk` and is case-insensitive.
- `KPHTOOLS_SERVER_PORT`: optional listen port; defaults to `8000`.

Disk storage variables:

- `KPHTOOLS_SYMBOLDIR`: required unless `-symboldir` is provided.

OSS storage variables:

- `KPHTOOLS_SERVER_OSS_REGION`: required OSS region, for example `cn-hangzhou`.
- `KPHTOOLS_SERVER_OSS_BUCKET`: required bucket name.
- `KPHTOOLS_SERVER_OSS_ENDPOINT`: optional internal or custom endpoint.
- `KPHTOOLS_SERVER_OSS_PREFIX`: optional object key prefix; leading and trailing `/` are removed.
- `OSS_ACCESS_KEY_ID`: required by the OSS SDK environment credentials provider.
- `OSS_ACCESS_KEY_SECRET`: required by the OSS SDK environment credentials provider.
- `OSS_SESSION_TOKEN`: optional STS session token.

Example disk configuration on Windows Command Prompt:

```bat
set KPHTOOLS_SERVER_STORAGE=disk
set KPHTOOLS_SYMBOLDIR=C:/Symbols
set KPHTOOLS_SERVER_PORT=8000
```

Invalid storage modes or missing mode-specific variables cause the server to exit before listening.

## OSS behavior and permissions

With `KPHTOOLS_SERVER_OSS_PREFIX=symbols`, the example object key is:

```text
symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe
```

The OSS identity needs permission to call `PutObject` and `HeadObject`/read object metadata for the configured bucket and prefix. Bucket creation, lifecycle rules, encryption, RAM policy management, and migration or deletion of existing local files are outside the server's scope.

Uploads use OSS forbid-overwrite semantics. An existing object at the SHA-derived key, including a concurrent upload conflict, is treated as an idempotent success. `/exists` uses object metadata and returns `file_size` without downloading the object. Only `NoSuchKey` is treated as absent; other OSS failures return HTTP 502 with a generic message.

OSS mode does not fall back to disk. Existing analysis tools still consume a local `symbols` directory, so objects needed by those tools must be mounted or downloaded separately.

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
