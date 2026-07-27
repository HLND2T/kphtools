# Upload Server

[Back to README](../README.md)

`upload_server.py` accepts file uploads, validates PE files and Authenticode signatures, and stores accepted files on local disk or Alibaba Cloud OSS.

## Behavior

The server will:

- Accept POST requests at `/upload`.
- Validate that uploaded files are PE files.
- Verify that `FileDescription` is `NT Kernel & System`.
- Preflight the raw PE certificate table before invoking LIEF, then verify each Authenticode signature. The PE authentihash, CMS signer signature, authenticated attributes, countersignature, and RFC 3161 timestamp must be valid.
- Require the actual signer certificate subject CN to be exactly `Microsoft Windows` and its issuer CN to be exactly `Microsoft Windows Production PCA 2011`.
- Build the signer and timestamp certificate chains using only `ca/windows_code_signing.pem` as the trust-anchor source.
- Extract `OriginalFilename` and `FileVersion` from `FileResource`.
- Determine the `x86`, `amd64`, or `arm64` architecture from the PE header.
- Select the storage backend with `KPHTOOLS_SERVER_STORAGE=disk|oss`.
- Store files using `{arch}/{FileName}.{FileVersion}/{FileSHA256}/{FileName}` as the backend-relative path.

Clients must provide the HTTP POST upload request. Use nginx or a CDN when HTTPS support is required.

## Authenticode trust policy

The only production trust source is:

```text
ca/windows_code_signing.pem
```

The path is resolved relative to `upload_server.py`, not the current working directory. The server never merges this bundle with system CAs, the Windows certificate store, `certifi`, environment-selected CA files, LIEF defaults, or certificates downloaded over AIA, HTTP, or LDAP.

Certificates embedded in a PE may be used as intermediates, but an embedded certificate is never a trust anchor unless the same DER certificate is present in the repository bundle. Multi-signature files are evaluated one signature at a time; one completely valid and policy-compliant signature is sufficient. There is no fallback to the first embedded certificate when the signer cannot be identified.

LIEF `0.17.6` performs the per-signature Authenticode integrity and authentihash checks. `asn1crypto` exposes timestamp CMS fields and `cryptography` verifies the timestamp signature, message imprint, RFC 3161 `SigningCertificate`/`SigningCertificateV2` binding, timestamp certificate profile, historical validity, and certificate path. This supplemental check is required because LIEF 0.17.x does not fail all Microsoft countersignature cryptographic errors by itself.

The code-signing leaf must be an end-entity certificate whose EKU includes `codeSigning`; when KeyUsage is present it must permit a digital signature or content commitment. RFC 3161 and PKCS#9 timestamp certificates must be end entities with a critical, timestamp-only EKU; a present KeyUsage must permit signing. CA path building enforces BasicConstraints, path length, CA KeyUsage, CA EKU restrictions, AKI/SKI matching, bounded public-key sizes, and rejects critical extensions that the verifier does not implement.

All parsing, integrity, identity, timestamp, and trust errors fail closed. Production rejection logs contain the uploaded SHA-256, signature index, and a bounded error category; they do not contain uploaded bytes, PEM blocks, or full certificate structures.

Verification is resource-bounded before and after LIEF parsing. The current policy limits the PE certificate table to 8 MiB, an individual signature to 4 MiB, all signature DER to 8 MiB, total signatures to 16, nested depth to 4, embedded certificates per signature to 64, timestamp values per signature to 16, and certificate-chain search through per-upload shared budgets. Exceeding a limit rejects the upload before storage.

Known policy boundaries remain intentional for this migration: revocation/Windows Disallowed CTL checks are offline and are not performed, and the existing CA bundle still contains multiple public roots. Microsoft identity continues to use the exact signer and issuer CN policy from the previous implementation rather than pinning a Microsoft intermediate fingerprint. CA minimization or fingerprint pinning requires a separate security review.

## CA startup preflight

The CA bundle is loaded once before storage initialization or port binding. Startup validates every PEM certificate block, rejects truncated/non-certificate/invalid blocks, deduplicates certificates by DER SHA-256, and logs only:

- the normalized bundle path;
- the PEM block and unique-certificate counts;
- the bundle SHA-256.

If the file is missing, unreadable, empty, or malformed, the process exits with status 1 and never starts listening. There is no empty-bundle or system-trust fallback.

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

Run the service from a complete Git checkout or deployment copy that contains both `upload_server.py` and `ca/windows_code_signing.pem`. The repository currently does not build a separate upload-server release artifact; the tag workflow only publishes `kphdyn.xml`.

Disk storage uses `symbols` under the current working directory by default. Use `-symboldir` to select another directory; `KPHTOOLS_SYMBOLDIR` takes precedence when set.

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

- `KPHTOOLS_SYMBOLDIR`: optional symbol directory override; defaults to `symbols` under the current working directory.

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

## Updating the CA bundle

`ca/windows_code_signing.pem` is a security boundary. Every update must receive a dedicated review that lists each added or removed certificate's subject, issuer, serial number, validity interval, and SHA-256 fingerprint, along with the source and operational reason.

Before merging a CA update:

1. Confirm that no unintended end-entity code-signing certificate was added as a trust anchor.
2. Run the CA loader, valid-chain, unknown-root, signer/issuer, timestamp, and real Microsoft PE tests.
3. Record the new bundle SHA-256 in the deployment review.
4. Deploy the updated `ca/` directory together with `upload_server.py`; do not synchronize trust from the system or network at runtime.

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

## Authenticode verification tests

The unit test suite covers CA parsing, trust paths, signer identity, LIEF flags, multi-signature decisions, timestamp integrity, and fail-closed exceptions. A real Microsoft-signed PE smoke test is opt-in:

```powershell
$env:KPHTOOLS_AUTHENTICODE_TEST_PE = "C:\Windows\System32\ntoskrnl.exe"
uv run python -m unittest tests.test_upload_server.TestRealAuthenticodeSmoke -v
```

The smoke test accepts the original PE, rejects PE-content, certificate-table, and signer-identity tampering, and confirms rejected uploads are not handed to storage.
