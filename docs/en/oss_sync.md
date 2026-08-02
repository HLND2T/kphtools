# OSS Sync

[Back to README](../../README.md)

## Synchronization modes

- Continuous synchronization is the default: after the initial sync, local file changes are monitored continuously; `oss2local` and `both` also poll OSS at the configured interval.
- `--once` performs a one-shot synchronization: after the initial sync, it compares paths, sizes, and content hashes for non-excluded local and OSS files, then exits without starting file monitoring or continuous polling.

Exit codes for `--once`:

- `0`: all non-excluded local and OSS files match exactly.
- `1`: content, size, or file-set differences remain, or an unhandled synchronization error occurs.

One-shot mode does not delete extra files on either side. If a file exists on only one side, verification exits with `1`; use a separate, explicit cleanup process when mirror-style deletion is required.

## Install dependencies

Dependencies are managed centrally by the repository root `pyproject.toml` and `uv.lock`:

```powershell
uv sync
```

## Background synchronization configuration

OSS synchronization uses `alibabacloud-oss-v2` and shares the same connection environment variables as `upload_server.py`:

- `KPHTOOLS_SYMBOLDIR`: optional local symbol directory; defaults to `symbols` (consistent with `upload_server.py`)
- `OSS_ACCESS_KEY_ID`: Alibaba Cloud AccessKey ID, required
- `OSS_ACCESS_KEY_SECRET`: Alibaba Cloud AccessKey Secret, required
- `OSS_SESSION_TOKEN`: optional STS session token
- `KPHTOOLS_SERVER_OSS_REGION`: OSS region, required, for example `cn-hangzhou`
- `KPHTOOLS_SERVER_OSS_ENDPOINT`: OSS endpoint, required
- `KPHTOOLS_SERVER_OSS_BUCKET`: OSS bucket name, required
- `KPHTOOLS_SERVER_OSS_PREFIX`: optional OSS path prefix; defaults to empty
- `KPHTOOLS_OSS_SYNC_CHECK_INTERVAL`: OSS check interval in seconds; defaults to `60`
- `KPHTOOLS_OSS_SYNC_EXCLUDE`: comma-separated excluded paths; defaults to `.git,.stfolder`
- `KPHTOOLS_OSS_SYNC_EXCLUDE_EXTENSION`: comma-separated excluded extensions; defaults to `.txt,.yaml,.pdb,.id0,.id1,.id2,.nam,.til,.i64,.log,.stignore`

Set the synchronization direction with a command-line argument:

```bash
uv run --env-file .env oss_sync.py --direction local2oss
uv run --env-file .env oss_sync.py --direction oss2local
uv run --env-file .env oss_sync.py --direction both
```

Use `--once` in CI or batch jobs and use the exit code as the synchronization result:

```bash
uv run --env-file .env oss_sync.py --direction local2oss --once
```

