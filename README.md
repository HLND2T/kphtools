# Toolkits for KPH Dynamic Data

[简体中文](README.zh-CN.md)

Several scripts are included to generate offsets for [SystemInformer](https://github.com/winsiderss/systeminformer)'s [kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml), adding your own `struct_offset` or `func_offset` entries. The symbol inventory and analysis workflow can be customized through `config.yaml`.

## Quick start

Install the [requirements](docs/en/requirements.md), then run the full pipeline:

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
uv run download_symbols.py -fast
uv run dump_symbols.py
uv run update_symbols.py
```

The first download may take hours. Later runs can reuse the PE, PDB, and YAML artifacts already stored under `symbols/`.

## Workflow

1. [`download_symbols.py`](docs/en/download_symbols.md) downloads PE files and matching PDB symbols from Microsoft Symbol Server.
2. [`dump_symbols.py`](docs/en/dump_symbols.md) analyzes each binary and writes per-symbol YAML artifacts plus an `artifacts.yaml` manifest next to it.
3. [`update_symbols.py`](docs/en/update_symbols.md) exports those YAML artifacts back into `kphdyn.xml`.

The default symbol layout is:

```text
symbols/<arch>/<file>.<version>/<sha256>/
```

All four scripts use `symbols` under the current working directory by default. Set `KPHTOOLS_SYMBOLDIR` to override that directory; the environment variable takes precedence over `-symboldir`.

## Nightly releases

The build workflow runs daily at **03:17 Singapore time (19:17 UTC)** from the default branch, `main`. It can also be started manually through **Build On Self Runner → Run workflow**; manual nightly publication is restricted to the default branch.

Download [`kphdyn.xml`](https://github.com/HLND2T/kphtools/releases/download/nightly/kphdyn.xml) from the fixed [`nightly` prerelease](https://github.com/HLND2T/kphtools/releases/tag/nightly). The first run creates the release. Later runs compare the generated XML with that release's attachment and update the release, attachment, and tag only when XML data changes. The tag then points to the source commit used for the build.

Comparison ignores indentation, line endings, comments, and attribute order. Element order, field IDs, text, and all attribute values remain significant. If the comparison or download fails, publication stops. Unchanged XML skips publication while symbol synchronization still runs. Regular tag releases retain their existing behavior, and the nightly prerelease does not replace the latest stable release.

## Shared CI caches

The Windows/Linux self-hosted build and PR jobs use the S3-compatible bucket `actions-cache-kphtools` for symbol shards and the uv dependency cache. Configure `S3_ENDPOINT_URL` (an HTTP(S) origin), `S3_ACCESS_KEY_ID`, and `S3_SECRET_ACCESS_KEY` in the `win64` environment. Provision the bucket with list/read/write access for these credentials; the clients do not create it. Every runner must be able to reach the endpoint, which must support conditional `PutObject` requests (`IfMatch` and `IfNoneMatch`). `PERSISTED_WORKSPACE` is no longer used by CI.

Symbols are sharded by `arch/binary.version/sha256`. Each shard has separate `inputs` (PE/PDB/IDA and other analysis files) and `results` (YAML) archives, compressed with zstd level 1. Builds restore the catalog and YAML first, and fetch inputs only when analysis needs them. Only changed components are uploaded. Immutable archive keys are scoped to this repository and runner OS; the small `catalog.json` is updated conditionally so concurrent producers cannot overwrite a newer catalog. Archives are checked for size, SHA-256, content identity, and safe paths. OSS synchronization retains its existing exclusions and downloads only uncached files.

Do not expire all shard objects by age: an unchanged input may remain referenced by the catalog indefinitely. Any later garbage collection must preserve referenced objects. This migration does not delete old S3 snapshots.

PR validation downloads only the input shards for `amd64/ntoskrnl.exe.10.0.22621.3668` and copies them into an isolated directory, excluding YAML so analysis runs again. Missing PE/PDB inputs are downloaded from the exact upstream XML selection, falling back to the retained download metadata in [`.github/pr-kernel.xml`](.github/pr-kernel.xml) when upstream has pruned this version. As in the original workflow, a nonempty PE is required; a separate PDB is optional, and existing IDA databases remain available to the analysis pipeline. Validation must generate fresh YAML and fails on analysis errors. PR results never update the shared catalog. uv caches use the pinned `hzqst/setup-uv` S3 backend in both jobs.

Generated data lives in `.ci-symbol-cache/` and `.ci-pr-analysis/` under the standard checkout. PR XML, YAML, and logs are uploaded as a diagnostic artifact before cleanup. Each job cleans its generated directories on its own runner, including on ordinary failure; uv's post-job cache save retains access to the checkout and dependency files. No PR-close cleanup job or per-PR persistent workspace is needed. Runner shutdown or forced termination still requires runner lifecycle cleanup. Previously created `kphtools-pr-*` directories are not removed by this migration.

Before the first migrated run, seed the bucket from the existing symbol store using [issue #42](https://github.com/HLND2T/kphtools/issues/42) and the matching migration checkout: `uv run --group ci --frozen python ci_symbol_cache.py seed --symbols <source-symbols> --repository HLND2T/kphtools --platform Windows`. The command preserves the source, archives one component at a time, reuses uploaded objects on retry, and publishes the catalog after all shards succeed. A nonempty catalog requires `--merge`, which should only be used with an authoritative source. The fixed PR kernel's PE and PDB returned 404 from Microsoft Symbol Server when checked on 2026-10-09; preserve the existing PE and IDA database, and include a PDB if available. uv is warmed separately by `setup-uv` during CI.

## Documentation

- [Requirements and environment setup](docs/en/requirements.md)
- [Linux/WSL validation and cross-platform runners](docs/en/linux.md)
- [Download PE and PDB symbols](docs/en/download_symbols.md)
- [Dump YAML artifacts](docs/en/dump_symbols.md)
- [Generate reference YAML for `LLM_DECOMPILE`](docs/en/reference_yaml.md)
- [Export YAML artifacts to `kphdyn.xml`](docs/en/update_symbols.md)
- [Synchronize symbol files with OSS](docs/en/oss_sync.md)
- [Run the upload server](docs/en/upload_server.md)
- [Run the reference Jenkins workflow on Windows](docs/en/jenkins_windows.md)
