# 将 YAML 工件导出到 `kphdyn.xml`

[返回 README](../../README.zh-CN.md)

`update_symbols.py` 是 YAML 到 XML 的导出工具。

## 用法

导出 YAML 工件：

```bash
uv run update_symbols.py [-xml="kphdyn.xml"] [-symboldir="path/to/symbols"] [-configyaml="config.yaml"]
```

导出器读取 [`dump_symbols.py`](dump_symbols.md) 生成的 YAML 工件，并更新 `kphdyn.xml` 中对应的条目。它会优先只解析一次每个二进制文件的 `artifacts.yaml`；如果 manifest 不存在、缺少配置中的 symbol，或早于任一对应单符号 YAML，则兼容回退到 `{symbol}.yaml` 逐文件加载。格式损坏的 manifest 会明确报错，不会被静默忽略。

将符号目录下发现的、未由配置管理的 PE 文件同步到 XML：

```bash
uv run update_symbols.py [-xml="kphdyn.xml"] [-symboldir="path/to/symbols"] -syncfile
```

`-syncfile` 是独立模式，完成文件条目同步后退出。随后不带 `-syncfile` 再运行导出器，以导出符号值。

如果符号 YAML 缺失或无法解析，`update_symbols.py` 会导出：

- `uint16` 使用 `0xffff`。
- `uint32` 使用 `0xffffffff`。

