# update_symbols syncfile Design

## 背景

`update_symbols.py` 当前是 YAML symbol artifacts 到 `kphdyn.xml` 的导出器。脚本解析了
`-syncfile` 参数，但该参数没有独立的同步逻辑；同时 `-xml` 和 `-symboldir`
仍是必填参数，不符合 `download_symbols.py` 和 `dump_symbols.py` 中默认使用
`kphdyn.xml` / `symbols` 的约定。

符号目录已经采用如下结构存放 PE 文件：

```text
{symboldir}/{arch}/{file}.{version}/{sha256}/{file}
```

`-syncfile` 的目标是把该目录中尚未登记到 XML 的 PE 文件补入 `<data>`，
使后续下载、dump 和 update 流程可以基于同一份 `kphdyn.xml` 继续推进。

## 目标

- 让 `-syncfile` 成为纯同步模式：只扫描符号目录并补齐缺失 `<data>`。
- `-syncfile` 不加载 `config.yaml`，不读取 YAML artifacts，不更新已有 fields id。
- 新增 `<data>` 时通过 `pefile` 提取 `timestamp` 和 `SizeOfImage`。
- 新增 `<data>` 前校验目录名中的 SHA256 与文件实际 SHA256 一致。
- `-xml` 默认 `kphdyn.xml`，`-symboldir` 默认 `symbols`。
- 支持 `KPHTOOLS_XML` 和 `KPHTOOLS_SYMBOLDIR` 环境变量覆盖命令行默认值。
- 输出本次扫描、新增、跳过和错误统计。

## 非目标

- 不重写普通 YAML-to-XML 导出流程。
- 不改变 `config.yaml`、symbol artifacts 或 `dump_symbols.py` 的语义。
- 不在本次统一修复普通导出流程中 `fields` 属性与 XML 文本 fields id 的差异。
- 不引入 XML pretty printer，避免对整份 XML 产生大规模格式化改动。
- 不新增依赖；继续使用项目已有依赖 `pefile`。

## 推荐方案

采用独立 `syncfile_main(args)`。

`main()` 在解析参数后先判断 `args.syncfile`：

1. 若为 `True`，直接执行 `syncfile_main(args)`。
2. 若为 `False`，保持现有 YAML-to-XML 导出流程。

这样可以让 `-syncfile` 成为边界清晰的轻量入口，避免无意义依赖
`config.yaml`，也避免把纯文件同步与字段偏移导出混在同一条控制流里。

## CLI 行为

新增默认常量：

```python
DEFAULT_XML_PATH = "kphdyn.xml"
DEFAULT_SYMBOL_DIR = "symbols"
```

`parse_args()` 调整为：

- `-xml` 默认 `DEFAULT_XML_PATH`
- `-symboldir` 默认 `DEFAULT_SYMBOL_DIR`
- `-configyaml` 继续默认 `config.yaml`
- `KPHTOOLS_XML` 存在时覆盖 `args.xml`
- `KPHTOOLS_SYMBOLDIR` 存在时覆盖 `args.symboldir`

`-syncfile` 成功路径示例：

```bash
uv run python update_symbols.py -syncfile
```

该命令默认读取 `kphdyn.xml` 并扫描 `symbols`。

## 新增组件

### `scan_symbol_directory(symboldir)`

遍历符号目录，识别以下文件：

```text
{symboldir}/{arch}/{file}.{version}/{sha256}/{file}
```

只返回真实存在的 PE 文件路径。目录结构不符合预期的条目由调用方统计为
`invalid_path`。

### `parse_file_path_info(symboldir, file_path)`

从文件路径解析：

- `arch`
- `file`
- `version`
- `sha256`
- `binary_path`

解析规则：

- 相对路径必须至少包含四段：`arch/file.version/sha256/file`。
- `file.version` 必须以最终文件名加 `.` 开头。
- `sha256` 必须是 64 位十六进制字符串，比较时统一转为小写。

### `find_data_entry(root, info)`

检查 XML 是否已有对应 `<data>`。

匹配键为：

- `arch`
- `file`
- `version`
- `hash` 或兼容旧测试中的 `sha256`

只要任一 hash 属性与目录 SHA256 一致，即视为已存在。

### `parse_pe_info(binary_path, expected_sha256)`

读取 PE 文件并返回：

- `timestamp`: `hex(pe.FILE_HEADER.TimeDateStamp)`
- `size`: `hex(pe.OPTIONAL_HEADER.SizeOfImage)`
- `sha256`: 实际 SHA256

若实际 SHA256 与 `expected_sha256` 不一致，抛出可区分的 hash mismatch
异常，由 `syncfile_main()` 统计为 `hash_mismatch` 并跳过该文件。

### `find_insert_position(root, info)`

为新增 `<data>` 找到稳定插入位置：

1. 优先在同 `arch`、同 `file` 的 `<data>` 组内按版本号递增插入。
2. 若同组版本都小于新版本，插在同组最后一项之后。
3. 若没有同组 `<data>`，插在第一个 `<fields>` 前。
4. 若 XML 没有 `<fields>`，插在 root 末尾。

版本排序使用数字元组比较，例如 `10.0.20348.1` 小于
`10.0.20348.1006`。无法解析的版本退化为字符串比较，保证流程不中断。

### `create_data_entry(info, pe_info)`

创建格式对齐现有官方 XML 的 `<data>`：

```xml
<data arch="amd64" version="10.0.x" file="ntoskrnl.exe" hash="..." timestamp="0x..." size="0x...">0</data>
```

注意：

- 使用 `hash` 属性，不新增 `sha256` 属性。
- fields id 写入元素文本 `0`，不写 `fields="0"`。
- 不新增 `added` 属性，避免引入当前流程无法稳定定义的时间来源。

## syncfile 流程

`syncfile_main(args)` 执行步骤：

1. 校验 XML 文件存在。
2. 校验 `symboldir` 是目录。
3. 解析 XML。
4. 遍历 `scan_symbol_directory(args.symboldir)`。
5. 对每个候选文件调用 `parse_file_path_info()`。
6. 调用 `find_data_entry()`，已存在则统计 `existing` 并跳过 PE 解析。
7. 对缺失条目调用 `parse_pe_info()`。
8. SHA256 校验失败或 PE 解析失败时打印 warning 并继续。
9. 调用 `find_insert_position()` 和 `create_data_entry()` 插入 `<data>`。
10. 若新增数量大于 0，保存 XML 到 `args.outxml or args.xml`。
11. 输出统计并返回 `0`；入口错误返回非 `0`。

## 统计与输出

统计字段：

- `scanned`: 成功识别到的候选 PE 文件数。
- `existing`: XML 中已经存在的条目数。
- `added`: 新增 `<data>` 数。
- `invalid_path`: 路径结构不符合预期的数量。
- `hash_mismatch`: SHA256 校验失败数量。
- `pe_error`: `pefile` 解析失败或文件读取失败数量。
- `skipped`: 其他可恢复跳过数量。

可恢复错误打印 warning 后继续扫描。XML 缺失、符号目录缺失等入口错误直接返回
非 `0`。

## 测试策略

在 `tests/test_update_symbols.py` 中新增定向测试：

1. `parse_args()` 默认 `kphdyn.xml` / `symbols`。
2. `parse_args()` 支持 `KPHTOOLS_XML` / `KPHTOOLS_SYMBOLDIR` 覆盖。
3. `parse_file_path_info()` 解析标准目录结构。
4. `find_data_entry()` 同时兼容 `hash` 和 `sha256`。
5. `create_data_entry()` 使用文本 `0`，不写 `fields="0"`。
6. `find_insert_position()` 将新增 `<data>` 插在 `<fields>` 前。
7. `syncfile_main()` 在 mock `parse_pe_info()` 下新增缺失条目并跳过已存在条目。

这些测试不需要真实 PE 文件；PE 解析路径通过 mock 覆盖。真实 PE 行为保留给人工
smoke 验证。

## 风险与权衡

- `ElementTree.write(...)` 可能与手工格式有差异；本次不引入 pretty printer，以免
  扩大改动面。测试聚焦结构正确性。
- 普通导出流程仍可能生成 `fields` 属性格式的 `<data>`；这是既有行为，本次仅保证
  `-syncfile` 新增条目符合当前官方 XML 形态。
- 目录里可能存在只有 YAML/PDB、没有 PE 的 hash 目录；扫描逻辑只把最终文件名匹配
  的 PE 文件视为候选，避免误处理旁路文件。
- 同一 `arch/file/version` 下可存在多个 SHA256；匹配键包含 hash，因此允许并存。

## 验收标准

- `uv run python update_symbols.py -syncfile` 可在默认路径下运行。
- 缺失 PE 条目被补为 `<data ...>0</data>`。
- 已存在 XML 条目不会重复新增。
- SHA256 不匹配的文件不会写入 XML。
- `-xml` 和 `-symboldir` 的默认值及环境变量覆盖行为与 `download_symbols.py`
  保持一致。
