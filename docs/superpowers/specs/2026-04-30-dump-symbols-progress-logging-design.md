# dump_symbols Progress Logging Design

## 背景

当前 `dump_symbols.py` 主流程几乎没有主动输出。即使传入 `-debug`，也主要只是放开子进程输出，而不是打印脚本自身的执行进度。这会导致以下体验问题：

- 正常运行时，用户无法判断脚本是否正在扫描、处理、跳过还是已结束。
- 未找到可处理目录时，脚本会静默返回，缺少最基本的可观测性。
- `-debug` 不符合用户直觉，无法帮助定位 lazy startup、skill 预处理或回退路径。

## 目标

- 默认输出关键进度，让用户能看出脚本是否在扫描、是否找到目标、正在处理哪个 binary、最终是否成功。
- `-debug` 输出更详细但仍可读的执行日志，帮助定位 lazy MCP 启动、skill 处理和异常路径。
- 保持实现轻量，不引入新依赖，不重构为完整 logging 框架。

## 非目标

- 不新增 `--json-log` 或结构化日志格式。
- 不修改现有核心处理语义，只增加可观测性。
- 不跨文件做大范围 logging 改造，本次仅修改 `dump_symbols.py`。

## 方案

采用轻量 `print` 方案，并在 `dump_symbols.py` 内增加两个小型辅助输出函数：

- 普通进度输出：默认启用，打印关键节点。
- 调试输出：仅在 `args.debug` 或显式传入 `debug=True` 时打印。

不引入 `logging` 模块，避免为单脚本增加额外配置复杂度。

## 默认输出范围

默认模式下输出以下关键节点：

1. 启动扫描
   - 输出 `symboldir` 和 `arch`
2. 扫描结果
   - 输出匹配到的待处理 binary 目录数量
   - 若数量为 `0`，明确输出“未找到可处理目录”
3. 每个 binary 的处理进度
   - 开始处理：显示 `binary_dir` 和 `pdb_path`
   - 处理成功
   - 处理失败
4. 整体结束摘要
   - 成功处理数量
   - 失败数量
   - 跳过数量

## `-debug` 额外输出范围

在默认输出基础上，`-debug` 额外打印以下细节：

1. `LazyIdalibSession`
   - 首次启动 MCP
   - 连接的 MCP URL
   - binary mismatch
   - startup cleanup
   - close 路径分支
2. `process_binary_dir()`
   - 当前 skill 名称
   - `expected_output` 是否齐全
   - preprocess 状态
   - 是否 fallback 到 `run_skill()`
3. `run_skill()`
   - 调用的 skill 名称
   - agent 执行失败
4. `_open_session()`
   - 打开 session
   - initialize 失败/cleanup
5. 取消与异常路径
   - startup cleanup
   - close cleanup
   - cancel re-raise 前的摘要

## 跳过语义

为了让默认输出真正有用，需要定义“跳过”的最小可见语义：

- 若 `_iter_binary_dirs()` 结果为空：整体输出“未找到可处理目录”。
- 若某个 binary 下所有 skill 都因 `expected_output` 已存在而未做实际工作：输出该 binary “跳过”。

这里的“跳过”是用户视角上的“本次没做工作”，不是内部某个 skill 的局部 `continue`。

## 实现边界

- 仅修改 `dump_symbols.py`
- 保持 CLI 参数不变
- 不改变已有返回码约定
- 不改变 lazy startup、`qexit`、startup cleanup 逻辑，只在其关键路径前后增加输出

## 验证方式

通过定向测试和人工运行验证：

1. 保持现有 `tests.test_dump_symbols` 全量通过
2. 新增针对默认输出和 `-debug` 输出的定向测试：
   - 无匹配目录时输出“未找到可处理目录”
   - 处理单个 binary 时输出开始/成功
   - `-debug` 时输出 skill 或 lazy session 细节
3. 人工运行：
   - `uv run dump_symbols.py -symboldir ... -arch amd64`
   - `uv run dump_symbols.py -symboldir ... -arch amd64 -debug`

## 风险与权衡

- 增加 `print` 会改变 stdout 内容，但这是本次需求本身。
- 若默认输出过多，会影响可读性，因此默认只保留用户真正关心的节点。
- `-debug` 输出会更冗长，但只在显式开启时生效，风险可控。
