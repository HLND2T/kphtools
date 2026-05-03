# kphtools reference YAML 生成器设计

日期：2026-05-01

## 1. 摘要

本设计为 `kphtools` 新增一个独立 CLI：`generate_reference_yaml.py`。

该脚本用于针对单个函数生成 `LLM_DECOMPILE` 所需的 reference YAML，输出到：

`ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml`

例如：

`ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml`

reference YAML 与当前版本普通 `{symbol}.yaml` 工件职责分离：

- 普通 `{symbol}.yaml` 继续作为当前版本符号解析结果工件，存放在 `symboldir/<arch>/<file>.<version>/<sha256>/`
- reference YAML 只作为后续 `LLM_DECOMPILE` 的参考函数样本，存放在仓库内 `ida_preprocessor_scripts/references/`

首版仅支持单函数生成，不支持批量扫描，不自动改写 `find-*.py`，不自动修改 `config.yaml`，也不直接触发 LLM。

在导出语义上，本设计要求严格对齐 `D:\CS2_VibeSignatures\generate_reference_yaml.py` 当前实现，尤其是：

- `procedure` 继续沿用 CS2 的伪代码导出逻辑
- `disasm_code` 必须沿用 CS2 的注释行导出逻辑
- `disasm_code` 必须正确处理离散 function chunk，而不是只导出入口连续块

## 2. 目标

1. 提供一个独立 CLI，为 `kphtools` 生成单函数 reference YAML
2. 输出路径采用 `module + arch` 语义，而不是 `platform`
3. 优先复用当前版本普通 `{symbol}.yaml` 工件中的地址信息
4. 统一通过 IDA MCP 导出反汇编和伪代码，供后续 `LLM_DECOMPILE` 使用
5. 保持 reference YAML schema 最小化，便于人工审阅与后续复用
6. 严格复用或等价移植 CS2 当前 `procedure` / `disasm_code` 导出实现语义，避免在 `kphtools` 里另造一套导出算法

## 3. 非目标

1. 本次不支持批量生成 reference YAML
2. 本次不自动把 reference YAML 接入具体 `find-*.py`
3. 本次不修改 `config.yaml` 公共 schema 去新增 alias 字段
4. 本次不把该工具并入 `dump_symbols.py` 主流程
5. 本次不在生成完成后直接执行真实 LLM fallback 验证
6. 本次不重新设计一套不同于 CS2 的 `procedure` / `disasm_code` 导出格式

## 4. 方案比较与结论

### 4.1 方案 1：直接移植 CS2_VibeSignatures 脚本

优点：

- 实现最快
- 与参考项目接口最接近

缺点：

- 会把 `gamever/platform/bin/...` 语义带入 `kphtools`
- 与 `kphtools` 当前 `symboldir/<arch>/<file>.<version>/<sha256>/` 结构不贴合
- 后续维护会持续出现语义错位

### 4.2 方案 2：做 kphtools 原生 CLI，并复用现有 MCP 与工件逻辑

优点：

- 职责边界清晰
- 能复用现有 MCP 启动/关闭模式与普通工件读取逻辑
- 与 `kphtools` 的目录语义、模块命名和现有工作流保持一致

缺点：

- 首版设计量略高于“直接复制”

### 4.3 方案 3：将 reference 导出并入 dump_symbols.py 或预处理公共层

优点：

- 可复用更多现有执行路径

缺点：

- 人工调用不便
- 会把“单次生成参考样本”的动作和主分析流水线耦合
- 不符合独立工具的职责边界

### 4.4 选定方案

采用方案 2：实现 `kphtools` 原生单函数 CLI，并复用现有 MCP 会话模式与普通工件读取能力。

## 5. CLI 设计

### 5.1 脚本位置

- `generate_reference_yaml.py`

### 5.2 核心职责

输入一个规范函数名 `func_name`，在当前 IDA 目标二进制上下文中解析对应函数地址，导出该函数的：

- `func_va`
- `disasm_code`
- `procedure`

然后写出 reference YAML。

### 5.3 参数边界

首版建议参数形态如下：

- 必填：`-func_name`
- 可选：`-module`
- 可选：`-arch`
- 可选：`-mcp_host`
- 可选：`-mcp_port`
- 可选：`-debug`
- 可选：`-binary`
- 可选：`-auto_start_mcp`

规则：

1. `-auto_start_mcp` 与 `-binary` 必须成对出现
2. 未指定 `-auto_start_mcp` 时，默认连接当前已运行的 MCP 服务
3. `-module`、`-arch` 未显式给出时，优先从当前 IDA binary 上下文推断

### 5.4 输出路径

输出固定写到：

`ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml`

例如：

`ida_preprocessor_scripts/references/ntoskrnl/ExReferenceCallBackBlock.amd64.yaml`

## 6. 输出 schema

reference YAML 使用最小 schema：

```yaml
func_name: ExReferenceCallBackBlock
func_va: "0x140123456"
disasm_code: |
  ...
procedure: |
  ...
```

约束：

1. 顶层只包含 `func_name`、`func_va`、`disasm_code`、`procedure`
2. `func_va` 必须写成十六进制字符串
3. `disasm_code` 必须非空
4. `procedure` 允许为空字符串
5. `func_name` 保持用户输入的规范名，不强制替换为 IDA 中的真实名字

说明：

- `procedure` 与 `disasm_code` 的具体文本组织方式，以 CS2 当前 `build_function_detail_export_py_eval(...)` 的真实行为为准
- `kphtools` 不定义与 CS2 不一致的独立导出方言

## 7. 执行流程

脚本执行流程固定为 5 步：

1. 建立 MCP 会话
2. 识别当前二进制上下文
3. 解析目标函数地址
4. 导出函数反汇编与伪代码
5. 写出 reference YAML

### 7.1 MCP 会话模式

支持两种模式：

1. 连接现有 `idalib-mcp`
2. 通过 `-auto_start_mcp -binary <path>` 自动启动 `idalib-mcp`

两种模式在会话建立后统一走同一条业务链路，不分叉导出逻辑。

### 7.2 上下文识别

脚本需要确定：

- `binary_path`
- `module`
- `arch`
- `binary_dir`

其中：

- `arch` 从 `symboldir/<arch>/...` 这一层推断，只接受 `amd64` 或 `arm64`
- `module` 通过当前 binary 文件名与 `config.yaml` 中 `modules[].path` 的候选文件名匹配，再映射回模块规范名
- `binary_dir` 指当前版本目录：`symboldir/<arch>/<file>.<version>/<sha256>/`

如果任一上下文无法唯一确定，脚本直接失败，不做猜测。

### 7.3 地址解析优先级

函数地址解析按以下顺序执行：

1. 先检查当前 `binary_dir/<func_name>.yaml`
2. 如果普通工件存在且包含 `func_rva` 或 `func_va`，则优先复用其中的地址信息；当只有 `func_rva` 时，结合当前 IDA `imagebase` 还原 `func_va`
3. 如果普通工件不存在或不含可用地址，则到 IDA 中按精确 `func_name` 查找
4. 如果后续确实需要 alias，扩展时再补一个轻量元数据读取层，从对应 `find-*.py` 的 `FUNC_METADATA` 读取 alias

首版不依赖 `config.yaml` 中的 alias，因为当前公共配置并未统一承载这类信息。

解析结果要求：

- 0 个地址：失败
- 多个不同地址：失败
- 唯一地址：继续导出

### 7.4 内容导出

拿到 `func_va` 后，通过 MCP `py_eval` 导出：

- `disasm_code`
- `procedure`

要求：

1. 导出实现应严格对齐 CS2 当前 `build_function_detail_export_py_eval(...)` 的行为
2. `disasm_code` 必须非空
3. `procedure` 尽量导出 Hex-Rays 伪代码
4. 如果 Hex-Rays 不可用或反编译失败，`procedure` 允许为空字符串
5. `disasm_code` 中应在可稳定读取时，于对应指令行前插入注释行
6. `disasm_code` 必须覆盖当前函数全部已归属的 function chunk，包括离散 chunk，而不是只覆盖入口连续块

具体对齐要求：

1. 优先复用或等价移植 CS2 的共享 `py_eval` 代码生成器，而不是在 `kphtools` 中重新发明一版导出脚本
2. `procedure` 继续沿用 CS2 当前 `get_pseudocode(...)` 逻辑，不在 `kphtools` 侧自定义额外变体
3. `disasm_code` 继续沿用 CS2 当前“chunk 归属 + 控制流遍历 + code-head 缺口补齐”的收集策略
4. 注释读取继续沿用 CS2 当前逻辑：普通注释、repeatable 注释、以及可稳定读取的 extra comment 去重后插入到对应指令行之前
5. `procedure` 若按 CS2 当前 `cfunc.get_pseudocode()` 输出包含 Hex-Rays 注释文本，则原样保留，不在 `kphtools` 侧额外裁剪或重写

### 7.5 function chunk 处理要求

为避免遗漏离散 tail chunk，`disasm_code` 的导出必须遵守与 CS2 当前实现一致的策略：

1. 优先使用 `idautils.Chunks(func.start_ea)` 收集 chunk 范围
2. 若失败或为空，回退到 `ida_funcs.func_tail_iterator_t`
3. 若仍失败，最后回退到 `(func.start_ea, func.end_ea)` 单区间
4. 所有控制流遍历与补齐扫描都必须限制在当前函数 chunk 范围内
5. 从函数入口做控制流遍历后，再扫描全部 chunk 内 code heads，把未收集到的指令地址补齐
6. 最终按地址升序输出，确保离散 chunk 稳定纳入 `disasm_code`

## 8. 内部结构

首版允许仍放在单文件中实现，但内部职责建议拆成 4 个小单元。

### 8.1 TargetContextResolver

职责：

- 从 CLI 参数和当前 IDA binary 路径确定 `binary_path`
- 推断或校验 `module`
- 推断或校验 `arch`
- 定位当前 `binary_dir`

### 8.2 FunctionAddressResolver

职责：

- 优先读取当前版本普通 `{func_name}.yaml`
- 从 `func_rva` 或 `func_va` 恢复唯一 `func_va`
- 普通工件不可用时，回退到 IDA 精确名字解析

### 8.3 ReferenceExporter

职责：

- 通过 MCP `py_eval` 导出函数反汇编与伪代码
- 在 Python 侧校验导出 payload 是否满足最小 schema

实现约束：

- 不重新设计独立于 CS2 的 `procedure` / `disasm_code` 导出器
- 优先直接移植或抽取 CS2 当前 `build_function_detail_export_py_eval(...)` 语义
- 若因仓库结构差异无法直接复用代码，也必须在行为上保持等价，包括注释导出和离散 chunk 收集

### 8.4 ReferenceYamlWriter

职责：

- 以稳定字段顺序写出 reference YAML
- 多行字符串使用 YAML literal block，便于人工审阅

## 9. 复用边界

### 9.1 建议复用

1. `dump_symbols.py` 中现有的 MCP 启动/关闭模式
2. `dump_symbols.py` 中对 binary 与 MCP 会话匹配的校验思路
3. `symbol_artifacts.load_artifact()` 对普通工件 YAML 的读取与十六进制字段解析能力
4. CS2 当前 `build_function_detail_export_py_eval(...)` 的导出语义与回退顺序

### 9.2 不建议复用

1. `dump_symbols.py` 的批处理入口
2. `ida_skill_preprocessor.py` 的 skill 执行链
3. `symbol_artifacts.write_*_yaml()` 的普通工件写入逻辑

原因：

- 普通工件与 reference YAML schema 不同
- reference YAML 属于独立职责，不应伪装成普通 `{symbol}.yaml` 工件
- `procedure` / `disasm_code` 的 IDA 导出逻辑已有成熟实现，重复设计只会制造行为偏差

## 10. 错误处理

### 10.1 必须直接失败的情况

1. 无法确认当前 binary path
2. 无法唯一确定 `module`
3. 无法唯一确定 `arch`
4. 无法定位当前 `binary_dir`
5. 未解析到函数地址
6. 解析出多个不同地址
7. `disasm_code` 为空
8. `func_va` 非法
9. MCP 返回 payload 结构不符合预期

### 10.2 允许降级的情况

只有 `procedure` 可以降级：

- Hex-Rays 不可用
- 反编译失败
- 伪代码提取异常

此时仍允许写出一个有效 reference YAML，但 `procedure` 必须写成空字符串。

注释读取失败不应导致整体失败：

- 普通注释、repeatable 注释或 extra comment 读取异常时，只跳过对应注释
- function chunk 枚举失败时必须按 CS2 现有顺序回退，而不是直接退化为入口连续块导出

## 11. 成功判定

生成成功要求以下条件同时满足：

1. 输出文件存在于 `ida_preprocessor_scripts/references/<module>/<func_name>.<arch>.yaml`
2. YAML 顶层字段完整且仅包含 4 个约定字段
3. `func_va` 是可解析的十六进制字符串
4. `disasm_code` 非空
5. `procedure` 是字符串，可为空
6. `disasm_code` 在有注释可读时包含对应注释行
7. `disasm_code` 不因离散 function chunk 而截断为仅入口连续块

## 12. 验收条件

### 12.1 文档级验收

1. 用户可以通过单条 CLI 命令生成单个 reference YAML
2. 输出路径使用 `module + arch` 语义，而不是 `platform`
3. reference YAML 与普通 `{symbol}.yaml` 工件职责清晰分离

### 12.2 实现级验收

1. 参数校验正确处理 `-auto_start_mcp` 与 `-binary` 配对关系
2. 能从当前 binary 上下文解析出 `module`、`arch`、`binary_dir`
3. 地址解析遵循“普通工件优先，IDA 查找回退”的顺序
4. 地址歧义时返回明确错误
5. `procedure` 失败时允许降级输出
6. `disasm_code` 失败时必须整体失败
7. `disasm_code` 导出逻辑严格对齐 CS2 的注释与 chunk 处理语义

## 13. 建议测试范围

首版至少覆盖以下定向测试：

1. 参数组合校验
2. 输出路径生成
3. 从现有普通工件恢复 `func_va`
4. IDA 名字查找成功分支
5. IDA 名字查找失败分支
6. IDA 名字查找歧义分支
7. `procedure` 为空但仍成功写出
8. `disasm_code` 为空时失败
9. 导出脚本包含注释读取逻辑
10. 导出脚本包含离散 chunk 收集与补齐逻辑

## 14. 后续扩展

本设计为后续能力预留边界，但不在本次实现范围内：

1. 从 `find-*.py` 元数据读取 alias
2. 支持批量生成 reference YAML
3. 支持更多 reference 类型，而不仅是普通 `func`
4. 自动把生成结果接入具体 `LLM_DECOMPILE` 配置
