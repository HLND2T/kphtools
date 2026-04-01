# AGENTS.md

本文件用于指导在本仓库内进行 Agent Coding（采用渐进式披露）。

## Serena memories（保持上下文精简）

1. 优先使用 `list_memories` 查看当前项目已有的 memories（不要默认读全）。
2. 仅在需要时，用 `read_memory` 精确读取某个 memory 文件（按需加载）。
3. 如 memory 信息不足/过期，再回退读取仓库文件或用 ContextEngine/符号/搜索能力做定点定位，并使用 `write_memory`、`edit_memory` 或 `delete_memory` 维护记忆内容。

## 本仓库的高层信息（优先读对应 memories）

以下内容已在 onboarding 时整理到 Serena memories，本文件不再重复展开：

- 项目目的/技术栈/关键外部工具：`project_overview.md`
- 目录结构与模块划分：`codebase_structure.md`
- 常用开发命令：`suggested_commands.md`
- 代码风格与约定：`style_conventions.md`
- 完成任务后的建议清单：`task_completion.md`

## 当 memories 不足时的“源文件”入口（按需查询和读取）

- 快速说明：`README.md`
- 依赖说明：`pyproject.toml`
- 主要脚本入口：`download_symbols.py`、`update_symbols.py`、`reverse_symbols.py`、`upload_server.py`、`migrate_symboldir.py`
- 逆向相关脚本：`ida/generate_mapping.py`、`ida/ida.py`
- 配置/数据：`kphdyn.xml`、`kphdyn.yaml`、`kphdyn2.yaml`、`kphdyn.official.xml`
- 大体量目录（避免全量读取）：`symbols/`、`output/`、`uploads/`

## 渐进式披露要点

- 先读 memories，再定位单文件/单符号；不要一次性读全仓库。
- 与符号/二进制相关的目录优先“按需定位”，避免全量扫描。
- 涉及外部工具（IDA/llvm-pdbutil/符号服务器）时，先确认环境与路径/变量配置。

## Misc rules

- Always `activate_project` on agent startup.
