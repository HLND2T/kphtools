# 代码风格与约定

最后核对日期：2026-05-04。

## Python 风格

- Python 版本要求是 `>=3.10`，代码中已使用 `list[str] | None`、`dataclass`、`pathlib.Path`、async/await 等 Python 3.10+ 风格。
- 现有命名以 `snake_case` 函数/变量、`UPPER_CASE` 常量、`PascalCase` 类为主。
- 顶层 CLI 脚本通常包含模块 docstring、`parse_args(...)`、`main(...)` 和 `if __name__ == "__main__"` 入口。
- 新近模块倾向于 `main(argv: list[str] | None = None) -> int`，较旧脚本仍有无返回注解的 `main()`；修改时优先贴近所在文件既有形态。
- 没有发现 `black`、`ruff`、`flake8`、`mypy` 等格式化/静态检查配置；默认按 PEP 8 和局部风格维护。

## 数据与接口约定

- 读取 `config.yaml` 时优先使用 `symbol_config.load_config(...)`，不要绕过其 schema 校验。
- 读写 `{symbol}.yaml` artifact 时优先使用 `symbol_artifacts.py` 的 helper，避免手写 YAML payload 或重复拼接路径。
- XML 更新逻辑集中在 `update_symbols.py`，应保持 `<data>`、`<fields>`、fallback 值和 sha256/hash 兼容逻辑。
- CLI 参数沿用现有单横线长名样式，例如 `-xml`、`-symboldir`、`-configyaml`、`-syncfile`、`-debug`；已有环境变量使用 `KPHTOOLS_*` 前缀。
- 对外部路径和生成目录优先使用 `Path`，但旧脚本中已有 `os.path` 风格时应局部一致，不做无关重写。

## IDA/MCP/LLM 约定

- IDA preprocessor 脚本放在 `ida_preprocessor_scripts/`，文件名通常与 `config.yaml` 中 skill name 对应，例如 `find-*.py`。
- 通用解析能力优先放在 `ida_preprocessor_common.py`、`generic_gv.py`、`generic_func.py`、`generic_struct_offset.py` 或 resolver helper 中，避免在每个 finder 中复制大量逻辑。
- 异步 MCP 逻辑使用 `asyncio` 与 `IsolatedAsyncioTestCase` 测试；需要模拟 MCP/LLM 时使用 `AsyncMock`/`patch`，避免测试依赖真实 IDA。
- LLM_DECOMPILE prompt/reference 路径遵循 README 中的 tuple contract：`(artifact_symbol_name, llm_query_name, prompt_path, reference_yaml_path)`。

## 测试风格

- 测试框架是标准库 `unittest`，文件命名 `tests/test_*.py`，类名多为 `Test...`。
- 测试大量使用 `TemporaryDirectory`、`Path`、`unittest.mock.patch`、`AsyncMock`，应继续隔离文件系统、外部工具、网络、MCP 和 LLM。
- 断言风格使用 `self.assertEqual(...)`、`assertIn`、`assertRaisesRegex` 等 `unittest` 断言。

## 维护偏好

- 当前仓库存在较大的脚本文件，修改时保持最小局部改动，避免顺手大拆分。
- 新增逻辑优先抽成小函数并补定向测试；不要为单点修改引入新依赖、全局配置或跨模块重构。
- 注释和 docstring 以解释约束、外部工具行为、复杂数据契约为主；避免重复代码本身。源码现状以英文注释/docstring 为主，计划文档中英混合，新增注释应匹配邻近文件语境并保持简洁。