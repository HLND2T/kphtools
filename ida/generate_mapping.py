#!/usr/bin/env python3
"""
Symbol Mapping Generator - 符号映射生成器

通过对比两个 Windows 内核版本的反汇编代码，利用 LLM 建立符号名映射关系。

用法:
    uv run python generate_mapping.py -func=FuncName -reference=path/to/ref.exe -reverse=path/to/rev.exe

示例 (OpenAI):
    uv run python generate_mapping.py \
        -func=PsSetCreateProcessNotifyRoutine \
        -reference="D:\\kphtools\\symbols\\amd64\\ntoskrnl.exe.10.0.22621.3646\\ntoskrnl.exe" \
        -reverse="D:\\kphtools\\symbols\\amd64\\ntoskrnl.exe.10.0.22621.3668\\ntoskrnl.exe" \
        -provider=openai -api_key="sk-xxx"

示例 (Anthropic):
    uv run python generate_mapping.py \
        -func=PsSetCreateProcessNotifyRoutine \
        -reference="D:\\kphtools\\symbols\\amd64\\ntoskrnl.exe.10.0.22621.3646\\ntoskrnl.exe" \
        -reverse="D:\\kphtools\\symbols\\amd64\\ntoskrnl.exe.10.0.22621.3668\\ntoskrnl.exe" \
        -provider=anthropic -api_key="sk-ant-xxx"

环境变量:
    OPENAI_API_KEY      - OpenAI API 密钥
    OPENAI_API_BASE     - OpenAI API 基础 URL（可选，用于兼容其他提供商）
    ANTHROPIC_API_KEY   - Anthropic API 密钥
    ANTHROPIC_API_BASE  - Anthropic API 基础 URL（可选）
    IDA64_PATH          - ida64.exe 路径（可选）

配置优先级:
    1. 命令行参数（最高优先级）
    2. 环境变量
    3. 默认值
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

import yaml

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


# 支持的 API 提供商
PROVIDERS = ["openai", "anthropic"]

# 默认模型
DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-20250514"
}


def get_default_template_path():
    """
    获取默认模板路径（脚本同目录下的 GenerateMapping.md）

    Returns:
        默认模板文件路径
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "GenerateMapping.md")


def load_prompt_template(template_path=None):
    """
    从文件加载 PROMPT_TEMPLATE

    Args:
        template_path: 模板路径（可选，默认为脚本同目录下的 GenerateMapping.md）

    Returns:
        模板字符串

    Raises:
        SystemExit: 如果模板文件不存在
    """
    path = template_path or get_default_template_path()

    if not os.path.exists(path):
        print(f"Error: 模板文件不存在: {path}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            template = f.read()
        print(f"[+] 加载模板: {path}")
        return template
    except Exception as e:
        print(f"Error: 无法读取模板文件 {path}: {e}")
        sys.exit(1)


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="通过对比反汇编代码生成符号映射"
    )
    parser.add_argument(
        "-func",
        required=True,
        help="要分析的函数名"
    )
    parser.add_argument(
        "-reference",
        required=True,
        help="参考PE路径（有完整符号）"
    )
    parser.add_argument(
        "-reverse",
        required=True,
        help="待分析PE路径（符号可能缺失）"
    )
    parser.add_argument(
        "-ida",
        help="ida64.exe 路径，默认从 PATH 或 IDA64_PATH 环境变量查找"
    )
    parser.add_argument(
        "-provider",
        choices=PROVIDERS,
        default="openai",
        help="API 提供商: openai 或 anthropic（默认: openai）"
    )
    parser.add_argument(
        "-api_base",
        help="API base URL（或使用 OPENAI_API_BASE/ANTHROPIC_API_BASE 环境变量）"
    )
    parser.add_argument(
        "-api_key",
        help="API key（或使用 OPENAI_API_KEY/ANTHROPIC_API_KEY 环境变量）"
    )
    parser.add_argument(
        "-model",
        help="LLM 模型名称（默认: openai=gpt-4o, anthropic=claude-sonnet-4-20250514）"
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="启用调试输出"
    )
    parser.add_argument(
        "-template",
        help="自定义 PROMPT_TEMPLATE 文件路径（默认: ida/GenerateMapping.md）"
    )

    return parser.parse_args()


def get_ida_path(ida_arg):
    """
    获取 ida64.exe 的路径

    优先级:
    1. 命令行参数 -ida
    2. 环境变量 IDA64_PATH
    3. 系统 PATH

    Args:
        ida_arg: 命令行指定的路径

    Returns:
        ida64.exe 的完整路径

    Raises:
        SystemExit: 如果找不到 ida64.exe
    """
    # 1. 命令行参数
    if ida_arg:
        if os.path.exists(ida_arg):
            return ida_arg
        print(f"Error: 指定的 IDA 路径不存在: {ida_arg}")
        sys.exit(1)

    # 2. 环境变量
    env_path = os.environ.get("IDA64_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    # 3. 系统 PATH
    ida_in_path = shutil.which("ida64.exe") or shutil.which("ida64")
    if ida_in_path:
        return ida_in_path

    print("Error: 找不到 ida64.exe")
    print("请通过以下方式之一指定 IDA 路径:")
    print("  1. 使用 -ida 参数: -ida=\"C:\\IDA\\ida64.exe\"")
    print("  2. 设置环境变量: set IDA64_PATH=C:\\IDA\\ida64.exe")
    print("  3. 将 IDA 目录添加到系统 PATH")
    sys.exit(1)


def get_api_config(provider, api_key_arg, api_base_arg):
    """
    获取 API 配置

    优先级:
    1. 命令行参数
    2. 环境变量

    Args:
        provider: API 提供商 (openai 或 anthropic)
        api_key_arg: 命令行指定的 API key
        api_base_arg: 命令行指定的 API base URL

    Returns:
        (api_key, api_base) 元组

    Raises:
        SystemExit: 如果未配置 API key
    """
    if provider == "openai":
        env_key = "OPENAI_API_KEY"
        env_base = "OPENAI_API_BASE"
    else:  # anthropic
        env_key = "ANTHROPIC_API_KEY"
        env_base = "ANTHROPIC_API_BASE"

    # API Key
    api_key = api_key_arg or os.environ.get(env_key)
    if not api_key:
        print(f"Error: 未配置 {provider.upper()} API Key")
        print("请通过以下方式之一指定:")
        print(f"  1. 使用 -api_key 参数: -api_key=\"your-key\"")
        print(f"  2. 设置环境变量: set {env_key}=your-key")
        sys.exit(1)

    # API Base (可选)
    api_base = api_base_arg or os.environ.get(env_base)

    return api_key, api_base


def check_pdb_exists(pe_path):
    """
    检查 PE 同目录下是否存在 PDB 文件

    Args:
        pe_path: PE 文件路径

    Returns:
        (exists, pdb_path) 元组
    """
    pe_dir = os.path.dirname(pe_path)

    # 检查常见的 PDB 文件名
    pdb_names = ["ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrla57.pdb"]
    for pdb_name in pdb_names:
        pdb_path = os.path.join(pe_dir, pdb_name)
        if os.path.exists(pdb_path):
            return True, pdb_path

    return False, None


def get_yaml_path(pe_path, func_name):
    """
    获取 YAML 输出文件的路径

    Args:
        pe_path: PE 文件路径
        func_name: 函数名

    Returns:
        YAML 文件路径
    """
    pe_dir = os.path.dirname(pe_path)
    return os.path.join(pe_dir, f"{func_name}.yaml")


def run_ida_disasm(ida_path, func_name, pe_path, debug=False):
    """
    调用 IDA 生成函数反汇编

    Args:
        ida_path: ida64.exe 路径
        func_name: 函数名
        pe_path: PE 文件路径
        debug: 是否启用调试输出

    Returns:
        生成的 YAML 文件路径

    Raises:
        SystemExit: 如果 IDA 执行失败
    """
    # 获取 ida.py 脚本路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ida_script = os.path.join(script_dir, "ida.py")

    if not os.path.exists(ida_script):
        print(f"Error: IDA 脚本不存在: {ida_script}")
        sys.exit(1)

    yaml_path = get_yaml_path(pe_path, func_name)

    # 构建 IDA 命令
    # 使用 -A 自主模式，-P 保存数据库
    script_arg = f'{ida_script} --func {func_name}'
    cmd = [
        ida_path,
        "-A",  # Autonomous mode
        "-P",  # Pack database and save
        f"-S{script_arg}",
        pe_path
    ]

    if debug:
        print(f"  执行命令: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 分钟超时
        )

        if debug:
            if result.stdout:
                print(f"  IDA stdout: {result.stdout[:500]}")
            if result.stderr:
                print(f"  IDA stderr: {result.stderr[:500]}")

        # 检查输出文件是否生成
        if not os.path.exists(yaml_path):
            print(f"Error: IDA 未能生成输出文件: {yaml_path}")
            print(f"  返回码: {result.returncode}")
            if result.stderr:
                print(f"  错误输出: {result.stderr}")
            sys.exit(1)

        return yaml_path

    except subprocess.TimeoutExpired:
        print(f"Error: IDA 执行超时 (10分钟)")
        sys.exit(1)
    except Exception as e:
        print(f"Error: IDA 执行失败: {e}")
        sys.exit(1)


def load_yaml_data(yaml_path):
    """
    加载完整的 YAML 数据

    Args:
        yaml_path: YAML 文件路径

    Returns:
        dict: YAML 文件中的所有数据，支持任意字段
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if data else {}


def format_xrefs(xrefs):
    """
    格式化 xrefs 列表为字符串

    Args:
        xrefs: xref 列表，每项为 {"address": "...", "instruction": "..."}

    Returns:
        格式化的字符串，如果 xrefs 为 None 则返回空字符串
    """
    if not xrefs:
        return ""

    lines = []
    for xref in xrefs:
        addr = xref.get("address", "")
        instr = xref.get("instruction", "")
        lines.append(f"{addr}: {instr}")
    return "\n".join(lines)


def format_prompt(template, ref_data, rev_data):
    """
    使用 YAML 数据格式化模板

    支持的占位符格式:
    - {reference.xxx} - reference YAML 中的 xxx 字段
    - {reverse.xxx} - reverse YAML 中的 xxx 字段

    例如:
    - {reference.procedure} - reference PE 的 procedure
    - {reference.disasm_code} - reference PE 的 disasm_code
    - {reference.xrefs} - reference PE 的 xrefs
    - {reference.virtualaddress} - reference PE 的 virtualaddress
    - {reverse.procedure} - reverse PE 的对应字段
    - ... 同理

    Args:
        template: 模板字符串
        ref_data: reference YAML 数据字典
        rev_data: reverse YAML 数据字典

    Returns:
        格式化后的 prompt 字符串
    """
    def get_field_value(data, field_name):
        """获取字段值，对于 xrefs 等特殊字段进行格式化"""
        value = data.get(field_name)
        if value is None:
            return ""
        # xrefs 是列表，需要特殊格式化
        if field_name == "xrefs" and isinstance(value, list):
            return format_xrefs(value)
        return str(value)

    def replace_placeholder(match):
        """替换占位符"""
        prefix = match.group(1)  # reference 或 reverse
        field = match.group(2)   # 字段名

        if prefix == "reference":
            return get_field_value(ref_data, field)
        elif prefix == "reverse":
            return get_field_value(rev_data, field)
        else:
            return match.group(0)  # 未知前缀，保持原样

    # 匹配 {reference.xxx} 或 {reverse.xxx} 格式的占位符
    pattern = r'\{(reference|reverse)\.(\w+)\}'
    return re.sub(pattern, replace_placeholder, template)


def extract_unmapped_symbols(procedure_text, disasm_code=None):
    """
    从反汇编代码中提取未映射的符号

    Args:
        procedure_text: procedure 文本（伪代码）
        disasm_code: disasm_code 文本（反汇编代码），可选

    Returns:
        未映射符号的集合 (sub_xxx, loc_xxx 等)
    """
    pattern = r'\b(sub_[0-9A-Fa-f]+|loc_[0-9A-Fa-f]+)\b'
    symbols = set()
    
    # 从 procedure 提取
    if procedure_text:
        symbols.update(re.findall(pattern, procedure_text))
    
    # 从 disasm_code 提取
    if disasm_code:
        symbols.update(re.findall(pattern, disasm_code))
    
    return symbols


def call_llm_for_mapping(prompt, provider, api_key, api_base, model, debug=False):
    """
    调用 LLM 获取符号映射

    Args:
        prompt: 格式化后的提示词
        provider: API 提供商 (openai 或 anthropic)
        api_key: API 密钥
        api_base: API 基础 URL
        model: 模型名称
        debug: 是否启用调试输出

    Returns:
        LLM 响应文本
    """
    if debug:
        print(f"  提供商: {provider}")
        print(f"  使用模型: {model}")
        print(f"  API Base: {api_base or '默认'}")

    if provider == "openai":
        return _call_openai(prompt, api_key, api_base, model, debug)
    else:  # anthropic
        return _call_anthropic(prompt, api_key, api_base, model, debug)


def _call_openai(prompt, api_key, api_base, model, debug=False):
    """调用 OpenAI API"""
    if not HAS_OPENAI:
        print("Error: openai 模块未安装")
        print("请先在仓库根目录运行: uv sync")
        sys.exit(1)

    # 构建客户端
    client_kwargs = {"api_key": api_key}
    if api_base:
        client_kwargs["base_url"] = api_base

    client = OpenAI(**client_kwargs)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a reverse engineering expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )

        return response.choices[0].message.content

    except Exception as e:
        print(f"Error: OpenAI API 调用失败: {e}")
        sys.exit(1)


def _call_anthropic(prompt, api_key, api_base, model, debug=False):
    """调用 Anthropic API"""
    if not HAS_ANTHROPIC:
        print("Error: anthropic 模块未安装")
        print("请先在仓库根目录运行: uv sync")
        sys.exit(1)

    # 构建客户端
    client_kwargs = {"api_key": api_key}
    if api_base:
        client_kwargs["base_url"] = api_base

    client = Anthropic(**client_kwargs)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "user", "content": prompt}
            ],
            system="You are a reverse engineering expert."
        )

        # Anthropic 返回的是 content 列表
        if response.content and len(response.content) > 0:
            return response.content[0].text
        return ""

    except Exception as e:
        print(f"Error: Anthropic API 调用失败: {e}")
        sys.exit(1)


def parse_llm_response(response_text):
    """
    解析 LLM 返回的 YAML 格式映射

    Args:
        response_text: LLM 响应文本

    Returns:
        映射字典 {unmapped_symbol: mapped_symbol}
    """
    # 提取 ```yaml ... ``` 代码块
    match = re.search(r'```(?:yaml)?\s*(.*?)\s*```', response_text, re.DOTALL)
    if match:
        yaml_text = match.group(1).strip()
    else:
        yaml_text = response_text.strip()

    if not yaml_text:
        return {}

    try:
        result = yaml.safe_load(yaml_text)
        return result if result else {}
    except yaml.YAMLError as e:
        print(f"Warning: YAML 解析失败: {e}")
        print(f"  原始响应: {response_text}")
        return {}


def get_symbol_mapping_path(pe_path):
    """
    获取 SymbolMapping.yaml 的路径

    Args:
        pe_path: PE 文件路径

    Returns:
        SymbolMapping.yaml 文件路径
    """
    pe_dir = os.path.dirname(pe_path)
    return os.path.join(pe_dir, "SymbolMapping.yaml")


def append_to_symbol_mapping(mapping_file, new_mappings):
    """
    追加映射到 SymbolMapping.yaml，去重处理

    Args:
        mapping_file: SymbolMapping.yaml 路径
        new_mappings: 新的映射字典

    Returns:
        (added_count, skipped_count) 元组
    """
    existing = {}
    if os.path.exists(mapping_file):
        with open(mapping_file, "r", encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}

    added_count = 0
    skipped_count = 0

    for key, value in new_mappings.items():
        if key not in existing:
            existing[key] = value
            print(f"  Added: {key} -> {value}")
            added_count += 1
        else:
            print(f"  Skipped (exists): {key}")
            skipped_count += 1

    with open(mapping_file, "w", encoding="utf-8") as f:
        yaml.dump(existing, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return added_count, skipped_count


def main():
    """主函数"""
    args = parse_args()

    func_name = args.func
    reference_pe = args.reference
    reverse_pe = args.reverse
    provider = args.provider
    debug = args.debug

    # 确定模型名称
    model = args.model or DEFAULT_MODELS[provider]

    print(f"[*] 函数名: {func_name}")
    print(f"[*] 参考版本: {reference_pe}")
    print(f"[*] 待分析版本: {reverse_pe}")
    print(f"[*] API 提供商: {provider}")
    print(f"[*] 模型: {model}")

    # 加载模板
    template = load_prompt_template(args.template)

    # 验证文件存在
    if not os.path.exists(reference_pe):
        print(f"Error: 参考 PE 文件不存在: {reference_pe}")
        sys.exit(1)

    if not os.path.exists(reverse_pe):
        print(f"Error: 待分析 PE 文件不存在: {reverse_pe}")
        sys.exit(1)

    # 检查 reference 的 PDB
    pdb_exists, pdb_path = check_pdb_exists(reference_pe)
    if not pdb_exists:
        print(f"Error: 参考版本缺少 PDB 文件")
        print(f"  请确保以下文件之一存在:")
        print(f"  - {os.path.join(os.path.dirname(reference_pe), 'ntkrnlmp.pdb')}")
        print(f"  - {os.path.join(os.path.dirname(reference_pe), 'ntoskrnl.pdb')}")
        print(f"  - {os.path.join(os.path.dirname(reference_pe), 'ntkrla57.pdb')}")
        sys.exit(1)

    print(f"[+] 找到 PDB: {pdb_path}")

    # 获取 IDA 路径
    ida_path = get_ida_path(args.ida)
    print(f"[+] IDA 路径: {ida_path}")

    # 获取 API 配置
    api_key, api_base = get_api_config(provider, args.api_key, args.api_base)
    print(f"[+] API 配置完成")

    # 处理 reference PE
    ref_yaml_path = get_yaml_path(reference_pe, func_name)
    if os.path.exists(ref_yaml_path):
        print(f"[*] 复用已有文件: {ref_yaml_path}")
    else:
        print(f"[*] 生成 reference 反汇编...")
        ref_yaml_path = run_ida_disasm(ida_path, func_name, reference_pe, debug)
        print(f"[+] 生成完成: {ref_yaml_path}")

    # 处理 reverse PE
    rev_yaml_path = get_yaml_path(reverse_pe, func_name)
    if os.path.exists(rev_yaml_path):
        print(f"[*] 复用已有文件: {rev_yaml_path}")
    else:
        print(f"[*] 生成 reverse 反汇编...")
        rev_yaml_path = run_ida_disasm(ida_path, func_name, reverse_pe, debug)
        print(f"[+] 生成完成: {rev_yaml_path}")

    # 读取 YAML 内容
    print(f"[*] 读取反汇编内容...")
    ref_data = load_yaml_data(ref_yaml_path)
    rev_data = load_yaml_data(rev_yaml_path)

    # 检查是否有需要映射的符号（从 procedure 和 disasm_code 中提取）
    unmapped_symbols = extract_unmapped_symbols(
        rev_data.get("procedure", ""),
        rev_data.get("disasm_code", "")
    )
    if not unmapped_symbols:
        print(f"[*] 待分析版本没有未映射的符号 (sub_xxx, loc_xxx)，无需处理")
        sys.exit(0)

    print(f"[*] 发现 {len(unmapped_symbols)} 个未映射符号: {', '.join(sorted(unmapped_symbols))}")

    # 格式化 prompt
    prompt = format_prompt(template, ref_data, rev_data)

    if debug:
        print(f"  格式化后的 prompt:\n{prompt[:500]}...")

    # 调用 LLM
    print(f"[*] 调用 LLM 进行符号映射...")
    llm_response = call_llm_for_mapping(
        prompt, provider, api_key, api_base, model, debug
    )

    if debug:
        print(f"  LLM 响应:\n{llm_response}")

    # 解析 LLM 响应
    mappings = parse_llm_response(llm_response)

    if not mappings:
        print(f"[*] LLM 未返回有效映射")
        sys.exit(0)

    print(f"[+] 获得 {len(mappings)} 个映射")

    # 追加到 SymbolMapping.yaml
    mapping_file = get_symbol_mapping_path(reverse_pe)
    print(f"[*] 更新映射文件: {mapping_file}")

    added, skipped = append_to_symbol_mapping(mapping_file, mappings)

    print(f"\n{'='*50}")
    print(f"Summary: {added} 条新增, {skipped} 条跳过 (已存在)")
    print(f"映射文件: {mapping_file}")


if __name__ == "__main__":
    main()
