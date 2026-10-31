#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
title.py — 为合并生成的成品规则文件补充统一头部（修复/优化版）

相对原仓库（data/python/title.py）的修复点：
  1. 路径解析不再依赖“当前运行目录”
     原版用 open('../rules.txt')，相对的是执行命令时的 CWD：
     · 在仓库根目录运行 python3 data/python/title.py 时，../rules.txt
       会解析到仓库的“上一级目录”，文件不存在；
     · 而脚本遇到 FileNotFoundError 直接 continue，退出码仍为 0，
       表现为“不生效却毫无报错”。
     本版改为基于脚本自身位置解析仓库根目录
     （Path(__file__).resolve().parents[2]），从任何目录运行都能命中。

  2. 去掉对 pytz 的硬依赖
     原版 import pytz，环境未装会直接 ModuleNotFoundError 崩溃。
     本版优先用标准库 zoneinfo（Python 3.9+），拿不到再回退 pytz，
     最后用系统本地时间兜底；不再需要额外安装第三方包。

  3. 不再静默吞掉文件缺失
     原版 except FileNotFoundError: continue 把“没找到文件”藏了起来。
     本版对缺失文件打印明确提示（但仍跳过不报错，便于批量场景），
     真正读写 IO 错误会抛出，避免“假成功”。

  4. 头部内容集中为 HEADER_TEMPLATE 常量，便于按需对齐
     默认输出你要的“原版”头部（! Title: 酷安广告规则 / Homepage: AD886）。
     若想恢复仓库原有的“个人合并 2.0”头部，改这一处即可。

  5. 规则条数只统计有效规则行（跳过 ! / # 注释行与空行）
     新版 rules.txt / allow.txt 头部含 merge.py 写入的来源分区注释
     （! 📋 规则来源：… / ! 🔗 原始地址：…），旧版按总行数统计会把
     注释块计入 Total count，导致 README 数字虚高。
"""
from pathlib import Path

# 仓库根目录 = 从脚本文件(data/python/title.py)向上数 3 层:
# data/python -> data -> 仓库根
REPO_ROOT = Path(__file__).resolve().parents[2]

# 要补头部的成品文件（相对仓库根目录；不存在时自动跳过）
FILE_LIST = ['rules.txt', 'allow.txt']

# 已带头部则跳过的标记（命中任一即跳过，防止重复套标题）
HEADER_MARKS = ('[Adblock Plus', '[个人合并', '! Title', '# Title', '# AdClose')

# 头部模板（占位符：{version}=北京时间，{count}=规则条数）。
# 默认对齐你要求恢复的“原版”头部；要改回仓库原样“个人合并 2.0”就替换本常量。
HEADER_TEMPLATE = (
    "! Title: 酷安广告规则\n"
    "! Homepage: https://github.com/qq5460168/AD886\n"
    "! by: 酷安@那个谁520\n"
    "! Last Updated: {version}（北京时间）\n"
    "! Total count: {count}\n"
)


def beijing_time() -> str:
    """返回北京时间字符串 YYYY-MM-DD HH:MM:SS（尽量不依赖第三方包）。"""
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo  # Python 3.9+
        return datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    try:
        from datetime import datetime
        import pytz
        return datetime.now(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 系统本地时间兜底


def has_header(content: str) -> bool:
    """判断内容是否已带头部标记。"""
    return content.lstrip().startswith(HEADER_MARKS)


def count_rules(content: str) -> int:
    """统计有效规则行数（跳过空行与 ! / # 注释行）。"""
    n = 0
    for line in content.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(('!', '#')):
            continue
        n += 1
    return n


def add_title(file_path: Path) -> str:
    """为单个文件补头部，返回状态描述。"""
    if not file_path.exists():
        return f"[跳过] 不存在: {file_path}"

    content = file_path.read_text(encoding='utf-8')
    if has_header(content):
        return f"[跳过] 已带头部: {file_path.name}"

    # 清理文件开头的空行（部分成品文件以 CRLF 空行开头），避免头部后留空行
    content = content.lstrip('\r\n')
    count = count_rules(content)
    header = HEADER_TEMPLATE.format(version=beijing_time(), count=count)
    file_path.write_text(header + content, encoding='utf-8')
    return f"[已更新] {file_path.name}: 头部 {len(header.splitlines())} 行 + 规则 {count} 行"


def main() -> int:
    print(f"仓库根目录: {REPO_ROOT}")
    print(f"时间: {beijing_time()}（北京时间）")
    changed = 0
    for name in FILE_LIST:
        status = add_title(REPO_ROOT / name)
        print(status)
        if status.startswith('[已更新]'):
            changed += 1
    print(f"完成，共更新 {changed} 个文件。")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
