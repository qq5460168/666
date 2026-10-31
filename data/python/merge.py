#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
merge.py — 按来源分区块合并黑名单( rules.txt )与白名单( allow.txt )

设计思路（参考 xiaolei7172/ADS 的 merge.py）：
  - 每个上游文件在下载阶段已被 update-rules.sh 写入来源头：
        ! 📋 规则来源：{来源名}
        ! 🔗 原始地址：{URL}
  - 本脚本按来源逐个读取 tmp/rules*.txt 与 tmp/allow*.txt，
    只把「该来源带来的新规则」写入对应分区；每个分区前输出
    来源头（来源名 + 原始地址 + 规则说明），实现：
        「每条规则都能一步定位所属上游来源」。
  - 去重为跨来源全局去重（先到先得）：同一规则首次出现的来源
    保留，后续来源的重复规则不输出，保证总条数与旧版
    `cat rules*.txt | sort -u` 一致（MISSING=0）。
  - 保留旧版 error.txt 整行精确剔除逻辑（同时作用于 rules 与 allow）。

依赖说明：update-rules.sh 下载后会为每个文件头部写入
  `! 📋 规则来源：xxx` / `! 🔗 原始地址：yyy`，
  并在 tmp 目录生成 src_index（文件名<TAB>来源名<TAB>原始URL）。
  本脚本以 src_index 为准获取来源信息；缺失时回退为从文件头解析。

输出：
  - 仓库根 rules.txt（黑名单，带来源分区头）
  - 仓库根 allow.txt（白名单，带来源分区头）
"""
import os
import sys
import re
from collections import OrderedDict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))
TMP_DIR = os.path.join(REPO_ROOT, "tmp")
ERROR_FILE = os.path.join(REPO_ROOT, "data", "rules", "error.txt")
SRC_INDEX = os.path.join(TMP_DIR, "src_index")

# 来源头标记（下载阶段由 update-rules.sh 写入）
RE_SRC = re.compile(r"^!\s*📋\s*规则来源：\s*(.+?)\s*$")
RE_URL = re.compile(r"^!\s*🔗\s*原始地址：\s*(.+?)\s*$")

SEP = "! =============================================="


def log(msg):
    print(f"[merge.py] {msg}")


def read_src_index():
    """读取 tmp/src_index（文件名<TAB>来源名<TAB>URL），返回 {文件名: (来源名, URL)}"""
    mapping = {}
    if not os.path.exists(SRC_INDEX):
        log(f"警告: 未找到 {SRC_INDEX}，将回退为从文件头解析来源")
        return mapping
    with open(SRC_INDEX, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                fname = parts[0]
                name = parts[1]
                url = parts[2] if len(parts) > 2 else ""
                mapping[fname] = (name, url)
    return mapping


def parse_file_header(path):
    """从文件头部解析来源名与原始地址（回退方案）"""
    name, url = "未知来源", ""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                m = RE_SRC.match(line)
                if m:
                    name = m.group(1)
                m = RE_URL.match(line)
                if m:
                    url = m.group(1)
    except OSError:
        pass
    return name, url


def get_source(path, src_index):
    fname = os.path.basename(path)
    if fname in src_index:
        return src_index[fname]
    return parse_file_header(path)


def collect_black_files():
    """收集黑名单上游文件（rulesN.txt），按文件名字典序排序

    与旧版 `cat rules*.txt` 的 shell 通配排序一致
    （rules0.txt < rules01.txt < rules1.txt < rules2.txt ...），
    保证「先到先得」去重归属与旧行为相同。
    """
    files = []
    for name in os.listdir(TMP_DIR):
        if re.match(r"^rules\d+\.txt$", name):
            files.append(os.path.join(TMP_DIR, name))
    return sorted(files)


def collect_allow_files():
    """收集白名单上游文件（allowN.txt），按文件名字典序排序"""
    files = []
    for name in os.listdir(TMP_DIR):
        if re.match(r"^allow\d+\.txt$", name):
            files.append(os.path.join(TMP_DIR, name))
    return sorted(files)


def is_comment(line):
    s = line.strip()
    return not s or s.startswith(("#", "!", "["))


def merge_black(src_index):
    """黑名单按来源分区块合并（跨来源全局去重，先到先得）"""
    black_set = set()
    sections = OrderedDict()  # 来源名 -> {"header": [...], "rules": [...]}

    files = collect_black_files()
    log(f"发现黑名单上游文件 {len(files)} 个")
    for path in files:
        src_name, src_url = get_source(path, src_index)
        header = [SEP, f"! 📋 规则来源：{src_name}",
                  f"! 🔗 原始地址：{src_url}", SEP]
        new_rules = []
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                if is_comment(line):
                    continue
                rule = line.strip()
                if not rule:
                    continue
                key = rule.lower()
                if key not in black_set:
                    black_set.add(key)
                    new_rules.append(rule)
        if new_rules:
            sections.setdefault(src_name, {"header": header, "rules": []})
            sections[src_name]["rules"].extend(new_rules)

    # 应用 error.txt 整行精确剔除
    err_set = read_error_rules()
    final_sections = OrderedDict()
    removed = 0
    for name, sec in sections.items():
        kept = [r for r in sec["rules"] if r not in err_set]
        removed += len(sec["rules"]) - len(kept)
        if kept:
            final_sections[name] = {"header": sec["header"], "rules": kept}
    if removed:
        log(f"error.txt 排除: 黑名单剔除 {removed} 条")

    out = []
    total = 0
    for name, sec in final_sections.items():
        out.extend(sec["header"])
        out.extend(sec["rules"])
        total += len(sec["rules"])
    return out, total, len(final_sections)


def merge_allow(src_index):
    """白名单按来源分区块合并

    与旧版一致：从「全部上游文件」(rules*.txt 与 allow*.txt) 中
    提取 @@|| 开头的白名单行；跨来源全局去重，先到先得。
    """
    allow_set = set()
    sections = OrderedDict()

    all_files = collect_black_files() + collect_allow_files()
    log(f"白名单来源候选文件 {len(all_files)} 个")
    for path in all_files:
        src_name, src_url = get_source(path, src_index)
        header = [SEP, f"! 📋 规则来源：{src_name}",
                  f"! 🔗 原始地址：{src_url}", SEP]
        new_rules = []
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s.startswith("@@"):
                    continue
                if not re.match(r"^@@\|\|.*\^(\$important)?$", s):
                    continue
                if s in allow_set:
                    continue
                allow_set.add(s)
                new_rules.append(s)
        if new_rules:
            sections.setdefault(src_name, {"header": header, "rules": []})
            sections[src_name]["rules"].extend(new_rules)

    err_set = read_error_rules()
    final_sections = OrderedDict()
    removed = 0
    for name, sec in sections.items():
        kept = [r for r in sec["rules"] if r not in err_set]
        removed += len(sec["rules"]) - len(kept)
        if kept:
            final_sections[name] = {"header": sec["header"], "rules": kept}
    if removed:
        log(f"error.txt 排除: 白名单剔除 {removed} 条")

    out = []
    total = 0
    for name, sec in final_sections.items():
        out.extend(sec["header"])
        out.extend(sec["rules"])
        total += len(sec["rules"])
    return out, total, len(final_sections)


def read_error_rules():
    """读取 data/rules/error.txt：忽略空行与 # 注释行，返回整行精确剔除集合

    utf-8-sig 容错：Windows 上写出的 error.txt 常带 UTF-8 BOM，
    用 utf-8 读取会把 BOM 残留在第一行导致匹配失败。
    """
    err = set()
    if not os.path.exists(ERROR_FILE):
        return err
    with open(ERROR_FILE, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            err.add(s)
    return err


def main():
    log(f"仓库根目录: {REPO_ROOT}")
    src_index = read_src_index()
    log(f"来源映射: {len(src_index)} 项")

    black_out, black_total, black_secs = merge_black(src_index)
    rules_path = os.path.join(REPO_ROOT, "rules.txt")
    with open(rules_path, "w", encoding="utf-8") as f:
        f.write("\n".join(black_out) + ("\n" if black_out else ""))
    log(f"黑名单: {black_total} 条 / {black_secs} 个来源 -> rules.txt")

    allow_out, allow_total, allow_secs = merge_allow(src_index)
    allow_path = os.path.join(REPO_ROOT, "allow.txt")
    with open(allow_path, "w", encoding="utf-8") as f:
        f.write("\n".join(allow_out) + ("\n" if allow_out else ""))
    log(f"白名单: {allow_total} 条 / {allow_secs} 个来源 -> allow.txt")


if __name__ == "__main__":
    main()
