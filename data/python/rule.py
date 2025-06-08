#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re

# ==== 配置区 ====
INPUT_FILE = '.././rules.txt'      # 规则来源文件
OUTPUT_FILE = '.././merged_rules.txt'  # 合并输出的规则文件
HOMEPAGE = "https://github.com/qq5460168/AD886"
AUTHOR = "酷安@那个谁520"

# ==== 工具函数 ====
def log(msg):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")

def is_valid_ad_rule(line):
    """
    检查广告屏蔽规则是否符合格式：
    必须以 "||" 开头，以 "^" 结尾，长度大于3。
    """
    return line.startswith("||") and line.endswith("^") and len(line) > 3

def is_valid_whitelist_rule(line):
    """
    检查白名单规则是否符合正确格式：
    正确格式应为：@@||域名^ 或 @@||域名^$options，不允许存在额外 "|" 符号。
    """
    pattern = r"^@@\|\|[^|]+\^(?:\$.*)?$"
    return re.match(pattern, line) is not None

def correct_whitelist_rule(line):
    """
    自动优化并修正错误的白名单规则格式：
      1. 如果不以 '@@||' 开头，则修正为 '@@||'
      2. 去除规则中 '^' 前多余的 "|" 符号
    """
    original = line
    if not line.startswith("@@||"):
        if line.startswith("@@|"):
            line = line.replace("@@|", "@@||", 1)
        else:
            line = "@@||" + line[2:]
    # 将结尾处多余的 "|" 去除（例如：@@||ads.adsterra.com^| 变为 @@||ads.adsterra.com^）
    m = re.match(r'(@@\|\|.+?)(\|+)(\^.*)$', line)
    if m:
        line = m.group(1) + m.group(3)
    return line

def extract_ad_domain(line):
    """
    从广告规则中提取域名部分，假定规则格式为 "||域名^"
    """
    return line[2:-1]

# ==== 合并规则 ====
def merge_rules(input_path):
    """
    读取输入文件中的所有规则，对白名单规则直接进行修正，
    分别收集广告屏蔽域名和修正后的白名单规则，然后合并后返回
    """
    if not os.path.exists(input_path):
        log(f"输入文件不存在: {input_path}")
        return None

    ad_domains = set()
    whitelist_rules = set()
    with open(input_path, 'r', encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue  # 跳过空行

            # 针对白名单规则处理（以 "@@" 开头）
            if line.startswith("@@"):
                fixed = correct_whitelist_rule(line)
                if not is_valid_whitelist_rule(fixed):
                    log(f"白名单规则修正后格式仍不正确: 原[{line}] 修正为[{fixed}]")
                else:
                    if line != fixed:
                        log(f"自动修正白名单规则: 原[{line}] 修正为[{fixed}]")
                    else:
                        log(f"白名单规则格式正确: {fixed}")
                whitelist_rules.add(fixed)
                continue

            # 跳过含有错误标记的规则（例如 "m^$important"）
            if "m^$important" in line:
                log(f"跳过错误规则: {line}")
                continue

            # 检查广告过滤规则
            if is_valid_ad_rule(line):
                domain = extract_ad_domain(line)
                ad_domains.add(domain)
                # 输出日志可选：log(f"有效广告规则: {line}")
            else:
                log(f"无效规则: {line}")

    return ad_domains, whitelist_rules

def write_merged_rules(output_path, ad_domains, whitelist_rules):
    """
    将广告过滤规则和白名单规则合并后输出到一个文件中。
    输出文件第一部分为广告过滤规则，后续为白名单规则。
    """
    with open(output_path, 'w', encoding="utf-8") as f:
        # 写入广告屏蔽规则
        f.write(f"# 广告屏蔽规则 (总计 {len(ad_domains)})\n")
        for domain in sorted(ad_domains):
            # 使用统一格式：||域名^
            f.write(f"||{domain}^\n")
        f.write("\n")
        # 写入白名单规则
        f.write(f"# 白名单规则 (总计 {len(whitelist_rules)})\n")
        for rule in sorted(whitelist_rules):
            f.write(f"{rule}\n")
    log(f"合并规则写入成功: {output_path}")

def main():
    result = merge_rules(INPUT_FILE)
    if result is None:
        return
    ad_domains, whitelist_rules = result
    log(f"读取到广告规则 {len(ad_domains)} 条，白名单规则 {len(whitelist_rules)} 条")
    write_merged_rules(OUTPUT_FILE, ad_domains, whitelist_rules)
    log("规则合并完毕。")

if __name__ == "__main__":
    main()