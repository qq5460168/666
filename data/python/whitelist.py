#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re
from pathlib import Path

# 配置
ALLOW_SOURCE = "../allow.txt"  # 源文件：包含@@||域名^格式的规则
OUTPUT_FILE = "../allow-ublock.txt"  # 输出文件：纯域名格式
HOMEPAGE = "https://github.com/qq5460168/666"
TIME_STR = datetime.datetime.now().astimezone(
    datetime.timezone(datetime.timedelta(hours=8))
).strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）'

def log(msg):
    """日志输出函数"""
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")

def extract_domain_from_rule(rule):
    """
    从uBlock规则中提取纯域名
    规则格式：@@||域名^ -> 提取为 域名
    """
    # 清除前后空白
    rule = rule.strip()
    
    # 跳过注释和空行
    if not rule or rule.startswith(('#', '!')):
        return None
    
    # 匹配uBlock白名单规则格式 @@||domain^
    pattern = r'^@@\|\|([a-zA-Z0-9-_.]+\.[a-zA-Z]{2,})\^$'
    match = re.match(pattern, rule)
    
    if match:
        return match.group(1).lower()  # 返回小写域名
    else:
        return None  # 不是标准格式的规则

def convert_whitelist_rules():
    """将allow.txt中的规则转换为纯域名格式"""
    # 检查源文件是否存在
    if not os.path.exists(ALLOW_SOURCE):
        log(f"错误：源文件不存在 {ALLOW_SOURCE}")
        return False

    # 读取并转换规则
    domains = set()
    invalid_rules = []
    line_number = 0

    with open(ALLOW_SOURCE, 'r', encoding='utf-8') as f:
        for line in f:
            line_number += 1
            domain = extract_domain_from_rule(line)
            
            if domain:
                domains.add(domain)
            elif line.strip() and not line.strip().startswith(('#', '!')):
                # 记录无效规则（非注释且非空行）
                invalid_rules.append(f"第{line_number}行: {line.strip()}")

    # 输出无效规则警告
    if invalid_rules:
        log(f"警告：发现{len(invalid_rules)}条无效规则，已跳过")
        for rule in invalid_rules:
            log(f"  {rule}")

    # 生成纯域名白名单内容
    header = [
        "# 纯域名白名单",
        f"# 来源: {ALLOW_SOURCE}",
        f"# 生成时间: {TIME_STR}",
        f"# 总域名数: {len(domains)}",
        f"# 项目主页: {HOMEPAGE}",
        ""
    ]
    
    # 按字母顺序排序域名
    content = '\n'.join(header + sorted(domains))

    # 写入输出文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(content)
    
    log(f"已成功转换 {len(domains)} 个域名到 {OUTPUT_FILE}")
    return True

if __name__ == "__main__":
    convert_whitelist_rules()
