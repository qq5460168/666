#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
此脚本用于生成多种主流规则格式，包括 Clash Meta、Quantumult X、SingBox、
Shadowrocket、Invizible Pro 和 AdClose 规则。
使用方式：
    python filter-dns.py source_rules.txt
其中 source_rules.txt 为包含原始规则列表的文本文件，每一行一条规则，
可包含注释行（以 # 开头）或空行，将自动过滤掉这些行。
"""

import os
import sys

def read_rules(file_path):
    """
    读取源规则文件：
    - 过滤掉空行和以 '#' 开头的注释行。
    - 去除重复的规则并排序。
    """
    with open(file_path, "r", encoding="utf8") as f:
        # 读取所有非空且不以#开始的行
        rules = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    # 使用 set 去重后进行排序
    return sorted(set(rules))

def write_rules(file_path, header, rules):
    """
    将规则写入到指定文件中，文件内容第一行为 header，其后每一行一条规则。
    """
    with open(file_path, "w", encoding="utf8") as f:
        f.write(header + "\n")
        for rule in rules:
            f.write(rule + "\n")

def generate_clash_meta_rules(rules):
    """
    生成 Clash Meta 格式规则：
    格式示例：  - 'example.com'
    """
    return ["  - '{}'".format(rule) for rule in rules]

def generate_quantumult_x_rules(rules):
    """
    生成 Quantumult X 格式规则：
    格式示例： HOST-SUFFIX,example.com,REJECT
    """
    return ["HOST-SUFFIX,{},REJECT".format(rule) for rule in rules]

def generate_singbox_rules(rules):
    """
    生成 SingBox 格式规则：
    格式示例（与 Quantumult X 类似）： DOMAIN-SUFFIX,example.com,REJECT
    """
    return ["DOMAIN-SUFFIX,{},REJECT".format(rule) for rule in rules]

def generate_shadowrocket_rules(rules):
    """
    生成 Shadowrocket 格式规则：
    格式示例： DOMAIN-SUFFIX,example.com,REJECT
    """
    return ["DOMAIN-SUFFIX,{},REJECT".format(rule) for rule in rules]

def generate_invizible_rules(rules):
    """
    生成 Invizible Pro 格式规则:
    格式较为简单，只需要列出规则即可。
    """
    return rules

def generate_adclose_rules(rules):
    """
    生成 AdClose 格式规则:
    格式示例： domain, example.com
    """
    return ["domain, {}".format(rule) for rule in rules]

def main():
    if len(sys.argv) < 2:
        print("Usage: {} source_rules.txt".format(sys.argv[0]))
        sys.exit(1)
    
    source_file = sys.argv[1]
    rules = read_rules(source_file)
    
    # 创建输出目录
    output_dir = "output_rules"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 生成 Clash Meta 规则并写入文件
    clash_meta = generate_clash_meta_rules(rules)
    write_rules(os.path.join(output_dir, "clash_meta.txt"), "# Clash Meta Rules", clash_meta)
    
    # 生成 Quantumult X 规则并写入文件
    quantumult_x = generate_quantumult_x_rules(rules)
    write_rules(os.path.join(output_dir, "quantumult_x.txt"), "# Quantumult X Rules", quantumult_x)
    
    # 生成 SingBox 规则并写入文件
    singbox = generate_singbox_rules(rules)
    write_rules(os.path.join(output_dir, "singbox.txt"), "# SingBox Rules", singbox)
    
    # 生成 Shadowrocket 规则并写入文件
    shadowrocket = generate_shadowrocket_rules(rules)
    write_rules(os.path.join(output_dir, "shadowrocket.txt"), "# Shadowrocket Rules", shadowrocket)
    
    # 生成 Invizible Pro 规则并写入文件
    invizible = generate_invizible_rules(rules)
    write_rules(os.path.join(output_dir, "invizible.txt"), "# Invizible Pro Rules", invizible)
    
    # 生成 AdClose 规则并写入文件
    adclose = generate_adclose_rules(rules)
    write_rules(os.path.join(output_dir, "adclose.txt"), "# AdClose Rules", adclose)
    
    print("各格式规则生成成功，存放在目录：{}".format(output_dir))

if __name__ == "__main__":
    main()