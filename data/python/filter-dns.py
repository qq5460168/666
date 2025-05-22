#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import datetime
import json
import logging
import os
import sys

# 配置 logging 模块，用于记录程序运行状态和调试信息
logging.basicConfig(
    level=logging.INFO,  # 设置日志级别为 INFO
    format='[%(asctime)s] %(levelname)s: %(message)s',  # 日志输出格式
    datefmt='%Y-%m-%d %H:%M:%S'  # 时间格式
)
logger = logging.getLogger(__name__)

# ==== 配置区 ====

def get_time_str():
    """
    获取当前时间的字符串表示，并追加(北京时间)字样
    """
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）'

def get_rule_formats(time_str):
    """
    根据当前时间字符串 time_str 返回各个规则格式的配置。
    已取消全局的主页和作者信息，因此 header 中不包含相关信息。
    每个配置包括：名称、输出文件路径、生成文件头的 lambda 函数和生成一行规则的 lambda 函数
    """
    return [
        {
            "name": "dns",
            "file": ".././dns.txt",
            "header": lambda total: [
                "[Adblock Plus 2.0]",
                f"! Title: 酷安反馈反馈",
                f"! Total Count: {total}",
                f"! Update Time: {time_str}"
            ],
            "line": lambda domain: f"||{domain}^"  # Adblock Plus 规则格式
        },
        {
            "name": "hosts",
            "file": ".././hosts.txt",
            "header": lambda total: [
                "# Title: Hosts Rules",
                f"# Update Time: {time_str}"
            ],
            "line": lambda domain: f"0.0.0.0 {domain}"  # Hosts 文件格式
        },
        {
            "name": "qx",
            "file": ".././qx.list",
            "header": lambda total: [
                "# Title: Quantumult X Rules",
                f"# Update Time: {time_str}"
            ],
            "line": lambda domain: f"HOST-SUFFIX,{domain},REJECT"  # Quantumult X 格式
        },
        {
            "name": "shadowrocket",
            "file": ".././Shadowrocket.list",
            "header": lambda total: [
                "# Title: Shadowrocket Rules",
                f"# Update Time: {time_str}"
            ],
            "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"  # Shadowrocket 格式
        },
        {
            "name": "adclose",
            "file": ".././AdClose.txt",
            "header": lambda total: [
                "# AdClose 专用广告规则",
                "# 格式：domain, <域名>",
                f"# 生成时间: {time_str}"
            ],
            "line": lambda domain: f"domain, {domain}"  # AdClose 格式规则
        },
        {
            "name": "singbox_srs",
            "file": ".././singbox.srs",
            "header": lambda total: [
                "# Title: SingBox SRS Rules",
                f"# Update Time: {time_str}"
            ],
            "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"  # SingBox (SRS) 格式规则
        },
        {
            "name": "singbox_json",
            "file": ".././Singbox.json",
            "header": None,  # 使用 json 模块生成，不需要 header
            "line": None    # 不需要 line 配置
        },
        {
            "name": "invizible",
            "file": ".././invizible.txt",
            "header": lambda total: [
                "# Title: Invizible Pro Rules",
                f"# Update Time: {time_str}"
            ],
            "line": lambda domain: f"{domain}"  # Invizible 格式，直接输出域名
        },
        {
            "name": "clash",
            "file": ".././clash.yaml",
            "header": lambda total: [
                "# Title: Clash Rules",
                f"# Update Time: {time_str}"
            ],
            "line": lambda domain: f"  - DOMAIN-SUFFIX,{domain},REJECT"  # Clash 格式，前面有两个空格和破折号
        },
        {
            "name": "clash_meta",
            "file": ".././clash_meta.yaml",
            "header": lambda total: [
                "# Clash Meta 专用规则 (简化域名列表格式)",
                f"# 生成时间: {time_str}",
                "payload:"
            ],
            "line": lambda domain: f"  - '{domain}'"  # Clash Meta 格式，以单引号包裹域名
        }
    ]

# ==== 核心逻辑 ====

def is_valid_ad_line(line):
    """
    判断规则行是否符合 Adblock Plus 格式：
    - 必须以 "||" 开头
    - 以 "^" 结尾
    - 且长度应大于 3 个字符
    """
    return line.startswith("||") and line.endswith("^") and len(line) > 3

def extract_domain(line):
    """
    从有效的规则行中提取出域名字符串
    去除前缀 "||" 和后缀 "^"
    """
    return line[2:-1]

def read_domains(input_path):
    """
    读取源规则文件并返回一个包含所有有效域名的列表
    - 忽略包含 "m^$important" 的行（认为是错误规则）
    - 通过 is_valid_ad_line 判断一行是否为有效规则
    """
    domains = []
    try:
        with open(input_path, 'r', encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # 如果包含错误规则标识，则跳过当前行
                if "m^$important" in line:
                    logger.warning(f"跳过错误规则: {line}")
                    continue
                if is_valid_ad_line(line):
                    domains.append(extract_domain(line))
    except Exception as e:
        logger.error(f"读取文件时出错: {e}")
        sys.exit(1)  # 出现错误则退出程序
    return domains

def write_singbox_json(fname, domains, time_str):
    """
    使用 json 模块生成 Singbox JSON 格式规则文件
    文件内容包括规则名称、类型、规则列表及更新时间（不包含主页和作者信息）
    """
    payload = {
        "name": "Singbox Ads Rule",
        "type": "domain",
        "payload": domains,
        "update_time": time_str,
    }
    try:
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        logger.info(f"生成 {fname} (Singbox JSON)")
    except Exception as e:
        logger.error(f"写入文件 {fname} 时出错: {e}")

def write_rule_file(format_conf, domains, time_str):
    """
    根据给定的规则格式配置生成对应的规则文件：
    - 如果格式名称为 "singbox_json"，调用 write_singbox_json 生成 JSON 文件；
    - 否则先生成头信息再逐行写入规则
    """
    fname = format_conf["file"]
    if format_conf["name"] == "singbox_json":
        write_singbox_json(fname, domains, time_str)
        return

    try:
        with open(fname, "w", encoding="utf-8") as f:
            # 生成文件头信息
            header = format_conf["header"](len(domains))
            for h in header:
                f.write(h + '\n')
            # 为每个域名生成一行规则并写入文件
            for domain in domains:
                f.write(format_conf["line"](domain) + '\n')
        logger.info(f"生成 {fname}")
    except Exception as e:
        logger.error(f"写入文件 {fname} 时出错: {e}")

def main():
    """
    脚本主入口：
    - 解析命令行参数，获取源规则文件路径
    - 获取当前时间字符串并生成各规则格式配置
    - 读取并过滤源规则文件中的有效域名
    - 遍历各规则格式，生成对应的规则文件
    """
    parser = argparse.ArgumentParser(description='生成多种广告规则格式')
    parser.add_argument('--input', type=str, default='.././rules.txt', help='源规则文件路径')
    args = parser.parse_args()

    time_str = get_time_str()
    rule_formats = get_rule_formats(time_str)

    if not os.path.exists(args.input):
        logger.error(f"源规则文件不存在: {args.input}")
        sys.exit(1)

    # 使用 set 去重后对域名进行排序
    domains = sorted(set(read_domains(args.input)))
    if not domains:
        logger.warning("没有读取到有效的域名。")
    # 生成所有配置格式的规则文件
    for fmt in rule_formats:
        write_rule_file(fmt, domains, time_str)

    logger.info("全部规则已生成。")

if __name__ == "__main__":
    main()