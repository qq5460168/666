#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import os
import re
import requests
import json
import logging
import socket
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
CONFIG = {
    "RULE_SOURCES_FILE": "sources.txt",  # 规则来源文件
    "OUTPUT_FILE": "merged-filter.txt",  # 输出文件
    "STATS_FILE": "rule_stats.json",     # 统计信息输出文件
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules",             # 输出文件标题
    "VERSION": "1.0.0",                  # 版本号
    "MAX_WORKERS": 5                     # 并发下载最大线程数
}

# 国内和国外 DNS 服务列表
DNS_SERVERS = {
    "domestic": ["114.114.114.114", "223.5.5.5", "119.29.29.29"],
    "international": ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
}

# 正则表达式模块，用于识别不同类型的规则
REGEX_PATTERNS = {
    "blank": re.compile(r"^\s*$"),  # 空行
    "domain": re.compile(r"^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?"),  # 域名规则
    "element": re.compile(r"##.+"),  # 元素过滤规则
    "regex_rule": re.compile(r"^/.*/$"),  # 正则表达式规则
    "modifier": re.compile(r"\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$")
}

# 配置日志输出格式
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)

# ------------------- 工具函数 -------------------

def resolve_domain(domain, dns_servers):
    """
    使用指定的 DNS 服务器解析域名。
    如果域名在所有 DNS 服务中均无法解析，则返回 False。
    """
    for dns in dns_servers:
        try:
            # 使用 socket 库解析域名
            resolver = socket.getaddrinfo(domain, None, 0, 0, 0, socket.AI_ADDRCONFIG)
            if resolver:
                return True  # 成功解析
        except socket.gaierror:
            continue
    return False  # 无法解析

def filter_unresolvable_domains(rules, dns_servers):
    """
    过滤掉规则中无法解析的域名。
    参数:
        rules: 合并后的规则列表
        dns_servers: DNS 服务列表
    返回:
        仅包含可解析域名的规则列表
    """
    resolvable_rules = []
    for rule in rules:
        domain = extract_domain(rule)  # 提取域名
        if resolve_domain(domain, dns_servers["domestic"]) or resolve_domain(domain, dns_servers["international"]):
            resolvable_rules.append(rule)
        else:
            log.warning(f"无法解析域名，已跳过: {domain}")
    return resolvable_rules

def is_comment_line(line):
    """
    判断是否为备注信息。
    """
    line = line.strip()
    return (line.startswith("#") or line.startswith("!")) and re.search(r"[\u4e00-\u9fff]", line)

def is_valid_rule(line):
    """
    判断规则是否合法。
    """
    if is_comment_line(line) or REGEX_PATTERNS["blank"].match(line):
        return False
    return (REGEX_PATTERNS["domain"].match(line) or 
            REGEX_PATTERNS["element"].search(line) or 
            REGEX_PATTERNS["regex_rule"].match(line) or 
            REGEX_PATTERNS["modifier"].search(line))

def fix_rule(rule):
    """
    修复规则语法。
    """
    rule = rule.strip().strip("|")
    rule = rule.replace("https://", "").replace("http://", "")
    if rule.startswith("@@") and not rule.startswith("@@||"):
        rule = "@@||" + rule[2:]
    return rule

def extract_domain(rule):
    """
    从规则中提取域名部分。
    """
    if rule.startswith("@@||"):
        rule = rule[4:]
    elif rule.startswith("||"):
        rule = rule[2:]
    m = re.match(r"([^/\^\s]+)", rule)
    return m.group(1) if m else rule

def fetch_rules(source):
    """
    从指定来源下载或读取规则内容。
    """
    valid_rules = []
    invalid_rules = []
    try:
        if source.startswith("file:"):
            file_path = source.split("file:")[1].strip()
            with open(file_path, "r", encoding="utf8") as f:
                lines = f.readlines()
        else:
            response = requests.get(source, headers={"User-Agent": CONFIG["USER_AGENT"]}, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
        for line in map(str.strip, lines):
            if is_valid_rule(line):
                valid_rules.append(line)
            elif line:
                invalid_rules.append(line)
    except requests.RequestException as e:
        log.error(f"下载失败: {source} - {e}")
    except FileNotFoundError:
        log.error(f"本地文件未找到: {source}")
    except Exception as e:
        log.error(f"未知错误: {source} - {e}")
    return valid_rules, invalid_rules

# ------------------- 主程序逻辑 -------------------

def process_sources(sources):
    """
    并发处理所有规则来源。
    """
    merged_rules = set()
    error_reports = {}
    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        future_to_source = {executor.submit(fetch_rules, s): s for s in sources}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                valid_rules, invalid_rules = future.result()
                fixed_rules = {fix_rule(rule) for rule in valid_rules}
                merged_rules.update(fixed_rules)
                if invalid_rules:
                    error_reports[source] = invalid_rules
                    log.warning(f"{source} 发现 {len(invalid_rules)} 条无效规则")
            except Exception as e:
                log.error(f"处理来源时出错: {source} - {e}")
    return merged_rules, error_reports

def main():
    """
    主程序入口。
    """
    log.info("开始处理规则文件")
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        log.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    with sources_file.open("r", encoding="utf8") as f:
        sources = [line.strip() for line in f if line.strip()]

    merged_rules, error_reports = process_sources(sources)
    final_rules = filter_unresolvable_domains(merged_rules, DNS_SERVERS)

    sorted_rules = sorted(final_rules, key=lambda x: (not x.startswith("||"), not x.startswith("@@"), x))

    with open(CONFIG["OUTPUT_FILE"], "w", encoding="utf8") as f:
        f.write("\n".join(sorted_rules))
        f.write(f"\n\n# Total count: {len(sorted_rules)}\n")
        f.write(f"# Title: {CONFIG['TITLE']}\n")
        f.write(f"# Version: {CONFIG['VERSION']}\n")

    log.info(f"规则合并完成，输出到 {CONFIG['OUTPUT_FILE']}")

if __name__ == "__main__":
    main()