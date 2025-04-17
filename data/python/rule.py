#!/usr/bin/env python3
import os
import re
import requests
import json
import logging
from datetime import datetime
from typing import List, Tuple, Dict

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 配置参数
RULE_SOURCES_FILE = 'sources.txt'
OUTPUT_FILE = 'merged-filter.txt'
STATS_FILE = 'rule_stats.json'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# 正则表达式模块化
REGEX_PATTERNS = {
    "comment": re.compile(r'^[!#]'),
    "blank": re.compile(r'^\s*$'),
    "domain": re.compile(r'^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?'),
    "element": re.compile(r'##.+'),
    "regex_rule": re.compile(r'^/.*/$'),
    "modifier": re.compile(r'\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$')
}

def is_valid_rule(line: str) -> bool:
    """验证规则有效性"""
    if REGEX_PATTERNS["comment"].match(line) or REGEX_PATTERNS["blank"].match(line):
        return False
    return any([
        REGEX_PATTERNS["domain"].match(line),
        REGEX_PATTERNS["element"].search(line),
        REGEX_PATTERNS["regex_rule"].match(line),
        REGEX_PATTERNS["modifier"].search(line)
    ])

def download_rules(url: str) -> Tuple[List[str], List[str]]:
    """下载规则并验证"""
    invalid_rules = []
    valid_rules = []
    try:
        if url.startswith('file:'):
            file_path = url.split('file:')[1].strip()
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = (line.strip() for line in f)
        else:
            resp = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=15)
            resp.raise_for_status()
            lines = (line.strip() for line in resp.text.splitlines())

        for line in lines:
            if is_valid_rule(line):
                valid_rules.append(line)
            elif line and not (REGEX_PATTERNS["comment"].match(line) or REGEX_PATTERNS["blank"].match(line)):
                invalid_rules.append(line)
    except Exception as e:
        logging.error(f"⚠️ 下载失败: {url} - {str(e)}")
    return valid_rules, invalid_rules

def write_stats(rule_count: int) -> None:
    """写入规则统计信息到 JSON 文件"""
    stats = {
        "rule_count": rule_count,
        "last_update": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    try:
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=4)
        logging.info(f"✅ 已更新统计信息: {STATS_FILE}")
    except Exception as e:
        logging.error(f"写入统计信息失败: {e}")

def process_sources(sources: List[str]) -> Tuple[set, Dict[str, List[str]]]:
    """处理规则来源"""
    merged_rules = set()
    error_reports = {}

    for url in sources:
        logging.info(f"📥 正在处理: {url}")
        valid_rules, invalid_rules = download_rules(url)
        merged_rules.update(valid_rules)

        if invalid_rules:
            error_reports[url] = invalid_rules
            logging.warning(f"⚠️ 发现 {len(invalid_rules)} 条无效规则")

    return merged_rules, error_reports

def save_merged_rules(rules: set, output_file: str) -> None:
    """保存合并后的规则到文件"""
    try:
        sorted_rules = sorted(rules, key=lambda x: (
            not x.startswith('||'),
            not x.startswith('##'),
            x
        ))
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_rules))
        logging.info(f"✅ 规则合并完成，输出到 {output_file}")
    except Exception as e:
        logging.error(f"写入合并规则文件失败: {e}")

def main() -> None:
    logging.info("📂 开始处理规则文件")

    try:
        # 读取规则来源
        with open(RULE_SOURCES_FILE, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"规则来源文件 {RULE_SOURCES_FILE} 未找到！")
        return
    except Exception as e:
        logging.error(f"读取规则来源文件失败: {e}")
        return

    merged_rules, error_reports = process_sources(sources)

    # 保存合并后的规则
    save_merged_rules(merged_rules, OUTPUT_FILE)

    # 写入统计信息
    write_stats(len(merged_rules))

if __name__ == "__main__":
    main()
