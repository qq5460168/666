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
RULE_SOURCES_FILE = 'sources.txt'         # 规则来源文件
OUTPUT_FILE = 'merged-filter.txt'        # 输出文件
STATS_FILE = 'rule_stats.json'           # 统计文件
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# 正则表达式模块化
REGEX_PATTERNS = {
    "comment": re.compile(r'^[!#]'),      # 注释行
    "blank": re.compile(r'^\s*$'),       # 空行
    "domain": re.compile(r'^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?'),
    "element": re.compile(r'##.+'),      # 元素规则
    "regex_rule": re.compile(r'^/.*/$'), # 正则规则
    "modifier": re.compile(r'\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$')
}

def is_valid_rule(line: str) -> bool:
    """
    验证规则有效性
    :param line: 规则行
    :return: 是否有效
    """
    # 如果是注释行或空行，直接返回 False
    if REGEX_PATTERNS["comment"].match(line) or REGEX_PATTERNS["blank"].match(line):
        return False
    # 验证规则是否匹配有效格式
    return any([
        REGEX_PATTERNS["domain"].match(line),
        REGEX_PATTERNS["element"].search(line),
        REGEX_PATTERNS["regex_rule"].match(line),
        REGEX_PATTERNS["modifier"].search(line)
    ])

def download_rules(url: str) -> Tuple[List[str], List[str]]:
    """
    下载规则并验证
    :param url: 规则来源 URL 或本地文件路径
    :return: (有效规则列表, 无效规则列表)
    """
    valid_rules = []
    invalid_rules = []
    try:
        if url.startswith('file:'):
            # 读取本地文件
            file_path = url.split('file:')[1].strip()
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = (line.strip() for line in f)
        else:
            # 下载远程文件
            resp = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=15)
            resp.raise_for_status()
            lines = (line.strip() for line in resp.text.splitlines())

        for line in lines:
            if is_valid_rule(line):
                valid_rules.append(line)
            elif line:
                invalid_rules.append(line)

    except requests.exceptions.RequestException as e:
        logging.error(f"⚠️ 下载失败: {url} - {str(e)}")
    except FileNotFoundError:
        logging.error(f"⚠️ 本地文件未找到: {url}")
    except Exception as e:
        logging.error(f"⚠️ 未知错误: {url} - {str(e)}")

    return valid_rules, invalid_rules

def write_stats(rule_count: int) -> None:
    """
    写入规则统计信息到 JSON 文件
    :param rule_count: 有效规则数
    """
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
    """
    处理规则来源
    :param sources: 规则来源列表
    :return: 合并后的规则集合和错误报告
    """
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
    """
    保存合并后的规则到文件
    :param rules: 合并后的规则集合
    :param output_file: 输出文件路径
    """
    try:
        # 按优先级排序规则
        sorted_rules = sorted(rules, key=lambda x: (
            not x.startswith('||'),   # 优先域名规则
            not x.startswith('##'),   # 其次是元素规则
            x                         # 最后按字典顺序排序
        ))
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_rules))
        logging.info(f"✅ 规则合并完成，输出到 {output_file}")
    except Exception as e:
        logging.error(f"写入合并规则文件失败: {e}")

def main() -> None:
    """
    主函数：处理规则合并、验证和统计
    """
    logging.info("📂 开始处理规则文件")

    # 检查规则来源文件是否存在
    if not os.path.exists(RULE_SOURCES_FILE):
        logging.error(f"规则来源文件 {RULE_SOURCES_FILE} 未找到！")
        return

    try:
        # 读取规则来源
        with open(RULE_SOURCES_FILE, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"读取规则来源文件失败: {e}")
        return

    # 处理规则来源
    merged_rules, error_reports = process_sources(sources)

    # 保存合并后的规则
    save_merged_rules(merged_rules, OUTPUT_FILE)

    # 写入统计信息
    write_stats(len(merged_rules))

    # 输出错误报告
    if error_reports:
        logging.warning("\n⚠️ 以下来源存在无效规则:")
        for url, errors in error_reports.items():
            logging.warning(f"  - 来源: {url}")
            for error in errors:
                logging.warning(f"    - 无效规则: {error}")

if __name__ == "__main__":
    main()