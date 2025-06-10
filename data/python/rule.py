#!/usr/bin/env python3

import os
import re
import requests
import json
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
CONFIG = {
    "RULE_SOURCES_FILE": "sources.txt",       # 规则来源文件
    "OUTPUT_FILE": "merged-filter.txt",         # 输出文件
    "STATS_FILE": "rule_stats.json",            # 统计文件
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules",                    # 标题
    "VERSION": "1.0.0",                         # 版本号
    "MAX_WORKERS": 5                            # 最大并发下载数
}

# 正则表达式模块
REGEX_PATTERNS = {
    "blank": re.compile(r'^\s*$'),  # 空行
    "domain": re.compile(r'^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?'),  # 域名规则
    "element": re.compile(r'##.+'),  # 元素规则
    "regex_rule": re.compile(r'^/.*/$'),  # 正则规则
    "modifier": re.compile(r'\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$')  # 修饰符
}

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_rule(line):
    """
    验证规则有效性
    :param line: 规则行
    :return: 是否有效
    """
    if line.startswith('!') or line.startswith('#') or REGEX_PATTERNS["blank"].match(line):
        return False
    return any([
        REGEX_PATTERNS["domain"].match(line),
        REGEX_PATTERNS["element"].search(line),
        REGEX_PATTERNS["regex_rule"].match(line),
        REGEX_PATTERNS["modifier"].search(line)
    ])


def fix_rule(rule):
    """
    修复错误规则语法，直接修复以下情况：
    1. 移除规则首尾多余的竖线
    2. 去除 HTTP/HTTPS 协议部分
    3. 对于白名单规则，统一使用 @@|| 前缀
    :param rule: 原始规则字符串
    :return: 修复后的规则字符串
    """
    # 去除开头和结尾的空白以及多余的竖线
    rule = rule.strip().strip('|')
    # 去除协议部分
    rule = rule.replace("https://", "").replace("http://", "")
    # 对于@@规则，确保正确前缀@@||使用
    if rule.startswith('@@') and not rule.startswith('@@||'):
        rule = '@@||' + rule[2:]
    return rule


def fetch_rules(source):
    """
    从指定来源下载或读取规则
    :param source: URL 或本地文件路径
    :return: (有效规则列表, 无效规则列表)
    """
    valid_rules = []
    invalid_rules = []

    try:
        if source.startswith('file:'):
            # 读取本地文件（去除 "file:" 前缀）
            file_path = source.split('file:')[1].strip()
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        else:
            # 下载远程规则
            response = requests.get(source, headers={'User-Agent': CONFIG["USER_AGENT"]}, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()

        for line in map(str.strip, lines):
            if is_valid_rule(line):
                valid_rules.append(line)
            elif line:  # 非空行但无效
                invalid_rules.append(line)

    except requests.RequestException as e:
        logging.error(f"下载失败: {source} - {e}")
    except FileNotFoundError:
        logging.error(f"本地文件未找到: {source}")
    except Exception as e:
        logging.error(f"未知错误: {source} - {e}")

    return valid_rules, invalid_rules


def write_stats(rule_count, total_count):
    """
    写入规则统计信息到 JSON 文件
    :param rule_count: 有效规则数
    :param total_count: 总规则数
    """
    stats = {
        "rule_count": rule_count,
        "total_count": total_count,
        "title": CONFIG["TITLE"],
        "version": CONFIG["VERSION"],
        "last_update": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    with open(CONFIG["STATS_FILE"], 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=4)
    logging.info(f"已更新统计信息: {CONFIG['STATS_FILE']}")


def process_sources(sources):
    """
    并发处理所有规则来源
    :param sources: 规则来源列表
    :return: 合并后的有效规则集合和错误报告
    """
    merged_rules = set()
    error_reports = {}

    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        future_to_source = {executor.submit(fetch_rules, source): source for source in sources}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                valid_rules, invalid_rules = future.result()
                # 对每条有效规则进行修复后再合并
                fixed_rules = {fix_rule(rule) for rule in valid_rules}
                merged_rules.update(fixed_rules)
                if invalid_rules:
                    error_reports[source] = invalid_rules
                    logging.warning(f"{source} 发现 {len(invalid_rules)} 条无效规则")
            except Exception as e:
                logging.error(f"处理来源时出错: {source} - {e}")

    return merged_rules, error_reports


def main():
    """
    主函数：处理规则合并、验证、修复和统计
    """
    logging.info("开始处理规则文件")

    # 检查规则来源文件是否存在
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    # 读取规则来源
    with sources_file.open('r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip()]

    # 下载、验证、并修复规则
    merged_rules, error_reports = process_sources(sources)

    # 排序规则：先显示以 "||" 开头的规则，再显示以 "##" 开头的规则，然后按字母顺序排序
    sorted_rules = sorted(merged_rules, key=lambda x: (
        not x.startswith('||'),
        not x.startswith('##'),
        x
    ))

    # 写入到输出文件
    with open(CONFIG["OUTPUT_FILE"], 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_rules))
        f.write(f"\n\n# Total count: {len(sorted_rules)}\n")
        f.write(f"# Title: {CONFIG['TITLE']}\n")
        f.write(f"# Version: {CONFIG['VERSION']}\n")
    logging.info(f"规则合并完成，输出到 {CONFIG['OUTPUT_FILE']}")

    # 写入统计信息
    write_stats(len(sorted_rules), len(merged_rules))

    # 输出错误报告
    if error_reports:
        logging.warning("以下来源存在无效规则:")
        for source, errors in error_reports.items():
            logging.warning(f"来源: {source}")
            for error in errors:
                logging.warning(f"无效规则: {error}")


if __name__ == "__main__":
    main()