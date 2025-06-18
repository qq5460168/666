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
   文件
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules",                    # 标题
    "VERSION": "1.0.0",                         # 版本号
    "MAX_WORKERS": 5                            # 最大并发下载数
}

# 正则表达式模块
REGEX_PATTERNS = {
    "blank": re.compile(r'^\s*$'),  # 空行
    # 域名规则支持可选的@@或||前缀，匹配字母、数字、连字符、下划线、点和星号
    "domain": re.compile(r'^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?'),
    "element": re.compile(r'##.+'),  # 元素规则，如 CSS 过滤器
    "regex_rule": re.compile(r'^/.*/$'),  # 正则规则，要求以 / 开始并以 / 结束
    "modifier": re.compile(r'\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$')  # 修饰符规则
}

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_rule(line):
    """
    验证规则有效性。过滤以下情况：
    1. 以 '!' 或 '#' 开头的（备注信息，不参与规则合并）；
    2. 空行；
    3. 不匹配任何规则格式的规则。
    
    包括对元素规则、域名规则、正则规则以及修饰符的判断。
    
    :param line: 规则行字符串
    :return: True 表示规则有效，False 表示无效
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
    修复错误规则语法，处理以下情况：
    1. 移除规则首尾多余的竖线；
    2. 去除 HTTP/HTTPS 协议部分；
    3. 对于白名单规则（以 @@ 开头），统一使用 @@|| 前缀。
    
    :param rule: 原始规则字符串
    :return: 修正后的规则字符串
    """
    rule = rule.strip().strip('|')
    rule = rule.replace("https://", "").replace("http://", "")
    if rule.startswith('@@') and not rule.startswith('@@||'):
        rule = '@@||' + rule[2:]
    return rule


def fetch_rules(source):
    """
    从指定来源下载或读取规则。
    如果 source 以 "file:" 开头，则从本地文件读取；否则视为 URL 下载规则。
    
    :param source: 规则来源（URL 或本地文件路径，前者需为 file: 开头格式）
    :return: (有效规则列表, 无效规则列表)
    """
    valid_rules = []
    invalid_rules = []
    try:
        if source.startswith('file:'):
            file_path = source.split('file:')[1].strip()
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        else:
            response = requests.get(source, headers={'User-Agent': CONFIG["USER_AGENT"]}, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()

        for line in map(str.strip, lines):
            if is_valid_rule(line):
                valid_rules.append(line)
            elif line:
                invalid_rules.append(line)

    except requests.RequestException as e:
        logging.error(f"下载失败: {source} - {e}")
    except FileNotFoundError:
        logging.error(f"本地文件未找到: {source}")
    except Exception as e:
        logging.error(f"未知错误: {source} - {e}")

    return valid_rules, invalid_rules


def extract_domain(rule):
    """
    尝试从规则字符串中提取域名部分。规则通常以 @@|| 或 || 开头，
    提取后面的域名直到遇到 '/'、'^' 或空白符。
    
    :param rule: 修正后的规则字符串
    :return: 域名字符串
    """
    # 去除白名单前缀 @@|| 或黑名单前缀 ||
    if rule.startswith('@@||'):
        rule = rule[4:]
    elif rule.startswith('||'):
        rule = rule[2:]
    # 提取连续非分隔符的部分作为域名
    m = re.match(r'([^/\^\s]+)', rule)
    if m:
        return m.group(1)
    return rule


def filter_blacklist(rules):
    """
    自动过滤掉那些黑名单规则中，如果其对应的域名出现在白名单规则中，就移除该黑名单规则。
    
    :param rules: 合并后的全部规则（包含白名单与黑名单规则）
    :return: 经过过滤后的规则集合
    """
    whitelist_domains = set()
    blacklist_rules = []

    # 分离白名单和黑名单，并提取白名单中的域名
    for rule in rules:
        if rule.startswith('@@'):
            domain = extract_domain(rule)
            whitelist_domains.add(domain)
        else:
            blacklist_rules.append(rule)

    filtered_blacklist = []
    for rule in blacklist_rules:
        domain = extract_domain(rule)
        if domain in whitelist_domains:
            # 该黑名单规则的域名在白名单中存在，过滤掉
            continue
        filtered_blacklist.append(rule)

    # 返回包含所有白名单规则与经过过滤的黑名单规则
    final_rules = {r for r in rules if r.startswith('@@')}
    final_rules.update(filtered_blacklist)
    return final_rules


def write_stats(rule_count, total_count):
    """
    将规则统计信息写入 JSON 文件。
    
    :param rule_count: 有效规则数量
    :param total_count: 合并后的总规则数
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
    并发处理所有规则来源，下载、验证并修复规则，同时记录错误报告。
    
    :param sources: 规则来源列表
    :return: 合并后的有效规则集合和错误报告字典
    """
    merged_rules = set()
    error_reports = {}

    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        future_to_source = {executor.submit(fetch_rules, source): source for source in sources}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                valid_rules, invalid_rules = future.result()
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
    主函数：加载规则、合并、自动过滤包含白名单的黑名单规则，排序并写入输出文件，同时生成统计信息。
    """
    logging.info("开始处理规则文件")

    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    with sources_file.open('r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip()]

    merged_rules, error_reports = process_sources(sources)
    # 自动过滤掉黑名单中包含白名单域名的规则
    final_rules = filter_blacklist(merged_rules)

    # 排序规则：先显示以 "||" 开头的（黑名单）规则，再显示白名单规则(@@开头)，然后按字母顺序排序
    sorted_rules = sorted(final_rules, key=lambda x: (
        not x.startswith('||'),
        not x.startswith('@@'),
        x
    ))

    with open(CONFIG["OUTPUT_FILE"], 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_rules))
        f.write(f"\n\n# Total count: {len(sorted_rules)}\n")
        f.write(f"# Title: {CONFIG['TITLE']}\n")
        f.write(f"# Version: {CONFIG['VERSION']}\n")
    logging.info(f"规则合并完成，输出到 {CONFIG['OUTPUT_FILE']}")

    write_stats(len(sorted_rules), len(merged_rules))

    if error_reports:
        logging.warning("以下来源存在无效规则:")
        for source, errors in error_reports.items():
            logging.warning(f"来源: {source}")
            for error in errors:
                logging.warning(f"无效规则: {error}")


if __name__ == "__main__":
    main()