#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import requests
import json
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
CONFIG = {
    "RULE_SOURCES_FILE": "sources.txt",       # 规则来源文件，每行为一个规则来源（URL 或本地路径）
    "OUTPUT_FILE": "merged-filter.txt",         # 合并后输出的规则文件
    "STATS_FILE": "rule_stats.json",            # 规则统计文件（JSON格式）
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules",                    # 文件标题
    "VERSION": "1.0.0",                         # 版本号
    "MAX_WORKERS": 5                            # 最大并发下载数
}

# 正则表达式定义
REGEX_PATTERNS = {
    "blank": re.compile(r'^\s*$'),  # 空行
    "domain": re.compile(r'^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?'),
    "element": re.compile(r'##.+'),  # 元素规则，例如 CSS 过滤器
    "regex_rule": re.compile(r'^/.*/$'),  # 正则规则，以 / 开始和结尾
    "modifier": re.compile(r'\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$')  # 修饰符规则
}

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_rule(line):
    """
    验证规则有效性。过滤以下情况：
    1. 以 '!' 或 '#' 开头（备注行）；
    2. 空行；
    3. 不匹配任何规则格式。
    判断规则格式时，同时支持域名、元素、正则、修饰符规则。
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
    对规则进行简单修正：
    1. 去除规则首尾多余的空白及竖线
    2. 清除协议部分（http://、https://）
    3. 对于白名单规则确保前缀为 @@|| 
    """
    rule = rule.strip().strip('|')
    rule = rule.replace("https://", "").replace("http://", "")
    if rule.startswith('@@') and not rule.startswith('@@||'):
        rule = '@@||' + rule[2:]
    return rule

def fetch_rules(source):
    """
    从指定的来源（本地文件或 URL）中加载规则，返回元组 (有效规则列表, 无效规则列表)。
    """
    valid_rules = []
    invalid_rules = []
    try:
        if source.startswith('file:'):
            # 处理本地文件
            file_path = source.split('file:')[1].strip()
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        else:
            # 处理网络下载
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
    从规则中提取域名部分：
    - 白名单规则：以 @@|| 开头，黑名单规则：以 || 开头，
    提取后面的域名直到遇到 '/'、'^' 或空白符。
    """
    if rule.startswith('@@||'):
        rule = rule[4:]
    elif rule.startswith('||'):
        rule = rule[2:]
    m = re.match(r'([^/\^\s]+)', rule)
    if m:
        return m.group(1)
    return rule

def filter_blacklist(rules):
    """
    自动过滤掉那些黑名单规则，其对应的域名在白名单规则中存在时将移除该黑名单规则。
    传入的 rules 集合同时可能包含白名单（以 @@ 开头）和黑名单规则。
    """
    whitelist_domains = set()
    blacklist_rules = []
    # 提取白名单中的域名和分离黑名单规则
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
            # 若白名单中已存在该域名，则不纳入黑名单
            continue
        filtered_blacklist.append(rule)
    # 最终结果包含所有白名单规则和过滤后的黑名单规则
    final_rules = {r for r in rules if r.startswith('@@')}
    final_rules.update(filtered_blacklist)
    return final_rules

def write_stats(rule_count, total_count):
    """
    将统计信息写入 JSON 文件中。
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
    并发处理所有规则来源，下载、校验并修正规则，同时记录出错的规则。
    返回合并后的所有规则集合和错误报告字典。
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
    主函数：
    1. 读取所有规则来源，下载、校验和修正规则；
    2. 自动筛选：如果某个黑名单规则的域名在白名单中存在，则过滤该黑名单规则；
    3. 对合并后的规则进行排序并写入输出文件，同时生成统计信息。
    """
    logging.info("开始处理规则文件")
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    with sources_file.open('r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip()]
    
    merged_rules, error_reports = process_sources(sources)
    # 自动过滤包含白名单的黑名单规则
    final_rules = filter_blacklist(merged_rules)

    # 排序规则：先显示以 "||" 开头的黑名单规则，再显示以 "@@" 开头的白名单规则，最后按字母顺序排序
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