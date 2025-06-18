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

# 正则表达式模块：恢复了元素规则的判断
REGEX_PATTERNS = {
    "blank": re.compile(r'^\s*$'),                  # 空行
    "domain": re.compile(r'^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?'),
    "element": re.compile(r'##.+'),                  # 元素规则，例如 CSS 过滤器
    "regex_rule": re.compile(r'^/.*/$'),             # 正则规则：必须以 / 开始、以 / 结束
    "modifier": re.compile(r'\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$')
}

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_comment_line(line):
    """
    判断是否为备注信息：
    如果规则以 "#" 或 "!" 开头并且包含中文字符，则视为备注，不进行后续合并。
    """
    line = line.strip()
    if (line.startswith('#') or line.startswith('!')) and re.search(r'[\u4e00-\u9fff]', line):
        return True
    return False

def is_valid_rule(line):
    """
    验证规则有效性，恢复了对元素规则的判断：
    过滤情况：
      1. 备注信息（以 "#" 或 "!" 开头且包含中文）
      2. 空行
      3. 如果不匹配任何规则格式，则视为无效
    支持域名规则、元素规则、正则规则和修饰符规则。
    """
    if is_comment_line(line) or REGEX_PATTERNS["blank"].match(line):
        return False
    return any([
        REGEX_PATTERNS["domain"].match(line),
        REGEX_PATTERNS["element"].search(line),   # 恢复判断元素规则
        REGEX_PATTERNS["regex_rule"].match(line),
        REGEX_PATTERNS["modifier"].search(line)
    ])

def fix_rule(rule):
    """
    修复规则语法：
      1. 去除规则首尾多余的空白和竖线
      2. 去除协议部分（http://或https://）
      3. 对于白名单规则（以 @@ 开头），统一使用 @@|| 前缀
    """
    rule = rule.strip().strip('|')
    rule = rule.replace("https://", "").replace("http://", "")
    if rule.startswith('@@') and not rule.startswith('@@||'):
        rule = '@@||' + rule[2:]
    return rule

def fetch_rules(source):
    """
    从指定来源（URL 或本地文件）下载或读取规则。
    返回值为 (有效规则列表, 无效规则列表)
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
    从规则中提取域名部分：
      对于白名单和黑名单规则，如果规则以 @@|| 或 || 开头，
      则去除前缀后提取连续的非 '/'、'^' 或空白字符部分作为域名。
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
    自动过滤：如果某个黑名单规则的域名在白名单规则中已存在，则移除该黑名单规则。
    输入: 同时包含白名单与黑名单的规则集合。
    输出: 返回过滤后的最终规则集合。
    """
    whitelist_domains = set()
    blacklist_rules = []
    
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
            continue
        filtered_blacklist.append(rule)
    
    final_rules = {r for r in rules if r.startswith('@@')}
    final_rules.update(filtered_blacklist)
    return final_rules

def write_stats(rule_count, total_count):
    """
    将统计信息写入 JSON 文件。
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
    并发处理所有规则来源，下载、校验并修正规则，并记录错误报告。
    返回合并后的规则集合与错误报告字典。
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
      1. 读取规则来源文件，下载、校验并修正各类规则（包括元素规则）。
      2. 自动过滤：如果某个黑名单规则的域名在白名单规则中已存在，则过滤该黑名单规则。
      3. 对合并后的规则进行排序，并写入输出文件及统计信息文件。
    """
    logging.info("开始处理规则文件")
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    with sources_file.open('r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip()]

    merged_rules, error_reports = process_sources(sources)
    final_rules = filter_blacklist(merged_rules)

    # 排序规则：先显示黑名单规则（以 "||" 开头），再显示白名单规则（以 "@@" 开头），最后按字母排序
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