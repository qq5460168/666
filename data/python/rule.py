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
    "RULE_SOURCES_FILE": "sources.txt",      # 规则来源文件
    "OUTPUT_FILE": "merged-filter.txt",        # 输出文件
    "STATS_FILE": "rule_stats.json",           # 统计信息输出文件
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules",                   # 输出文件标题
    "VERSION": "1.0.0",                        # 版本号
    "MAX_WORKERS": 5                           # 并发下载最大线程数
}

# 正则表达式模块，用于识别不同类型的规则：
REGEX_PATTERNS = {
    "blank": re.compile(r"^\s*$"),  # 空行
    "domain": re.compile(r"^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?"),  # 域名规则（注意：支持@白名单前缀）
    "element": re.compile(r"##.+"),  # 元素过滤规则（例如 CSS 过滤器）
    "regex_rule": re.compile(r"^/.*/$"),  # 正则表达式规则（需要以 / 开始、以 / 结束）
    "modifier": re.compile(r"\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$")
}

# 配置日志输出格式
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def is_comment_line(line):
    """
    判断是否为备注信息：
    规则以 "#" 或 "!" 开头且包含中文时，视为备注，不参与后续合并处理。
    """
    line = line.strip()
    return (line.startswith("#") or line.startswith("!")) and re.search(r"[\u4e00-\u9fff]", line)

def is_valid_rule(line):
    """
    判断规则是否合法：
      过滤备注、空行，以及不匹配任何规则格式的行。
    支持的规则类型包括域名规则、元素规则、正则规则及修饰符规则。
    """
    if is_comment_line(line) or REGEX_PATTERNS["blank"].match(line):
        return False
    return (REGEX_PATTERNS["domain"].match(line) or 
            REGEX_PATTERNS["element"].search(line) or 
            REGEX_PATTERNS["regex_rule"].match(line) or 
            REGEX_PATTERNS["modifier"].search(line))

def fix_rule(rule):
    """
    修复规则语法：
      1. 去除首尾多余的空格和竖线
      2. 移除 HTTP/HTTPS 协议头
      3. 对于白名单规则（以 @@ 开头），确保使用统一的 @@|| 前缀
    """
    rule = rule.strip().strip("|")
    rule = rule.replace("https://", "").replace("http://", "")
    if rule.startswith("@@") and not rule.startswith("@@||"):
        rule = "@@||" + rule[2:]
    return rule

def fetch_rules(source):
    """
    从指定来源下载或读取规则内容。
    参数:
      source: 来源路径，可以是 URL 或 "file:" 前缀的本地文件路径
    返回:
      (有效规则列表, 无效规则列表)
    """
    valid_rules = []
    invalid_rules = []
    try:
        # 判断来源: 本地文件或网络文件
        if source.startswith("file:"):
            file_path = source.split("file:")[1].strip()
            with open(file_path, "r", encoding="utf8") as f:
                lines = f.readlines()
        else:
            response = requests.get(source, headers={"User-Agent": CONFIG["USER_AGENT"]}, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
        # 针对每一行规则，执行有效性检验
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
      对于以 @@|| 或 || 开头的规则，去掉前缀后提取连续的非 "/"、"^" 或空白的部分作为域名。
    """
    if rule.startswith("@@||"):
        rule = rule[4:]
    elif rule.startswith("||"):
        rule = rule[2:]
    m = re.match(r"([^/\^\s]+)", rule)
    return m.group(1) if m else rule

def filter_blacklist(rules):
    """
    过滤黑名单规则：
      如果一个黑名单规则的域名已经在白名单规则中出现，则该黑名单规则将被过滤掉，
      以保证最终合并规则中不包含互相冲突的条目。
    返回:
      过滤后的最终规则集合
    """
    # 从所有白名单规则中提取域名形成集合
    whitelist_domains = {extract_domain(rule) for rule in rules if rule.startswith("@@")}
    # 筛选出黑名单规则中未出现在白名单域中的条目
    filtered_blacklist = [rule for rule in rules if not rule.startswith("@@") and extract_domain(rule) not in whitelist_domains]
    return {rule for rule in rules if rule.startswith("@@")} | set(filtered_blacklist)

def write_stats(rule_count, total_count):
    """
    将规则统计信息写入 JSON 文件。
    参数:
      rule_count: 最终合并后的规则数量
      total_count: 所有规则（包括重复、无效规则）的数量
    """
    stats = {
        "rule_count": rule_count,
        "total_count": total_count,
        "title": CONFIG["TITLE"],
        "version": CONFIG["VERSION"],
        "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    with open(CONFIG["STATS_FILE"], "w", encoding="utf8") as f:
        json.dump(stats, f, indent=4)
    logging.info(f"已更新统计信息: {CONFIG['STATS_FILE']}")

def process_sources(sources):
    """
    并发处理所有规则来源：
      1. 下载或读取规则文本；
      2. 校验规则有效性；
      3. 进行简单的语法修正（调用 fix_rule ）；
      4. 汇总所有修正后的规则并记录错误报告。
    参数:
      sources: 来源列表，由内含 URL 或本地路径组成
    返回:
      (合并后的规则集合, 错误报告字典)
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
                    logging.warning(f"{source} 发现 {len(invalid_rules)} 条无效规则")
            except Exception as e:
                logging.error(f"处理来源时出错: {source} - {e}")
    return merged_rules, error_reports

def main():
    """
    主函数：
      1. 读取规则来源文件中的所有来源地址；
      2. 并发下载、校验并修正规则（包括元素规则）；
      3. 使用过滤逻辑去除黑名单中与白名单冲突的规则；
      4. 对最终规则进行排序，并写入输出文件与统计信息文件。
    """
    logging.info("开始处理规则文件")
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    with sources_file.open("r", encoding="utf8") as f:
        sources = [line.strip() for line in f if line.strip()]

    merged_rules, error_reports = process_sources(sources)
    final_rules = filter_blacklist(merged_rules)

    # 排序策略：先显示黑名单规则（以 "||" 开头），再显示白名单规则（以 "@@" 开头），最后按字母顺序排序
    sorted_rules = sorted(final_rules, key=lambda x: (not x.startswith("||"), not x.startswith("@@"), x))

    with open(CONFIG["OUTPUT_FILE"], "w", encoding="utf8") as f:
        f.write("\n".join(sorted_rules))
        f.write(f"\n\n# Total count: {len(sorted_rules)}\n")
        f.write(f"# Title: {CONFIG['TITLE']}\n")
        f.write(f"# Version: {CONFIG['VERSION']}\n")

    logging.info(f"规则合并完成，输出到 {CONFIG['OUTPUT_FILE']}")
    write_stats(len(sorted_rules), len(merged_rules))

    if error_reports:
        logging.warning("以下来源存在无效规则:")
        for src, errors in error_reports.items():
            logging.warning(f"来源: {src}")
            for error in errors:
                logging.warning(f"无效规则: {error}")

if __name__ == "__main__":
    main()
