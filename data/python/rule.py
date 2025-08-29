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
    "OUTPUT_FILE": "merged-filter.txt",      # 输出文件
    "STATS_FILE": "rule_stats.json",         # 统计信息输出文件
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules (Exclude Path Rules)",  # 输出文件标题（标注排除路径规则）
    "VERSION": "1.0.2",                      # 版本号（更新以反映功能变更）
    "MAX_WORKERS": 5                         # 并发下载最大线程数
}

# 正则表达式模块：新增路径型规则识别
REGEX_PATTERNS = {
    "blank": re.compile(r"^\s*$"),  # 空行
    "domain": re.compile(r"^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?"),  # 域名规则（含白名单）
    "element": re.compile(r"##.+"),  # 元素过滤规则（已排除，保留正则用于兼容）
    "regex_rule": re.compile(r"^/.*/$"),  # 正则规则（/xxx/格式）
    "modifier": re.compile(r"\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$"),  # 修饰符（如$third-party）
    # 新增：路径型规则（以/开头，无域名前缀；或包含/path/格式的路径片段）
    "path_rule": re.compile(
        r"^/[^/]+(/.+)?$"  # 纯路径规则（如/yinghuacd/bottom.js、/*/*.add.*.add）
        r"|^[^:\/]+\.[^:\/]+\/[^/]+(/.+)?$"  # 带域名的路径规则（如.cn/2022/*/*.txt、.com/js/g.js）
    )
}

# 配置日志输出格式
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def is_comment_line(line):
    """判断是否为中文备注行（以#/!开头且含中文）"""
    line = line.strip()
    return (line.startswith("#") or line.startswith("!")) and re.search(r"[\u4e00-\u9fff]", line)

def is_valid_rule(line):
    """
    判断规则是否合法：排除备注、空行、元素规则、路径型规则
    仅保留：域名规则、纯正则规则（/xxx/格式）、修饰符规则
    """
    line = line.strip()
    # 排除：备注、空行、元素规则
    if is_comment_line(line) or REGEX_PATTERNS["blank"].match(line) or REGEX_PATTERNS["element"].search(line):
        return False
    # 排除：路径型规则（核心修改）
    if REGEX_PATTERNS["path_rule"].match(line):
        return False
    # 保留：域名规则、纯正则规则、修饰符规则
    return (REGEX_PATTERNS["domain"].match(line) or 
            REGEX_PATTERNS["regex_rule"].match(line) or 
            REGEX_PATTERNS["modifier"].search(line))

def fix_rule(rule):
    """修复规则语法（仅针对保留的规则类型）"""
    rule = rule.strip().strip("|")
    rule = rule.replace("https://", "").replace("http://", "")
    # 白名单规则统一前缀（@@→@@||）
    if rule.startswith("@@") and not rule.startswith("@@||"):
        rule = "@@||" + rule[2:]
    return rule

def fetch_rules(source):
    """
    从来源下载/读取规则：
    - 统计跳过的路径型规则、元素规则
    - 仅保留合法规则（排除路径/元素/备注/空行）
    """
    valid_rules = []
    invalid_rules = []
    skipped = {
        "path_rules": 0,    # 跳过的路径型规则数量
        "element_rules": 0  # 跳过的元素规则数量
    }
    try:
        # 读取本地文件或下载网络规则
        if source.startswith("file:"):
            file_path = source.split("file:")[1].strip()
            with open(file_path, "r", encoding="utf8") as f:
                lines = f.readlines()
        else:
            response = requests.get(source, headers={"User-Agent": CONFIG["USER_AGENT"]}, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
        
        # 逐行处理规则
        for line in map(str.strip, lines):
            if not line:  # 空行跳过
                continue
            if is_comment_line(line):  # 中文备注跳过
                continue
            # 统计并跳过元素规则
            if REGEX_PATTERNS["element"].search(line):
                skipped["element_rules"] += 1
                continue
            # 统计并跳过路径型规则（核心修改）
            if REGEX_PATTERNS["path_rule"].match(line):
                skipped["path_rules"] += 1
                continue
            # 验证并保留合法规则
            if is_valid_rule(line):
                valid_rules.append(line)
            else:
                invalid_rules.append(line)
        
        # 日志输出当前来源的跳过统计
        if skipped["path_rules"] > 0:
            logging.info(f"{source}：跳过 {skipped['path_rules']} 条路径型规则（如/yinghuacd/bottom.js）")
        if skipped["element_rules"] > 0:
            logging.info(f"{source}：跳过 {skipped['element_rules']} 条元素规则")
            
    except requests.RequestException as e:
        logging.error(f"下载失败: {source} - {e}")
    except FileNotFoundError:
        logging.error(f"本地文件未找到: {source}")
    except Exception as e:
        logging.error(f"未知错误: {source} - {e}")
    return valid_rules, invalid_rules, skipped

def extract_domain(rule):
    """从规则中提取域名（用于白名单冲突过滤）"""
    if rule.startswith("@@||"):
        rule = rule[4:]
    elif rule.startswith("||"):
        rule = rule[2:]
    # 提取域名部分（排除路径和修饰符）
    m = re.match(r"([^/\^\s\$]+)", rule)
    return m.group(1) if m else rule

def filter_blacklist(rules):
    """过滤冲突规则：白名单域名的黑名单规则会被排除"""
    whitelist_domains = {extract_domain(rule) for rule in rules if rule.startswith("@@")}
    filtered_blacklist = [
        rule for rule in rules 
        if not rule.startswith("@@") and extract_domain(rule) not in whitelist_domains
    ]
    # 合并白名单和过滤后的黑名单（去重）
    return {rule for rule in rules if rule.startswith("@@")} | set(filtered_blacklist)

def write_stats(rule_count, total_valid_before_filter, skipped_total):
    """写入统计信息：新增跳过的路径/元素规则数量"""
    stats = {
        "final_rule_count": rule_count,  # 最终合并后的规则数
        "valid_rules_before_filter": total_valid_before_filter,  # 过滤冲突前的有效规则数
        "skipped": {
            "total_path_rules": skipped_total["path_rules"],  # 总跳过路径型规则数
            "total_element_rules": skipped_total["element_rules"]  # 总跳过元素规则数
        },
        "title": CONFIG["TITLE"],
        "version": CONFIG["VERSION"],
        "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    with open(CONFIG["STATS_FILE"], "w", encoding="utf8") as f:
        json.dump(stats, f, indent=4)
    logging.info(f"统计信息已写入: {CONFIG['STATS_FILE']}")

def process_sources(sources):
    """并发处理所有来源：合并规则、统计跳过数量、收集错误"""
    merged_rules = set()
    error_reports = {}
    skipped_total = {
        "path_rules": 0,
        "element_rules": 0
    }
    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        # 提交所有来源的处理任务
        future_to_source = {executor.submit(fetch_rules, s): s for s in sources}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                valid_rules, invalid_rules, skipped = future.result()
                # 累加跳过的规则总数
                skipped_total["path_rules"] += skipped["path_rules"]
                skipped_total["element_rules"] += skipped["element_rules"]
                # 修复并合并有效规则
                fixed_rules = {fix_rule(rule) for rule in valid_rules}
                merged_rules.update(fixed_rules)
                # 收集无效规则报告
                if invalid_rules:
                    error_reports[source] = invalid_rules
                    logging.warning(f"{source}：发现 {len(invalid_rules)} 条无效规则（非路径/元素/合法规则）")
            except Exception as e:
                logging.error(f"处理来源出错: {source} - {e}")
    return merged_rules, error_reports, skipped_total

def main():
    """主函数：串联规则读取、处理、合并、输出全流程"""
    logging.info("开始处理规则（排除路径型规则和元素规则）")
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    # 读取所有规则来源（URL或本地路径）
    with sources_file.open("r", encoding="utf8") as f:
        sources = [line.strip() for line in f if line.strip()]
    if not sources:
        logging.warning("规则来源文件为空，无规则可处理")
        return

    # 并发处理来源，获取合并规则、错误报告、跳过统计
    merged_rules, error_reports, skipped_total = process_sources(sources)
    # 过滤白名单冲突的黑名单规则
    final_rules = filter_blacklist(merged_rules)
    # 排序：先黑名单（||开头）→ 再白名单（@@开头）→ 最后按字母序
    sorted_rules = sorted(
        final_rules,
        key=lambda x: (not x.startswith("||"), not x.startswith("@@"), x)
    )

    # 写入最终合并规则到输出文件
    with open(CONFIG["OUTPUT_FILE"], "w", encoding="utf8") as f:
        f.write("\n".join(sorted_rules))
        # 末尾添加统计注释
        f.write(f"\n\n# 最终规则总数: {len(sorted_rules)}\n")
        f.write(f"# 跳过路径型规则总数: {skipped_total['path_rules']}\n")
        f.write(f"# 跳过元素规则总数: {skipped_total['element_rules']}\n")
        f.write(f"# 标题: {CONFIG['TITLE']}\n")
        f.write(f"# 版本: {CONFIG['VERSION']}\n")
        f.write(f"# 最后更新: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

    # 输出关键日志
    logging.info(f"规则合并完成！输出文件: {CONFIG['OUTPUT_FILE']}")
    logging.info(f"关键统计：最终规则数={len(sorted_rules)} | 跳过路径规则数={skipped_total['path_rules']} | 跳过元素规则数={skipped_total['element_rules']}")
    # 写入详细统计到JSON
    write_stats(len(sorted_rules), len(merged_rules), skipped_total)

    # 输出无效规则报告（避免日志刷屏，仅显示前5条）
    if error_reports:
        logging.warning("\n以下来源存在无效规则：")
        for src, errors in error_reports.items():
            logging.warning(f"  来源: {src}（共{len(errors)}条）")
            for err in errors[:5]:
                logging.warning(f"    - {err}")
            if len(errors) > 5:
                logging.warning(f"    - ... 还有{len(errors)-5}条未显示\n")

if __name__ == "__main__":
    main()
