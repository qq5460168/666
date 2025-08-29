#!/usr/bin/env python3
import os
import re
import requests
import json
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数（新增路径规则开关、冲突检测模式等）
CONFIG = {
    "RULE_SOURCES_FILE": "sources.txt",      # 规则来源文件
    "OUTPUT_FILE": "merged-filter.txt",      # 输出文件
    "STATS_FILE": "rule_stats.json",         # 统计信息输出文件
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules",                 # 输出文件标题（动态标注路径规则状态）
    "VERSION": "1.1.0",                      # 版本号（优化后升级）
    "MAX_WORKERS": 5,                        # 并发下载最大线程数
    "ALLOW_PATH_RULES": False,               # 新增：是否保留路径型规则
    "CONFLICT_DETECTION_LEVEL": "strict"     # 新增：冲突检测模式（strict/normal）
}

# 正则表达式模块：优化路径规则识别精度
REGEX_PATTERNS = {
    "blank": re.compile(r"^\s*$"),  # 空行
    "domain": re.compile(r"^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?"),  # 域名规则（含白名单）
    "element": re.compile(r"##.+"),  # 元素过滤规则
    "regex_rule": re.compile(r"^/.*/$"),  # 正则规则（/xxx/格式）
    "modifier": re.compile(r"\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$"),  # 修饰符（如$third-party）
    # 优化路径型规则识别（更精准的路径片段检测）
    "path_rule": re.compile(
        r"^/[^/]+(/.+)?$"  # 纯路径规则（如/yinghuacd/bottom.js）
        r"|^[^:\/]+\.[^:\/]+\/[^/]+(/.+)?$"  # 带域名的路径规则（如example.com/js/ad.js）
        r"|^\|\|[^/]+/[^/]+"  # 带||前缀的路径规则（如||example.com/ad/）
    )
}

# 配置日志输出格式（新增文件名和行号）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
)

def is_comment_line(line):
    """判断是否为备注行（以#/!开头）"""
    line = line.strip()
    return line.startswith(("#", "!"))

def is_valid_rule(line):
    """
    判断规则是否合法：根据配置决定是否排除路径规则
    仅保留：域名规则、纯正则规则、修饰符规则
    """
    line = line.strip()
    # 排除：备注、空行、元素规则
    if is_comment_line(line) or REGEX_PATTERNS["blank"].match(line) or REGEX_PATTERNS["element"].search(line):
        return False
    # 根据配置决定是否排除路径型规则
    if not CONFIG["ALLOW_PATH_RULES"] and REGEX_PATTERNS["path_rule"].match(line):
        return False
    # 保留：域名规则、纯正则规则、修饰符规则
    return (REGEX_PATTERNS["domain"].match(line) or 
            REGEX_PATTERNS["regex_rule"].match(line) or 
            REGEX_PATTERNS["modifier"].search(line))

def fix_rule(rule):
    """修复规则语法（增强白名单和修饰符处理）"""
    rule = rule.strip().strip("|")
    # 移除协议前缀（更彻底的清理）
    rule = re.sub(r"^https?://", "", rule)
    # 白名单规则统一前缀（@@→@@||）
    if rule.startswith("@@") and not rule.startswith("@@||"):
        rule = "@@||" + rule[2:]
    # 修复修饰符位置（确保$在末尾）
    if "$" in rule and not rule.endswith("$"):
        parts = re.split(r"(\$)", rule)
        if len(parts) >= 3:
            rule = parts[0] + parts[2] + parts[1]
    return rule

def fetch_rules(source):
    """
    从来源下载/读取规则：
    - 增强错误处理和超时控制
    - 细化统计维度（按规则类型分类）
    """
    valid_rules = []
    invalid_rules = []
    skipped = {
        "path_rules": 0,
        "element_rules": 0,
        "comments": 0,
        "blank_lines": 0
    }
    try:
        # 读取本地文件或下载网络规则（增强超时和重试）
        if source.startswith("file:"):
            file_path = source.split("file:")[1].strip()
            with open(file_path, "r", encoding="utf8", errors="ignore") as f:
                lines = f.readlines()
        else:
            headers = {"User-Agent": CONFIG["USER_AGENT"]}
            response = requests.get(
                source,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                stream=False
            )
            response.raise_for_status()
            # 自动检测编码（解决乱码问题）
            encoding = response.apparent_encoding or "utf-8"
            lines = response.content.decode(encoding, errors="ignore").splitlines()
        
        # 逐行处理规则
        for line in map(str.strip, lines):
            if not line:
                skipped["blank_lines"] += 1
                continue
            if is_comment_line(line):
                skipped["comments"] += 1
                continue
            # 统计元素规则
            if REGEX_PATTERNS["element"].search(line):
                skipped["element_rules"] += 1
                continue
            # 统计路径规则（根据配置）
            if not CONFIG["ALLOW_PATH_RULES"] and REGEX_PATTERNS["path_rule"].match(line):
                skipped["path_rules"] += 1
                continue
            # 验证并保留合法规则
            if is_valid_rule(line):
                valid_rules.append(line)
            else:
                invalid_rules.append(line)
        
        # 日志输出统计（仅输出有内容的项）
        log_parts = []
        for key, value in skipped.items():
            if value > 0:
                log_parts.append(f"{value}条{key.replace('_', ' ')}")
        if log_parts:
            logging.info(f"{source}：跳过{', '.join(log_parts)}")
            
    except requests.RequestException as e:
        logging.error(f"下载失败: {source} - {str(e)[:100]}")  # 限制错误信息长度
    except FileNotFoundError:
        logging.error(f"本地文件未找到: {source}")
    except Exception as e:
        logging.error(f"处理错误: {source} - {str(e)[:100]}")
    return valid_rules, invalid_rules, skipped

def extract_domain(rule):
    """从规则中提取域名（支持修饰符解析，提升冲突检测精度）"""
    # 移除白名单前缀
    clean_rule = rule[4:] if rule.startswith("@@||") else rule[2:] if rule.startswith("||") else rule
    # 移除修饰符（$后面的内容）
    clean_rule = re.split(r"\$", clean_rule)[0]
    # 移除路径部分
    clean_rule = re.split(r"/", clean_rule)[0]
    # 提取主域名（简化版，可根据需要增强）
    match = re.match(r"([^:*]+)", clean_rule)
    return match.group(1).lower() if match else clean_rule.lower()

def filter_blacklist(rules):
    """
    过滤冲突规则：
    - 严格模式：白名单域名的所有子域名黑名单规则均被排除
    - 普通模式：仅完全匹配的域名冲突被排除
    """
    # 提取白名单域名（标准化处理）
    whitelist = {extract_domain(rule) for rule in rules if rule.startswith("@@")}
    filtered = []
    
    for rule in rules:
        if rule.startswith("@@"):  # 保留所有白名单规则
            filtered.append(rule)
            continue
        
        domain = extract_domain(rule)
        if CONFIG["CONFLICT_DETECTION_LEVEL"] == "strict":
            # 严格模式：检查是否为白名单域名的子域名
            is_conflict = any(
                domain == wl_domain or domain.endswith(f".{wl_domain}")
                for wl_domain in whitelist
            )
        else:
            # 普通模式：仅完全匹配
            is_conflict = domain in whitelist
        
        if not is_conflict:
            filtered.append(rule)
    
    return filtered

def write_stats(rule_count, total_valid_before_filter, skipped_total, source_stats):
    """写入细化的统计信息（新增来源贡献占比和规则类型分布）"""
    # 统计规则类型分布
    type_stats = {
        "blacklist": 0,
        "whitelist": 0,
        "regex": 0,
        "modifier": 0
    }
    with open(CONFIG["OUTPUT_FILE"], "r", encoding="utf8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@@"):
                type_stats["whitelist"] += 1
            elif REGEX_PATTERNS["regex_rule"].match(line):
                type_stats["regex"] += 1
            elif REGEX_PATTERNS["modifier"].search(line):
                type_stats["modifier"] += 1
            else:
                type_stats["blacklist"] += 1

    stats = {
        "final_rule_count": rule_count,
        "valid_rules_before_filter": total_valid_before_filter,
        "skipped": {
            "total_path_rules": skipped_total["path_rules"],
            "total_element_rules": skipped_total["element_rules"],
            "total_comments": skipped_total["comments"],
            "total_blank_lines": skipped_total["blank_lines"]
        },
        "rule_types": type_stats,
        "source_contributions": source_stats,  # 各来源贡献占比
        "config": {
            "allow_path_rules": CONFIG["ALLOW_PATH_RULES"],
            "conflict_detection": CONFIG["CONFLICT_DETECTION_LEVEL"]
        },
        "title": f"{CONFIG['TITLE']} {'(Include Path Rules)' if CONFIG['ALLOW_PATH_RULES'] else '(Exclude Path Rules)'}",
        "version": CONFIG["VERSION"],
        "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    with open(CONFIG["STATS_FILE"], "w", encoding="utf8") as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)
    logging.info(f"统计信息已写入: {CONFIG['STATS_FILE']}")

def process_sources(sources):
    """并发处理所有来源：优化去重效率，新增来源统计"""
    merged_rules = []  # 先列表存储，最后按类型分组去重
    error_reports = {}
    skipped_total = {
        "path_rules": 0,
        "element_rules": 0,
        "comments": 0,
        "blank_lines": 0
    }
    source_stats = {}  # 记录各来源的有效规则数

    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        future_to_source = {executor.submit(fetch_rules, s): s for s in sources}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                valid_rules, invalid_rules, skipped = future.result()
                # 累加跳过的规则总数
                for key in skipped_total:
                    skipped_total[key] += skipped.get(key, 0)
                # 修复并按类型分组（提升去重效率）
                fixed_rules = [fix_rule(rule) for rule in valid_rules]
                source_count = len(fixed_rules)
                source_stats[source] = {
                    "valid_count": source_count,
                    "percentage": 0  # 后续计算占比
                }
                merged_rules.extend(fixed_rules)
                # 收集无效规则报告
                if invalid_rules:
                    error_reports[source] = {
                        "count": len(invalid_rules),
                        "samples": invalid_rules[:5]  # 只保留前5条示例
                    }
                    logging.warning(f"{source}：发现 {len(invalid_rules)} 条无效规则")
            except Exception as e:
                logging.error(f"处理来源出错: {source} - {str(e)[:100]}")

    # 计算各来源的贡献占比
    total_valid = len(merged_rules)
    for source in source_stats:
        if total_valid > 0:
            source_stats[source]["percentage"] = round(source_stats[source]["valid_count"] / total_valid * 100, 2)

    # 分组去重（按规则类型分组后再去重，提升效率）
    whitelist = set()
    blacklist = set()
    regex_rules = set()
    modifier_rules = set()

    for rule in merged_rules:
        if rule.startswith("@@"):
            whitelist.add(rule)
        elif REGEX_PATTERNS["regex_rule"].match(rule):
            regex_rules.add(rule)
        elif REGEX_PATTERNS["modifier"].search(rule):
            modifier_rules.add(rule)
        else:
            blacklist.add(rule)

    # 合并去重后的规则
    unique_rules = list(whitelist) + list(blacklist) + list(regex_rules) + list(modifier_rules)
    return unique_rules, error_reports, skipped_total, source_stats, total_valid

def main():
    """主函数：优化流程逻辑，增强日志输出"""
    logging.info(f"开始处理规则（路径规则: {'包含' if CONFIG['ALLOW_PATH_RULES'] else '排除'}，冲突检测: {CONFIG['CONFLICT_DETECTION_LEVEL']}模式）")
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logging.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    # 读取所有规则来源（过滤空行和注释）
    with sources_file.open("r", encoding="utf8") as f:
        sources = [
            line.strip() for line in f 
            if line.strip() and not line.strip().startswith(("#", "!"))
        ]
    if not sources:
        logging.warning("规则来源文件为空，无规则可处理")
        return
    logging.info(f"加载规则来源: {len(sources)} 个")

    # 并发处理来源
    merged_rules, error_reports, skipped_total, source_stats, total_valid_before_filter = process_sources(sources)
    # 过滤白名单冲突
    final_rules = filter_blacklist(merged_rules)
    # 优化排序逻辑（按类型+域名长度排序，提升可读性）
    sorted_rules = sorted(
        final_rules,
        key=lambda x: (
            not x.startswith("||"),  # 黑名单优先
            x.startswith("@@"),      # 白名单次之
            len(x),                  # 短规则优先
            x                        # 最后按字母序
        )
    )

    # 写入最终规则
    with open(CONFIG["OUTPUT_FILE"], "w", encoding="utf8") as f:
        # 写入头部信息
        f.write(f"# {CONFIG['TITLE']}\n")
        f.write(f"# 版本: {CONFIG['VERSION']}\n")
        f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 规则总数: {len(sorted_rules)}\n")
        f.write(f"# 路径规则: {'包含' if CONFIG['ALLOW_PATH_RULES'] else '排除'}\n\n")
        # 写入规则内容
        f.write("\n".join(sorted_rules))
        # 写入统计注释
        f.write(f"\n\n# 跳过路径型规则: {skipped_total['path_rules']}\n")
        f.write(f"# 跳过元素规则: {skipped_total['element_rules']}\n")
        f.write(f"# 跳过注释行: {skipped_total['comments']}\n")

    # 写入统计信息
    write_stats(len(sorted_rules), total_valid_before_filter, skipped_total, source_stats)

    # 输出处理结果摘要
    logging.info(f"规则处理完成: {len(sorted_rules)} 条有效规则（去重后）")
    if error_reports:
        logging.warning(f"存在 {len(error_reports)} 个来源包含无效规则，详情见日志")

if __name__ == "__main__":
    main()
