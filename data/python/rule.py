#!/usr/bin/env python3
import os
import re
import requests
import json
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Tuple

# 配置参数 - 集中管理可配置项
CONFIG = {
    "RULE_SOURCES_FILE": "sources.txt",
    "OUTPUT_FILE": "merged-filter.txt",
    "STATS_FILE": "rule_stats.json",
    "LOCAL_RULES": {
        "adblock": "data/rules/adblock.txt",  # 本地广告规则路径
        "whitelist": "data/rules/whitelist.txt"  # 本地白名单路径
    },
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "TITLE": "Merged Rules (Exclude Path Rules)",
    "VERSION": "1.2.0",
    "MAX_WORKERS": 8,  # 增加并发数提升效率
    "TIMEOUT": 20  # 延长超时时间避免网络问题
}

# 正则表达式模块 - 优化匹配精度
REGEX_PATTERNS = {
    "blank": re.compile(r"^\s*$"),
    "domain": re.compile(r"^(@@)?(\|\|)?([a-zA-Z0-9-*_.]+)(\^|\$|/)?"),
    "element": re.compile(r"##.+"),
    "regex_rule": re.compile(r"^/.*/$"),
    "modifier": re.compile(r"\$(~?[\w-]+(=[^,\s]+)?(,~?[\w-]+(=[^,\s]+)?)*)$"),
    "path_rule": re.compile(
        r"^/[^/]+(/.+)?$"
        r"|^[^:\/]+\.[^:\/]+\/[^/]+(/.+)?$"
    ),
    "chinese_char": re.compile(r"[\u4e00-\u9fff]")
}

# 日志配置 - 同时输出到文件和控制台
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("rule_processing.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def is_comment_line(line: str) -> bool:
    """判断是否为中文备注行"""
    line = line.strip()
    return (line.startswith(("#", "!")) and 
            REGEX_PATTERNS["chinese_char"].search(line) is not None)


def is_valid_rule(line: str) -> bool:
    """验证规则有效性"""
    line = line.strip()
    if not line:
        return False
        
    # 排除注释、元素规则和路径规则
    if (is_comment_line(line) or 
        REGEX_PATTERNS["element"].search(line) or 
        REGEX_PATTERNS["path_rule"].match(line)):
        return False
        
    # 验证合法规则类型
    return (REGEX_PATTERNS["domain"].match(line) or 
            REGEX_PATTERNS["regex_rule"].match(line) or 
            REGEX_PATTERNS["modifier"].search(line))


def fix_rule(rule: str) -> str:
    """修复规则语法"""
    rule = rule.strip().strip("|")
    rule = rule.replace("https://", "").replace("http://", "")
    
    # 统一白名单规则格式
    if rule.startswith("@@") and not rule.startswith("@@||"):
        rule = "@@||" + rule[2:]
        
    # 移除重复修饰符
    if "$" in rule:
        parts = rule.split("$")
        if len(parts) > 2:
            rule = parts[0] + "$" + parts[-1]
    return rule


def load_local_rules() -> Tuple[List[str], List[str]]:
    """加载本地规则文件（adblock.txt和whitelist.txt）"""
    adblock_rules = []
    whitelist_rules = []
    
    # 加载本地广告规则
    if os.path.exists(CONFIG["LOCAL_RULES"]["adblock"]):
        with open(CONFIG["LOCAL_RULES"]["adblock"], "r", encoding="utf-8") as f:
            adblock_rules = [line.strip() for line in f if line.strip()]
        logger.info(f"加载本地广告规则: {len(adblock_rules)} 条")
    else:
        logger.warning(f"本地广告规则文件不存在: {CONFIG['LOCAL_RULES']['adblock']}")
    
    # 加载本地白名单规则
    if os.path.exists(CONFIG["LOCAL_RULES"]["whitelist"]):
        with open(CONFIG["LOCAL_RULES"]["whitelist"], "r", encoding="utf-8") as f:
            whitelist_rules = [line.strip() for line in f if line.strip()]
        logger.info(f"加载本地白名单规则: {len(whitelist_rules)} 条")
    else:
        logger.warning(f"本地白名单文件不存在: {CONFIG['LOCAL_RULES']['whitelist']}")
    
    return adblock_rules, whitelist_rules


def fetch_rules(source: str) -> Tuple[List[str], List[str], Dict[str, int]]:
    """从网络或本地文件获取规则并过滤"""
    valid_rules = []
    invalid_rules = []
    skipped = {
        "path_rules": 0,
        "element_rules": 0
    }
    
    try:
        if source.startswith("file:"):
            file_path = source.split("file:")[1].strip()
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        else:
            response = requests.get(
                source,
                headers={"User-Agent": CONFIG["USER_AGENT"]},
                timeout=CONFIG["TIMEOUT"]
            )
            response.raise_for_status()
            lines = response.text.splitlines()
        
        for line in map(str.strip, lines):
            if not line:
                continue
            if is_comment_line(line):
                continue
            if REGEX_PATTERNS["element"].search(line):
                skipped["element_rules"] += 1
                continue
            if REGEX_PATTERNS["path_rule"].match(line):
                skipped["path_rules"] += 1
                continue
            if is_valid_rule(line):
                valid_rules.append(line)
            else:
                invalid_rules.append(line)
                
        logger.info(
            f"处理完成 {source}: "
            f"有效规则 {len(valid_rules)} 条, "
            f"跳过路径规则 {skipped['path_rules']} 条, "
            f"跳过元素规则 {skipped['element_rules']} 条"
        )
            
    except Exception as e:
        logger.error(f"处理 {source} 失败: {str(e)}")
        
    return valid_rules, invalid_rules, skipped


def extract_domain(rule: str) -> str:
    """从规则中提取域名用于冲突检测"""
    if rule.startswith("@@||"):
        rule = rule[4:]
    elif rule.startswith("||"):
        rule = rule[2:]
    
    # 提取域名主体部分
    match = re.match(r"([^/\^\s\$]+)", rule)
    return match.group(1) if match else rule


def filter_blacklist(rules: Set[str]) -> Set[str]:
    """过滤与白名单冲突的黑名单规则"""
    whitelist_domains = {extract_domain(rule) for rule in rules if rule.startswith("@@")}
    filtered_blacklist = [
        rule for rule in rules 
        if not rule.startswith("@@") and extract_domain(rule) not in whitelist_domains
    ]
    return {rule for rule in rules if rule.startswith("@@")} | set(filtered_blacklist)


def write_stats(rule_count: int, total_valid: int, skipped_total: Dict[str, int]) -> None:
    """写入统计信息"""
    stats = {
        "final_rule_count": rule_count,
        "valid_rules_before_filter": total_valid,
        "skipped": skipped_total,
        "title": CONFIG["TITLE"],
        "version": CONFIG["VERSION"],
        "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    with open(CONFIG["STATS_FILE"], "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)
    logger.info(f"统计信息已写入 {CONFIG['STATS_FILE']}")


def process_sources(sources: List[str]) -> Tuple[Set[str], Dict[str, List[str]], Dict[str, int]]:
    """并发处理所有规则来源"""
    merged_rules = set()
    error_reports = {}
    skipped_total = {"path_rules": 0, "element_rules": 0}
    
    # 加载本地规则
    local_adblock, local_whitelist = load_local_rules()
    merged_rules.update(local_adblock)
    merged_rules.update(local_whitelist)
    
    with ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        future_to_source = {executor.submit(fetch_rules, s): s for s in sources}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                valid, invalid, skipped = future.result()
                skipped_total["path_rules"] += skipped["path_rules"]
                skipped_total["element_rules"] += skipped["element_rules"]
                merged_rules.update({fix_rule(rule) for rule in valid})
                if invalid:
                    error_reports[source] = invalid
            except Exception as e:
                logger.error(f"处理来源 {source} 出错: {str(e)}")
    
    return merged_rules, error_reports, skipped_total


def main() -> None:
    """主函数"""
    logger.info("开始处理规则（版本: %s）", CONFIG["VERSION"])
    
    sources_file = Path(CONFIG["RULE_SOURCES_FILE"])
    if not sources_file.exists():
        logger.error(f"未找到规则来源文件: {CONFIG['RULE_SOURCES_FILE']}")
        return

    with sources_file.open("r", encoding="utf-8") as f:
        sources = [line.strip() for line in f if line.strip()]
    
    if not sources:
        logger.warning("规则来源文件为空，仅使用本地规则")
    
    merged_rules, errors, skipped = process_sources(sources)
    final_rules = filter_blacklist(merged_rules)
    
    # 规则排序优化
    sorted_rules = sorted(
        final_rules,
        key=lambda x: (
            not x.startswith("||"),  # 黑名单优先
            not x.startswith("@@"),  # 然后白名单
            x  # 最后按字母序
        )
    )

    # 写入最终规则
    with open(CONFIG["OUTPUT_FILE"], "w", encoding="utf-8") as f:
        f.write("\n".join(sorted_rules))
        f.write(f"\n\n# 最终规则总数: {len(sorted_rules)}\n")
        f.write(f"# 跳过路径型规则总数: {skipped['path_rules']}\n")
        f.write(f"# 跳过元素规则总数: {skipped['element_rules']}\n")
        f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    write_stats(len(sorted_rules), len(merged_rules), skipped)
    logger.info("规则处理完成，输出文件: %s", CONFIG["OUTPUT_FILE"])

    # 输出错误报告
    if errors:
        with open("invalid_rules.log", "w", encoding="utf-8") as f:
            for source, rules in errors.items():
                f.write(f"来源: {source}\n")
                f.write("\n".join(rules) + "\n\n")
        logger.warning(f"发现无效规则，详情见 invalid_rules.log")


if __name__ == "__main__":
    main()
