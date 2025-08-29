import logging
from pathlib import Path
from typing import Set, List, Tuple

def load_rules(file_path: Path) -> Set[str]:
    """加载规则文件并返回去重后的规则集合"""
    rules = set()
    if not file_path.exists():
        logging.warning(f"规则文件不存在: {file_path}")
        return rules
        
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # 跳过注释和空行
            if not line or line.startswith(('!', '#')):
                continue
            rules.add(line)
    logging.info(f"从 {file_path.name} 加载 {len(rules)} 条规则")
    return rules

def extract_domains(rules: Set[str]) -> Tuple[Set[str], Set[str]]:
    """分离黑名单和白名单规则中的域名"""
    black_domains = set()
    white_domains = set()
    
    for rule in rules:
        # 处理白名单规则（@@开头）
        if rule.startswith("@@||"):
            domain = rule[4:].split('^')[0].lower()  # 提取域名部分
            white_domains.add(domain)
        # 处理黑名单规则（||开头）
        elif rule.startswith("||"):
            domain = rule[2:].split('^')[0].lower()  # 提取域名部分
            black_domains.add(domain)
    
    return black_domains, white_domains

def filter_blacklist_conflicts(black_rules: Set[str], white_domains: Set[str]) -> Set[str]:
    """过滤与白名单冲突的黑名单规则"""
    filtered = set()
    for rule in black_rules:
        if rule.startswith("||"):
            domain = rule[2:].split('^')[0].lower()
            if domain not in white_domains:
                filtered.add(rule)
            else:
                logging.debug(f"排除与白名单冲突的规则: {rule}")
        else:
            filtered.add(rule)  # 保留非标准格式规则
    
    logging.info(f"黑名单规则过滤前: {len(black_rules)}, 过滤后: {len(filtered)}")
    return filtered

def merge_and_sort_rules(black_rules: Set[str], white_rules: Set[str]) -> List[str]:
    """合并规则并按 黑名单→白名单→字母序 排序"""
    # 排序键函数：黑名单规则排在前，白名单次之，再按字母序
    def sort_key(rule: str) -> Tuple[int, int, str]:
        if rule.startswith("||"):
            return (0, 0, rule)  # 黑名单规则优先级0
        elif rule.startswith("@@||"):
            return (1, 0, rule)  # 白名单规则优先级1
        return (2, 0, rule)     # 其他规则优先级2
    
    # 合并并排序
    all_rules = list(black_rules.union(white_rules))
    all_rules.sort(key=sort_key)
    return all_rules

def process_rule_conflicts(blacklist_path: str, whitelist_path: str, output_path: str):
    """处理规则冲突与去重的主函数"""
    black_path = Path(blacklist_path)
    white_path = Path(whitelist_path)
    
    # 1. 加载原始规则
    black_rules = load_rules(black_path)
    white_rules = load_rules(white_path)
    
    # 2. 提取白名单域名用于冲突检测
    _, white_domains = extract_domains(white_rules)
    
    # 3. 过滤黑名单中的冲突规则
    filtered_black = filter_blacklist_conflicts(black_rules, white_domains)
    
    # 4. 合并去重并排序
    final_rules = merge_and_sort_rules(filtered_black, white_rules)
    
    # 5. 写入结果
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_rules))
    
    logging.info(f"规则处理完成，输出至 {output_path}，总规则数: {len(final_rules)}")

# 使用示例
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    process_rule_conflicts(
        blacklist_path="../rules.txt",
        whitelist_path="../allow.txt",
        output_path="../final_rules.txt"
    )
