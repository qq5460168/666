#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re
import json
from pathlib import Path

# 配置区
CONFIG = {
    "INPUT_FILE": "../rules.txt",
    "EXCLUDE_FILE": "../data/rules/exclude.txt",  # 排除规则路径
    "ALLOW_FILE": "../allow.txt",
    "LOCAL_RULES": "../data/rules/adblock.txt",   # 本地广告规则
    "TIME_STR": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）',
    "HOMEPAGE": "https://github.com/qq5460168/AD886",
    "AUTHOR": "酷安@那个谁520"
}

# 输出规则格式定义
RULE_FORMATS = [
    {
        "name": "dns",
        "file": "../dns.txt",
        "header": lambda total: [
            "[Adblock Plus 2.0]",
            f"! Title: 酷安广告规则",
            f"! Homepage: {CONFIG['HOMEPAGE']}",
            f"! by: {CONFIG['AUTHOR']}",
            f"! Last Updated: {CONFIG['TIME_STR']}",
            f"! Total Count: {total}"
        ],
        "line": lambda domain: f"||{domain}^"
    },
    {
        "name": "hosts",
        "file": "../hosts.txt",
        "header": lambda total: [
            f"# Title: Hosts Rules",
            f"# Homepage: {CONFIG['HOMEPAGE']}",
            f"# by: {CONFIG['AUTHOR']}",
            f"# Last Updated: {CONFIG['TIME_STR']}"
        ],
        "line": lambda domain: f"0.0.0.0 {domain}"
    },
    {
        "name": "adclose",
        "file": "../AdClose.txt",
        "header": lambda total: [
            f"# AdClose 专用广告规则",
            f"# 生成时间: {CONFIG['TIME_STR']}",
            f"# 格式：domain, <域名>"
        ],
        "line": lambda domain: f"domain, {domain}"
    },
    {
        "name": "invizible",
        "file": "../invizible.txt",
        "header": lambda total: [
            f"# Title: Invizible Pro Rules",
            f"# Homepage: {CONFIG['HOMEPAGE']}",
            f"# by: {CONFIG['AUTHOR']}",
            f"# Last Updated: {CONFIG['TIME_STR']}"
        ],
        "line": lambda domain: f"{domain}"
    },
    {
        "name": "clash",
        "file": "../clash.yaml",
        "header": lambda total: [
            f"# Title: Clash Rules",
            f"# Homepage: {CONFIG['HOMEPAGE']}",
            f"# by: {CONFIG['AUTHOR']}",
            f"# Last Updated: {CONFIG['TIME_STR']}",
            f"# Clash规则数量: {total}",
            "rules:"
        ],
        "line": lambda domain: f"  - DOMAIN-SUFFIX,{domain},REJECT"
    }
]


def log(msg: str) -> None:
    """日志输出函数"""
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")


def is_valid_ad_line(line: str) -> bool:
    """验证广告规则格式有效性"""
    return (
        line.startswith("||") and 
        line.endswith("^") and 
        '^' not in line[2:-1] and 
        '/' not in line[2:-1]
    )


def extract_domain(line: str) -> str:
    """从规则中提取域名"""
    domain = line[2:-1].lower().strip()
    if '/' in domain:
        domain = domain.split('/')[0]
    return domain


def load_local_adblock_rules() -> List[str]:
    """加载本地广告规则"""
    domains = []
    if not os.path.exists(CONFIG["LOCAL_RULES"]):
        log(f"警告: 本地广告规则文件不存在 {CONFIG['LOCAL_RULES']}")
        return domains
        
    with open(CONFIG["LOCAL_RULES"], "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if is_valid_ad_line(line):
                domain = extract_domain(line)
                domains.append(domain)
    
    log(f"加载本地广告规则: {len(domains)} 条")
    return domains


def read_domains(input_path: str) -> List[str]:
    """从输入文件读取有效域名"""
    domains = load_local_adblock_rules()  # 先加载本地规则
    
    if not os.path.exists(input_path):
        log(f"错误: 源规则文件不存在 {input_path}")
        return list(set(domains))
        
    log(f"读取源规则文件: {input_path}")
    with open(input_path, 'r', encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(('!', '@@')):
                continue
                
            if "m^$important" in line:
                log(f"跳过错误规则: {line}")
                continue
                
            if is_valid_ad_line(line):
                domain = extract_domain(line)
                
                # 过滤无效格式
                if ('*' in domain or '?' in domain or 
                    ':' in domain or re.match(r'^\d+\.\d+\.\d+\.\d+$', domain)):
                    log(f"跳过无效域名: {domain}")
                    continue
                    
                domains.append(domain)
            else:
                log(f"跳过无效规则: {line}")
                
    unique_domains = list(set(domains))
    log(f"共提取有效域名: {len(unique_domains)} 个")
    return unique_domains


def read_exclude_domains(path: str) -> Set[str]:
    """读取需排除的域名"""
    exclude = set()
    if not os.path.exists(path):
        log(f"警告: 排除文件不存在 {path}")
        return exclude
        
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                exclude.add(line.lower())
                
    log(f"加载排除域名: {len(exclude)} 个")
    return exclude


def read_allow_domains(path: str) -> Set[str]:
    """读取白名单域名"""
    allow = set()
    if not os.path.exists(path):
        log(f"警告: 白名单文件不存在 {path}")
        return allow
        
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(('!', '#')):
                continue
                
            if line.startswith("@@"):
                domain = line[4:] if line.startswith("@@||") else line[2:]
                if '^' in domain:
                    domain = domain.split('^', 1)[0]
                if '$' in domain:
                    domain = domain.split('$', 1)[0]
            else:
                domain = line.split('/')[0]
                
            if '.' in domain and '*' not in domain:
                allow.add(domain.lower())
            else:
                log(f"跳过无效白名单: {line}")
    
    log(f"加载白名单域名: {len(allow)} 个")
    return allow


def write_rules(domains: List[str]) -> None:
    """生成各种格式的规则文件"""
    total = len(domains)
    log(f"开始生成 {total} 条规则到目标文件")
    
    for fmt in RULE_FORMATS:
        try:
            # 创建输出目录
            output_path = Path(fmt["file"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 写入头部
            with open(fmt["file"], "w", encoding="utf-8") as f:
                if fmt["header"]:
                    f.write("\n".join(fmt["header"](total)) + "\n")
                
                # 写入规则
                for domain in sorted(domains):
                    f.write(fmt["line"](domain) + "\n")
            
            log(f"已生成 {fmt['name']} 规则: {fmt['file']}")
            
        except Exception as e:
            log(f"生成 {fmt['name']} 规则失败: {str(e)}")


def main() -> None:
    """主函数"""
    log("开始处理DNS规则")
    
    # 读取并处理域名
    raw_domains = read_domains(CONFIG["INPUT_FILE"])
    exclude_domains = read_exclude_domains(CONFIG["EXCLUDE_FILE"])
    allow_domains = read_allow_domains(CONFIG["ALLOW_FILE"])
    
    # 过滤排除和白名单域名
    filtered = [
        d for d in raw_domains 
        if d not in exclude_domains and d not in allow_domains
    ]
    
    # 去重并排序
    final_domains = sorted(list(set(filtered)))
    
    # 写入规则文件
    write_rules(final_domains)
    
    log(f"DNS规则处理完成，最终规则数: {len(final_domains)}")


if __name__ == "__main__":
    main()
