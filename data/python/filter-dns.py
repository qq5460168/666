#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re
import json

# ==== 配置区 ====
INPUT_FILE = '.././rules.txt'
EXCLUDE_FILE = '../data/rules/exclude.txt'  # 排除文件路径
ALLOW_FILE = '../allow.txt'                # 修正：白名单文件在根目录
TIME_STR = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）'
HOMEPAGE = "https://github.com/qq5460168/AD886"
AUTHOR = "酷安@那个谁520"

# 输出文件和规则格式定义
RULE_FORMATS = [
    # ... 保持不变 ...
]

def log(msg):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")

def is_valid_ad_line(line):
    # 修复：确保规则没有路径部分和额外分隔符
    return (
        line.startswith("||") and 
        line.endswith("^") and 
        '^' not in line[2:-1] and 
        '/' not in line[2:-1]
    )

def extract_domain(line):
    domain = line[2:-1].lower().strip()
    
    # 修复：移除路径部分（如果存在）
    if '/' in domain:
        domain = domain.split('/')[0]
    
    return domain

def contains_wildcard(domain):
    return '*' in domain or '?' in domain

def has_port(domain):
    return ':' in domain

def is_ipv6(domain):
    return ':' in domain or ('[' in domain and ']' in domain)

def is_ip_address(domain):
    # IPv4地址模式 (如 192.168.1.1)
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    # IPv6地址模式 (简化的检查)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, domain):
        return True
    if re.match(ipv6_pattern, domain.replace('[', '').replace(']', '')):
        return True
    return False

def has_path(domain):
    return '/' in domain

def read_domains(input_path):
    if not os.path.exists(input_path):
        log(f"文件不存在: {input_path}")
        return []
    domains = []
    with open(input_path, 'r', encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
                
            if line.startswith("@@"):
                # 跳过白名单规则，它们将在后续处理中排除
                continue
                
            if "m^$important" in line:
                log(f"跳过错误规则: {line}")
                continue
                
            if is_valid_ad_line(line):
                domain = extract_domain(line)
                
                # 检查通配符
                if contains_wildcard(domain):
                    log(f"跳过通配符域名: {domain}")
                    continue
                    
                # 检查带端口的域名
                if has_port(domain):
                    log(f"跳过带端口的域名: {domain}")
                    continue
                    
                # 检查IPv6地址
                if is_ipv6(domain):
                    log(f"跳过IPv6地址: {domain}")
                    continue
                    
                # 检查纯IP地址
                if is_ip_address(domain):
                    log(f"跳过纯IP地址: {domain}")
                    continue
                    
                # 检查是否包含路径
                if has_path(domain):
                    log(f"跳过带路径的域名: {domain}")
                    continue
                    
                log(f"有效规则: {line} -> {domain}")
                domains.append(domain)
            else:
                log(f"无效规则: {line}")
    return list(set(domains))

def read_exclude_domains(path):
    exclude = set()
    if not os.path.exists(path):
        log(f"排除文件不存在: {path}")
        return exclude
        
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                exclude.add(line.lower())
    log(f"从排除文件读取 {len(exclude)} 个域名")
    return exclude

def read_allow_domains(path):
    """读取白名单文件，提取不带通配符的域名"""
    allow = set()
    if not os.path.exists(path):
        log(f"白名单文件不存在: {path}")
        return allow
        
    log(f"开始读取白名单文件: {path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(('!', '#')):
                continue
                
            # 处理以@@开头的规则
            if line.startswith("@@"):
                # 提取域名部分
                if line.startswith("@@||"):
                    domain = line[4:]  # 去掉开头的@@||
                else:
                    domain = line[2:]  # 去掉开头的@@
                
                # 移除可能的后缀修饰符
                if '^' in domain:
                    domain = domain.split('^', 1)[0]
                if '$' in domain:
                    domain = domain.split('$', 1)[0]
                
                # 移除路径部分
                if '/' in domain:
                    domain = domain.split('/')[0]
                
                # 检查是否为有效域名
                if '.' in domain and not contains_wildcard(domain):
                    log(f"从白名单规则提取域名: {line} -> {domain}")
                    allow.add(domain.lower())
                else:
                    log(f"跳过无效白名单规则: {line}")
            else:
                # 处理纯域名格式
                domain = line
                # 移除路径部分
                if '/' in domain:
                    domain = domain.split('/')[0]
                
                # 检查是否为有效域名
                if '.' in domain and not contains_wildcard(domain):
                    log(f"添加白名单域名: {line} -> {domain}")
                    allow.add(domain.lower())
                else:
                    log(f"跳过无效白名单条目: {line}")
    
    log(f"从白名单文件读取 {len(allow)} 个域名: {', '.join(sorted(allow)[:5])}{'...' if len(allow) > 5 else ''}")
    return allow

def write_rule_file(format_conf, domains):
    fname = format_conf["file"]
    log(f"开始生成: {fname}")
    
    if format_conf["name"] == "singbox_json":
        with open(fname, "w", encoding="utf-8") as f:
            json_data = {
                "version": 1,
                "rules": [
                    {"domain_suffix": domain} for domain in domains
                ]
            }
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        log(f"生成 {fname} (Singbox JSON), 规则数量: {len(domains)}")
        return

    with open(fname, "w", encoding="utf-8") as f:
        if format_conf["header"]:
            header_lines = format_conf["header"](len(domains))
            for h in header_lines:
                f.write(h + '\n')
                
        for domain in domains:
            f.write(format_conf["line"](domain) + '\n')
            
    log(f"生成 {fname}，规则数量: {len(domains)}")

def main():
    log("=" * 50)
    log("开始生成广告规则")
    log("=" * 50)
    
    if not os.path.exists(INPUT_FILE):
        log(f"错误: 源规则文件不存在: {INPUT_FILE}")
        return
        
    # 读取源规则
    domains = read_domains(INPUT_FILE)
    log(f"从源文件读取到有效规则数量: {len(domains)}")
    
    # 读取排除域名
    exclude_domains = read_exclude_domains(EXCLUDE_FILE)
    
    # 读取白名单域名
    allow_domains = read_allow_domains(ALLOW_FILE)
    
    # 合并排除列表
    all_exclude = exclude_domains | allow_domains
    log(f"总排除域名数量: {len(all_exclude)} (排除列表: {len(exclude_domains)}, 白名单: {len(allow_domains)})")
    
    # 应用排除
    initial_count = len(domains)
    domains = [d for d in domains if d not in all_exclude]
    excluded_count = initial_count - len(domains)
    log(f"排除 {excluded_count} 个域名，剩余 {len(domains)} 个域名")
    
    # 排序并去重
    domains = sorted(set(domains))
    
    # 生成所有规则格式
    for fmt in RULE_FORMATS:
        write_rule_file(fmt, domains)
        
    log("=" * 50)
    log(f"全部规则生成完成! 共生成 {len(domains)} 个域名")
    log("=" * 50)

if __name__ == "__main__":
    main()
