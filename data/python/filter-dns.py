#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re
import json

# ==== 配置区 ====
INPUT_FILE = '.././rules.txt'
EXCLUDE_FILE = '../data/rules/exclude.txt'  # 排除文件路径
ALLOW_FILE = '../allow.txt'                # 白名单文件在根目录
TIME_STR = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）'
HOMEPAGE = "https://github.com/qq5460168/AD886"
AUTHOR = "酷安@那个谁520"

# 输出文件和规则格式定义
RULE_FORMATS = [
    {
        "name": "dns",
        "file": ".././dns.txt",
        "header": lambda total: [
            "[Adblock Plus 2.0]",
            f"! Title: 酷安广告规则",
            f"! Homepage: {HOMEPAGE}",
            f"! by: {AUTHOR}",
            f"! Last Updated: {TIME_STR}",
            f"! Total Count: {total}"
        ],
        "line": lambda domain: f"||{domain}^"
    },
    {
        "name": "hosts",
        "file": ".././hosts.txt",
        "header": lambda total: [
            f"# Title: Hosts Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}"
        ],
        "line": lambda domain: f"0.0.0.0 {domain}"
    },
    {
        "name": "qx",
        "file": ".././qx.list",
        "header": lambda total: [
            f"# Title: Quantumult X Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}",
            f"# Quantumult X规则数量: {total}",
            f"# ! Total count: {total}"
        ],
        "line": lambda domain: f"HOST-SUFFIX,{domain},REJECT"
    },
    {
        "name": "shadowrocket",
        "file": ".././Shadowrocket.list",
        "header": lambda total: [
            f"# Title: Shadowrocket Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}",
            f"# Shadowrocket规则数量: {total}",
            f"! Total count: {total}"
        ],
        "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "adclose",
        "file": ".././AdClose.txt",
        "header": lambda total: [
            f"# AdClose 专用广告规则",
            f"# 生成时间: {TIME_STR}",
            f"# 格式：domain, <域名>"
        ],
        "line": lambda domain: f"domain, {domain}"
    },
    {
        "name": "singbox_srs",
        "file": ".././singbox.srs",
        "header": lambda total: [
            f"# Title: SingBox SRS Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}",
            f"# Singbox规则数量: {total}",
            f"! Total count: {total}"
        ],
        "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "singbox_json",
        "file": ".././Singbox.json",
        "header": None,
        "line": None
    },
    {
        "name": "invizible",
        "file": ".././invizible.txt",
        "header": lambda total: [
            f"# Title: Invizible Pro Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}"
        ],
        "line": lambda domain: f"{domain}"
    },
    {
        "name": "clash",
        "file": ".././clash.yaml",
        "header": lambda total: [
            f"# Title: Clash Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}",
            f"# Clash规则数量: {total}",
            f"! Total count: {total}",
            "rules:"
        ],
        "line": lambda domain: f"  - DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "clash_meta",
        "file": ".././clash_meta.yaml",
        "header": lambda total: [
            f"# Title: Clash Meta规则",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}",
            f"# Clash Meta规则数量: {total}",
            f"! Total count: {total}",
            "payload:"
        ],
        "line": lambda domain: f"  - '{domain}'"
    },
    {
        "name": "mrs",
        "file": ".././Clash.mrs",
        "header": lambda total: [
            "# Title: Clash MRS Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}",
            f"# Last Updated: {TIME_STR}",
            f"# MRS规则数量: {total}",
            f"! Total count: {total}",
            "rules:"
        ],
        "line": lambda domain: f"  - DOMAIN-SUFFIX,{domain},REJECT"
    }
]

def log(msg):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")

def is_valid_ad_line(line: str) -> bool:
    return (
        line.startswith("||") and 
        line.endswith("^") and 
        '^' not in line[2:-1] and 
        '/' not in line[2:-1]
    )

def extract_domain(line: str) -> str:
    domain = line[2:-1].lower().strip()
    if '/' in domain:
        domain = domain.split('/')[0]
    return domain

def contains_wildcard(domain: str) -> bool:
    return '*' in domain or '?' in domain

def has_port(domain: str) -> bool:
    return ':' in domain

def is_ipv6(domain: str) -> bool:
    return ':' in domain or ('[' in domain and ']' in domain)

def is_ip_address(domain: str) -> bool:
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$'
    if re.match(ipv4_pattern, domain):
        return True
    if re.match(ipv6_pattern, domain.replace('[', '').replace(']', '')):
        return True
    return False

def has_path(domain: str) -> bool:
    return '/' in domain

def read_domains(input_path: str) -> list:
    if not os.path.exists(input_path):
        log(f"错误: 源规则文件不存在: {input_path}")
        return []
    domains = []
    log(f"开始读取源规则文件: {input_path}")
    with open(input_path, 'r', encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            if line.startswith("@@"):
                continue
            if "m^$important" in line:
                log(f"跳过错误规则: {line}")
                continue
            if is_valid_ad_line(line):
                domain = extract_domain(line)
                if contains_wildcard(domain):
                    log(f"跳过通配符域名: {domain}")
                    continue
                if has_port(domain):
                    log(f"跳过带端口的域名: {domain}")
                    continue
                if is_ipv6(domain):
                    log(f"跳过IPv6地址: {domain}")
                    continue
                if is_ip_address(domain):
                    log(f"跳过纯IP地址: {domain}")
                    continue
                if has_path(domain):
                    log(f"跳过带路径的域名: {domain}")
                    continue
                log(f"有效规则: {line} -> {domain}")
                domains.append(domain)
            else:
                log(f"无效规则: {line}")
    log(f"从源文件读取到 {len(domains)} 个有效域名")
    return list(set(domains))

def read_exclude_domains(path: str) -> set:
    exclude = set()
    if not os.path.exists(path):
        log(f"警告: 排除文件不存在: {path}")
        return exclude
    log(f"开始读取排除文件: {path}")
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                exclude.add(line.lower())
    log(f"从排除文件读取 {len(exclude)} 个域名")
    return exclude

def read_allow_domains(path: str) -> set:
    allow = set()
    if not os.path.exists(path):
        log(f"警告: 白名单文件不存在: {path}")
        return allow
    log(f"开始读取白名单文件: {path}")
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
                if '/' in domain:
                    domain = domain.split('/')[0]
                if '.' in domain and not contains_wildcard(domain):
                    log(f"从白名单规则提取域名: {line} -> {domain}")
                    allow.add(domain.lower())
                else:
                    log(f"跳过无效白名单规则: {line}")
            else:
                domain = line
                if '/' in domain:
                    domain = domain.split('/')[0]
                if '.' in domain and not contains_wildcard(domain):
                    log(f"添加白名单域名: {line} -> {domain}")
                    allow.add(domain.lower())
                else:
                    log(f"跳过无效白名单条目: {line}")
    sample_domains = list(allow)[:5]
    sample_text = ", ".join(sample_domains) + ("..." if len(allow) > 5 else "")
    log(f"从白名单文件读取 {len(allow)} 个域名: {sample_text}")
    return allow

def write_rule_file(format_conf: dict, domains: list):
    fname = format_conf["file"]
    log(f"开始生成规则文件: {fname}")
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
        if format_conf["line"]:
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
    domains = read_domains(INPUT_FILE)
    exclude_domains = read_exclude_domains(EXCLUDE_FILE)
    allow_domains = read_allow_domains(ALLOW_FILE)
    all_exclude = exclude_domains | allow_domains
    log(f"总排除域名数量: {len(all_exclude)} (排除列表: {len(exclude_domains)}, 白名单: {len(allow_domains)})")
    initial_count = len(domains)
    domains = [d for d in domains if d not in all_exclude]
    excluded_count = initial_count - len(domains)
    log(f"排除 {excluded_count} 个域名，剩余 {len(domains)} 个域名")
    domains = sorted(set(domains))
    for fmt in RULE_FORMATS:
        write_rule_file(fmt, domains)
    log("=" * 50)
    log(f"全部规则生成完成! 共生成 {len(domains)} 个域名")
    log("=" * 50)

if __name__ == "__main__":
    main()
