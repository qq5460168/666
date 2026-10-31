#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re
import json
from collections import OrderedDict

# ==== 配置区 ====
INPUT_FILE = '.././rules.txt'
EXCLUDE_FILE = '../data/rules/exclude.txt'  # 排除文件路径
ALLOW_FILE = '../allow.txt'                # 白名单文件在根目录
# 北京时间（UTC+8）：显式指定时区，避免 CI 运行在 UTC 时区时显示成 UTC 时间却标注北京时间
BEIJING_TZ = datetime.timezone(datetime.timedelta(hours=8))
TIME_STR = datetime.datetime.now(BEIJING_TZ).strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）'
HOMEPAGE = "https://github.com/qq5460168/AD886"
AUTHOR = "酷安@那个谁520"

# 来源分区头标记（merge.py 按来源分区块写入 rules.txt）
RE_SRC = re.compile(r"^!\s*📋\s*规则来源：\s*(.+?)\s*$")
RE_URL = re.compile(r"^!\s*🔗\s*原始地址：\s*(.+?)\s*$")
DEFAULT_SECTION = "未标注来源"

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
            f"! Total count: {total}"
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
            f"# Last Updated: {TIME_STR}",
            f"# Total count: {total}"
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
            f"# Total count: {total}"
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
            f"# 格式：domain, <域名>",
            f"# Total count: {total}"
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
            f"# Last Updated: {TIME_STR}",
            f"# Total count: {total}"
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
    }
]

def log(msg):
    print(f"[{datetime.datetime.now(BEIJING_TZ):%Y-%m-%d %H:%M:%S}] {msg}")

def is_valid_ad_line(line):
    # 确保规则没有路径部分和额外分隔符
    return (
        line.startswith("||") and 
        line.endswith("^") and 
        '^' not in line[2:-1] and 
        '/' not in line[2:-1]
    )

def extract_domain(line):
    domain = line[2:-1].lower().strip()
    
    # 移除路径部分（如果存在）
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
    """读取源规则文件，返回 (domains_set, OrderedDict{domain: 来源信息})

    解析 rules.txt 中 merge.py 写入的来源分区头
    （! 📋 规则来源：xxx / ! 🔗 原始地址：yyy），
    使 dns.txt 能按来源分区块输出，排查误杀一步定位。
    """
    if not os.path.exists(input_path):
        log(f"错误: 源规则文件不存在: {input_path}")
        return set(), OrderedDict()
        
    domains = set()
    domain_source = OrderedDict()   # domain -> {"name": 来源名, "url": 原始地址}
    cur_src = {"name": DEFAULT_SECTION, "url": ""}
    log(f"开始读取源规则文件: {input_path}")
    
    with open(input_path, 'r', encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('!'):
                # 解析来源分区头
                m = RE_SRC.match(line)
                if m:
                    cur_src = {"name": m.group(1), "url": ""}
                    continue
                m = RE_URL.match(line)
                if m:
                    cur_src["url"] = m.group(1)
                    continue
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
                    
                if domain not in domains:
                    domains.add(domain)
                    domain_source[domain] = {"name": cur_src["name"], "url": cur_src["url"]}
            else:
                log(f"无效规则: {line}")
                
    log(f"从源文件读取到 {len(domains)} 个有效域名，来源分区 {len({v['name'] for v in domain_source.values()})} 个")
    return domains, domain_source

def read_exclude_domains(path):
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

def read_allow_domains(path):
    """读取白名单文件，提取不带通配符的域名"""
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
    
    # 记录前5个白名单域名作为示例
    sample_domains = list(allow)[:5]
    sample_text = ", ".join(sample_domains) + ("..." if len(allow) > 5 else "")
    log(f"从白名单文件读取 {len(allow)} 个域名: {sample_text}")
    return allow

def write_dns_with_sections(filepath, domain_source, total):
    """dns.txt 按来源分区块输出，头部带来源汇总

    来源汇总与分区行数一致，保证排查误杀时：
      看到域名 -> 向上找最近的「! 📋 规则来源：」即可定位上游。
    """
    # 按来源分组（保持 rules.txt 中来源出现的顺序）
    sections = OrderedDict()
    for domain, info in domain_source.items():
        name = info["name"]
        if name not in sections:
            sections[name] = {"url": info["url"], "domains": []}
        sections[name]["domains"].append(domain)

    per_source = {name: len(sec["domains"]) for name, sec in sections.items()}
    n_src = len(sections)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("[Adblock Plus 2.0]\n")
        f.write(f"! Title: 酷安广告规则\n")
        f.write(f"! Homepage: {HOMEPAGE}\n")
        f.write(f"! by: {AUTHOR}\n")
        f.write(f"! Last Updated: {TIME_STR}\n")
        f.write(f"! Total count: {total}\n")
        # 来源汇总
        f.write("\n! ────────────── 来源汇总 ──────────────\n")
        for name, n in per_source.items():
            f.write(f"!   {n:>7} 条  {name}\n")
        f.write("! ────────────────────────────────────────\n")

        # 分区输出
        for name, sec in sections.items():
            f.write("\n! ==============================================\n")
            f.write(f"! 📋 规则来源：{name}\n")
            if sec["url"]:
                f.write(f"! 🔗 原始地址：{sec['url']}\n")
            f.write(f"! 📊 本区规则：{len(sec['domains'])} 条\n")
            f.write("! ==============================================\n")
            for d in sec["domains"]:
                f.write(f"||{d}^\n")

    log(f"生成 {filepath}，规则数量: {total}（{n_src} 个来源分区）")

def write_rule_file(format_conf, domains):
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
                
        for domain in domains:
            f.write(format_conf["line"](domain) + '\n')
            
    log(f"生成 {fname}，规则数量: {len(domains)}")

def main():
    log("=" * 50)
    log("开始生成广告规则")
    log("=" * 50)
    
    # 确保输入文件存在
    if not os.path.exists(INPUT_FILE):
        log(f"错误: 源规则文件不存在: {INPUT_FILE}")
        return
        
    # 读取源规则（含来源分区信息）
    domains, domain_source = read_domains(INPUT_FILE)
    
    # 读取排除域名
    exclude_domains = read_exclude_domains(EXCLUDE_FILE)
    
    # 读取白名单域名
    allow_domains = read_allow_domains(ALLOW_FILE)
    
    # 合并排除列表
    all_exclude = exclude_domains | allow_domains
    log(f"总排除域名数量: {len(all_exclude)} (排除列表: {len(exclude_domains)}, 白名单: {len(allow_domains)})")
    
    # 应用排除
    initial_count = len(domains)
    kept = [d for d in domains if d not in all_exclude]
    excluded_count = initial_count - len(kept)
    log(f"排除 {excluded_count} 个域名，剩余 {len(kept)} 个域名")
    
    # 排序
    domains = sorted(set(kept))
    # 保留来源信息（只含未被排除的域名）
    kept_source = OrderedDict((d, domain_source[d]) for d in domains if d in domain_source)
    
    # 生成所有规则格式
    for fmt in RULE_FORMATS:
        if fmt["name"] == "dns":
            write_dns_with_sections(fmt["file"], kept_source, len(domains))
        else:
            write_rule_file(fmt, domains)
        
    log("=" * 50)
    log(f"全部规则生成完成! 共生成 {len(domains)} 个域名")
    log("=" * 50)

if __name__ == "__main__":
    main()
