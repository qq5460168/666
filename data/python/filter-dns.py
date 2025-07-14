#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os
import re

# ==== 配置区 ====
INPUT_FILE = '.././rules.txt'
TIME_STR = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '（北京时间）'
HOMEPAGE = "https://github.com/qq5460168/AD886"
AUTHOR = "酷安@那个谁520"

# 输出文件和规则格式定义（已取消 “Update Time:” 信息）
RULE_FORMATS = [
    {
        "name": "dns",
        "file": ".././dns.txt",
        "header": lambda total: [
            "[Adblock Plus 2.0]",
            f"! Title: 酷安反馈反馈",
            f"! Homepage: {HOMEPAGE}",
            f"! by: {AUTHOR}",
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
            f"# by: {AUTHOR}"
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
            f"# Quantumult X规则数量: {total}",
            f"# ! Total count: {total}"  # 在这里添加了 #，将其作为注释
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
            f"Shadowrocket规则数量: {total}",
            f"! Total count: {total}"
        ],
        "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "adclose",
        "file": ".././AdClose.txt",
        "header": lambda total: [
            f"# AdClose 专用广告规则",
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
            f"Singbox规则数量: {total}",
            f"! Total count: {total}"
        ],
        "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "singbox_json",
        "file": ".././Singbox.json",
        "header": None,  # 特殊处理，生成 JSON 格式
        "line": None
    },
    {
        "name": "invizible",
        "file": ".././invizible.txt",
        "header": lambda total: [
            f"# Title: Invizible Pro Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}"
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
            f"Clash规则数量: {total}",
            f"! Total count: {total}"
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
            f"Clash Meta规则数量: {total}",
            f"! Total count: {total}",
            "payload:"
        ],
        "line": lambda domain: f"  - '{domain}'"
    }
]

# ==== 主要逻辑 ====
def log(msg):
    """统一打印日志，包含当前时间戳"""
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")

def is_valid_ad_line(line):
    """
    检查广告过滤规则是否符合格式：
    规则必须以 "||" 开头，以 "^" 结尾，且长度大于 3。
    """
    return line.startswith("||") and line.endswith("^") and len(line) > 3

def is_valid_whitelist_rule(line):
    """
    检查白名单规则是否符合正确格式：
    正确格式为：@@||域名^ 或 @@||域名^$options，不允许存在额外 "|" 符号。
    """
    pattern = r"^@@\|\|[^|]+\^(?:\$.*)?$"
    return re.match(pattern, line) is not None

def correct_whitelist_rule(line):
    """
    自动优化白名单规则格式：
      1. 如果规则未以 '@@||' 开头，则修正。
      2. 去除规则中 '^' 前多余的 "|" 符号。
    """
    original = line
    if not line.startswith("@@||"):
        if line.startswith("@@|"):
            line = line.replace("@@|", "@@||", 1)
        else:
            line = "@@||" + line[2:]
    m = re.match(r'(@@\|\|.+?)(\|+)(\^.*)$', line)
    if m:
        line = m.group(1) + m.group(3)
    if line != original:
        log(f"自动修正白名单规则: 原规则: {original} 修改为: {line}")
    else:
        log(f"白名单规则格式正确: {line}")
    return line

def extract_domain(line):
    """从规则中提取域名部分，假定规则格式为 '||域名^'"""
    return line[2:-1]

def read_domains(input_path):
    """读取 INPUT_FILE 文件，提取所有有效的广告过滤规则所对应的域名"""
    if not os.path.exists(input_path):
        log(f"文件不存在: {input_path}")
        return []
    domains = []
    with open(input_path, 'r', encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("@@"):
                correct_whitelist_rule(line)
                continue
            if "m^$important" in line:
                log(f"跳过错误规则: {line}")
                continue
            if is_valid_ad_line(line):
                log(f"有效规则: {line}")
                domains.append(extract_domain(line))
            else:
                log(f"无效规则: {line}")
    return list(set(domains))

def write_rule_file(format_conf, domains):
    """根据给定的格式配置生成输出规则文件"""
    fname = format_conf["file"]
    if format_conf["name"] == "singbox_json":
        with open(fname, "w", encoding="utf-8") as f:
            f.write('{\n')
            f.write('  "name": "Singbox Ads Rule",\n')
            f.write('  "type": "domain",\n')
            f.write('  "payload": [\n')
            for i, domain in enumerate(domains):
                comma = ',' if i < len(domains) - 1 else ''
                f.write(f'    "{domain}"{comma}\n')
            f.write('  ]\n}')
        log(f"生成 {fname} (Singbox JSON)")
        return

    with open(fname, "w", encoding="utf-8") as f:
        header = format_conf["header"](len(domains))
        for h in header:
            f.write(h + '\n')
        for domain in domains:
            f.write(format_conf["line"](domain) + '\n')
    log(f"生成 {fname}，规则数量: {len(domains)}")

def main():
    """主程序"""
    if not os.path.exists(INPUT_FILE):
        log(f"源规则文件不存在: {INPUT_FILE}")
        return
    domains = sorted(set(read_domains(INPUT_FILE)))
    if not domains:
        log("未发现有效规则，请检查 INPUT_FILE 内容是否符合要求。")
        return
    log(f"从 {INPUT_FILE} 读取到有效规则数量: {len(domains)}")
    for fmt in RULE_FORMATS:
        write_rule_file(fmt, domains)
    log("全部规则已生成。")

if __name__ == "__main__":
    main()