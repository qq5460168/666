#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import datetime
import os

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
            f"# by: {AUTHOR}"
        ],
        "line": lambda domain: f"HOST-SUFFIX,{domain},REJECT"
    },
    {
        "name": "shadowrocket",
        "file": ".././Shadowrocket.list",
        "header": lambda total: [
            f"# Title: Shadowrocket Rules",
            f"# Homepage: {HOMEPAGE}",
            f"# by: {AUTHOR}"
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
            f"# by: {AUTHOR}"
        ],
        "line": lambda domain: f"DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "singbox_json",
        "file": ".././Singbox.json",
        "header": None,  # 特殊处理
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
            f"# by: {AUTHOR}"
        ],
        "line": lambda domain: f"  - DOMAIN-SUFFIX,{domain},REJECT"
    },
    {
        "name": "clash_meta",
        "file": ".././clash_meta.yaml",
        "header": lambda total: [
            f"# Clash Meta 专用规则 (简化域名列表格式)",
            "payload:"
        ],
        "line": lambda domain: f"  - '{domain}'"
    }
]

# ==== 主要逻辑 ====
def log(msg):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")

def is_valid_ad_line(line):
    return line.startswith("||") and line.endswith("^") and len(line) > 3

def extract_domain(line):
    return line[2:-1]

def read_domains(input_path):
    with open(input_path, 'r', encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "m^$important" in line:
                log(f"跳过错误规则: {line}")
                continue
            if is_valid_ad_line(line):
                yield extract_domain(line)

def write_rule_file(format_conf, domains):
    fname = format_conf["file"]
    if format_conf["name"] == "singbox_json":
        # 特殊JSON格式
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
    log(f"生成 {fname}")

def main():
    if not os.path.exists(INPUT_FILE):
        log(f"源规则文件不存在: {INPUT_FILE}")
        return

    domains = sorted(set(read_domains(INPUT_FILE)))
    for fmt in RULE_FORMATS:
        write_rule_file(fmt, domains)

    log("全部规则已生成。")

if __name__ == "__main__":
    main()