#!/usr/bin/env python3
import os
import re
import time
import sqlite3  # Python 内置模块，无需安装
import subprocess
from pathlib import Path  # 优先使用标准库
from typing import Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# 兼容旧版Python（若无pathlib则尝试pathlib2）
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path  # type: ignore

# DNS服务器配置
DOMESTIC_DNS = [
    '223.5.5.5',    # AliDNS
    '119.29.29.29', # DNSPod
    '101.226.4.6'   # 360
]

INTERNATIONAL_DNS = [
    '8.8.8.8',      # Google
    '1.1.1.1',      # Cloudflare
    '9.9.9.11'      # Quad9
]

# SmartDNS基础配置
SMARTDNS_CONFIG = """bind [::]:5053 -no-rule-addr -no-rule-nameserver -no-dualstack-selection -force-aaaa-soa -no-speed-check -no-cache
log-level notice
log-file /tmp/smartdns.log
dualstack-ip-selection no
force-AAAA-SOA yes
response-mode fastest-response
"""

class DNSChecker:
    def __init__(self):
        self.cache_db = Path('/tmp/dns_cache.db')
        self.init_cache()
        self.dns_tool = 'dig' if platform.system() != 'Windows' else 'nslookup'
        self.smartdns_process = None

    def init_cache(self):
        """初始化SQLite缓存数据库"""
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS dns_cache (
                domain TEXT PRIMARY KEY,
                resolvable INTEGER,
                timestamp INTEGER
            )''')

    def check_cache(self, domain):
        """检查缓存结果"""
        with sqlite3.connect(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT resolvable FROM dns_cache WHERE domain=?', (domain,))
            result = cursor.fetchone()
            return bool(result[0]) if result else None

    def update_cache(self, domain, resolvable):
        """更新缓存"""
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute('INSERT OR REPLACE INTO dns_cache VALUES (?, ?, ?)',
                         (domain, int(resolvable), int(time.time())))

    def start_smartdns(self):
        """启动SmartDNS服务"""
        config_path = Path('/tmp/smartdns.conf')
        with open(config_path, 'w') as f:
            f.write(SMARTDNS_CONFIG)
            for dns in DOMESTIC_DNS + INTERNATIONAL_DNS:
                f.write(f"server {dns}\n")
        
        self.smartdns_process = subprocess.Popen(
            ['smartdns', '-f', '-c', str(config_path)],
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)  # 等待服务启动

    def stop_smartdns(self):
        """停止SmartDNS服务"""
        if self.smartdns_process:
            self.smartdns_process.terminate()

    def query_dns(self, domain, dns_server):
        """执行DNS查询（多平台兼容）"""
        try:
            if self.dns_tool == 'dig':
                cmd = ['dig', f'@{dns_server}', domain, 'A', '+short', '+time=2', '+tries=1']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                return bool(result.stdout.strip())
            else:  # nslookup for Windows
                cmd = ['nslookup', domain, dns_server]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                return "Name:" not in result.stdout
        except:
            return False

    def is_domain_resolvable(self, domain):
        """检查域名是否可解析（带缓存和重试）"""
        # 检查缓存
        cached = self.check_cache(domain)
        if cached is not None:
            print(f"::debug::Using cached result for {domain}")  # GitHub Actions日志
            return cached

        # 并发查询DNS
        dns_servers = DOMESTIC_DNS + INTERNATIONAL_DNS
        max_workers = min(6, len(dns_servers))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.query_dns, domain, dns): dns for dns in dns_servers}
            
            for future in as_completed(futures, timeout=5):
                if future.result():
                    self.update_cache(domain, True)
                    return True

        self.update_cache(domain, False)
        return False

def extract_domains(file_path):
    """从规则文件提取域名"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='latin-1') as f:
            content = f.read()
    
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('!', '#', '@')):
            continue
        
        # 清理AdBlock语法
        domain = re.sub(r'^\|\||\^|\$.*$', '', line).split('/')[0]
        if re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', domain.lower()):
            domains.add(domain.lower())
    
    return domains

def filter_rules(input_file, output_file, checker):
    """过滤无法解析的域名"""
    domains = extract_domains(input_file)
    total = len(domains)
    print(f"::group::Processing {input_file} ({total} domains)")  # GitHub Actions分组日志
    
    resolvable_rules = set()
    start_time = time.time()
    
    for i, domain in enumerate(domains, 1):
        if checker.is_domain_resolvable(domain):
            resolvable_rules.add(f"||{domain}^")
        
        # 进度报告
        if i % 100 == 0 or i == total:
            elapsed = time.time() - start_time
            print(f"::notice::Progress: {i}/{total} ({i/total:.1%}), Resolvable: {len(resolvable_rules)}, Time: {elapsed:.1f}s")
    
    # 写入输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('! Title: DNS-filtered rules\n')
        f.write('! Last updated: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
        f.write('\n'.join(sorted(resolvable_rules)))
    
    print(f"::endgroup::Finished. Kept {len(resolvable_rules)}/{total} rules")

def main():
    checker = DNSChecker()
    try:
        checker.start_smartdns()
        
        # 自动检测输入/输出目录
        workspace = Path(os.getenv('GITHUB_WORKSPACE', '.'))
        tmp_dir = workspace / 'tmp'
        output_dir = workspace / 'output'
        output_dir.mkdir(exist_ok=True)
        
        # 处理所有规则文件
        for input_file in tmp_dir.glob('*.txt'):
            output_file = output_dir / f"filtered_{input_file.name}"
            print(f"::group::Processing {input_file.name}")
            filter_rules(input_file, output_file, checker)
            print(f"::endgroup::")
            
    finally:
        checker.stop_smartdns()

if __name__ == '__main__':
    main()