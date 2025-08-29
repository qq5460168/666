import sys
import re
from pathlib import Path
from datetime import datetime

class AdGuardProcessor:
    def __init__(self):
        # 初始化计数器
        self.total_black = 0          # 原始黑名单规则总数
        self.total_white = 0          # 白名单规则总数
        self.filtered_count = 0       # 过滤后保留的规则数
        self.skipped_comments = 0     # 跳过的注释行数
        self.invalid_black_rules = 0  # 无效的黑名单规则数

        # 规则匹配正则（支持AdGuard/Hosts等格式）
        self.patterns = {
            "adguard_black": re.compile(r"^\|\|([\w\-\.]+)\^$"),  # ||domain.com^
            "adguard_white": re.compile(r"^@@\|\|([\w\-\.]+)\^$"), # @@||domain.com^
            "hosts_black": re.compile(r"^0\.0\.0\.0\s+([\w\-\.]+)$"), # 0.0.0.0 domain.com
            "hosts_white": re.compile(r"^127\.0\.0\.1\s+([\w\-\.]+)$")  # 127.0.0.1 domain.com
        }

    def process_blacklist(self, black_path, white_path, output_path):
        """处理黑名单并应用白名单过滤"""
        # 加载白名单域名（支持多种格式）
        white_domains = self._load_white_domains(white_path)
        self.total_white = len(white_domains)
        print(f"已加载 {self.total_white} 条白名单规则")

        # 处理黑名单并过滤
        with open(black_path, 'r', encoding='utf-8') as black_file, \
             open(output_path, 'w', encoding='utf-8') as out_file:

            # 写入文件头部信息
            self._write_header(out_file, black_path, white_path)

            for line in black_file:
                line = line.strip()
                if not line:
                    continue  # 跳过空行

                # 处理注释行
                if line.startswith(('#', '!')):
                    self.skipped_comments += 1
                    # 保留关键元数据注释（如版本、更新时间）
                    if any(keyword in line.lower() for keyword in ['title', 'version', 'updated']):
                        out_file.write(line + '\n')
                    continue

                self.total_black += 1
                # 提取黑名单规则中的域名（支持多种格式）
                domain = self._extract_domain(line, is_blacklist=True)
                if not domain:
                    self.invalid_black_rules += 1
                    print(f"⚠️ 无效黑名单规则: {line}")
                    continue

                # 检查是否在白名单中
                if domain not in white_domains:
                    out_file.write(line + '\n')
                    self.filtered_count += 1

    def _load_white_domains(self, white_path):
        """加载白名单域名（支持AdGuard和Hosts格式）"""
        domains = set()
        if not Path(white_path).exists():
            print(f"⚠️ 白名单文件不存在: {white_path}，将跳过过滤")
            return domains

        with open(white_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('#', '!')):
                    continue  # 跳过注释和空行

                domain = self._extract_domain(line, is_blacklist=False)
                if domain:
                    domains.add(domain)
        return domains

    def _extract_domain(self, line, is_blacklist):
        """从规则中提取域名（支持多种格式）"""
        if is_blacklist:
            # 匹配黑名单规则格式
            match = self.patterns["adguard_black"].match(line) or self.patterns["hosts_black"].match(line)
        else:
            # 匹配白名单规则格式
            match = self.patterns["adguard_white"].match(line) or self.patterns["hosts_white"].match(line)
        
        return match.group(1).lower() if match else None

    def _write_header(self, out_file, black_path, white_path):
        """写入处理后的文件头部信息"""
        header = [
            f"! 过滤后的广告规则",
            f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"! 源黑名单: {Path(black_path).name}",
            f"! 源白名单: {Path(white_path).name}",
            f"! -------------------------"
        ]
        out_file.write('\n'.join(header) + '\n\n')

    def generate_report(self):
        """生成详细处理报告"""
        return (
            f"\n处理报告:\n"
            f"1. 黑名单规则: {self.total_black} 条\n"
            f"   - 有效规则: {self.total_black - self.invalid_black_rules} 条\n"
            f"   - 无效规则: {self.invalid_black_rules} 条\n"
            f"2. 白名单规则: {self.total_white} 条\n"
            f"3. 过滤后保留: {self.filtered_count} 条\n"
            f"4. 跳过注释行: {self.skipped_comments} 条"
        )

def main():
    try:
        processor = AdGuardProcessor()
        
        # 路径处理（更健壮的层级计算）
        script_path = Path(__file__).resolve()
        base_dir = script_path.parents[3]  # 根据实际目录结构调整层级
        
        # 定义文件路径
        black_path = base_dir / "dns.txt"
        white_path = base_dir / "allow.txt"
        output_path = base_dir / "adblock-filtered.txt"

        # 验证输入文件是否存在
        if not black_path.exists():
            raise FileNotFoundError(f"黑名单文件不存在: {black_path}")

        print(f"开始处理...")
        print(f"黑名单: {black_path}")
        print(f"白名单: {white_path}")
        print(f"输出文件: {output_path}")

        processor.process_blacklist(black_path, white_path, output_path)
        print(processor.generate_report())
        print(f"✅ 处理完成，结果已保存至 {output_path}")
        sys.exit(0)

    except Exception as e:
        print(f"::error::处理失败: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
