import datetime
from pathlib import Path

def filter_dns_rules(source_file: Path, target_file: Path) -> None:
    """
    过滤DNS规则文件，保留特定格式的条目
    
    :param source_file: 源文件路径
    :param target_file: 目标文件路径
    """
    try:
        # 验证源文件存在且可读
        if not source_file.is_file():
            raise FileNotFoundError(f"源文件 {source_file} 不存在")
        
        # 确保目标目录存在
        target_file.parent.mkdir(parents=True, exist_ok=True)

        processed_count = 0
        with source_file.open('r', encoding='utf-8') as src, \
             target_file.open('w', encoding='utf-8') as dst:

            # 批量处理提高性能
            batch_lines = []
            for line in src:
                stripped = line.strip()
                # 精确匹配条件：至少包含4个字符 (||a^)
                if len(stripped) >= 4 and \
                   stripped.startswith("||") and \
                   stripped.endswith("^") and \
                   '#' not in stripped:  # 排除含注释符号的行
                    batch_lines.append(stripped + '\n')
                    processed_count += 1

                # 分批写入提高大文件处理效率
                if len(batch_lines) >= 1000:
                    dst.writelines(batch_lines)
                    batch_lines.clear()

            # 写入剩余内容
            if batch_lines:
                dst.writelines(batch_lines)

        print(f"成功处理 {processed_count} 条规则，输出到 {target_file}")

    except PermissionError as e:
        print(f"权限错误: {str(e)}")
    except UnicodeDecodeError:
        print(f"编码错误: {source_file} 不是有效的UTF-8文件")
    except Exception as e:
        print(f"未知错误: {str(e)}")
        # 清理可能生成的空文件
        if target_file.exists():
            target_file.unlink()
        raise

if __name__ == "__main__":
    # 使用pathlib处理路径
    project_dir = Path(__file__).parent.parent
    source_path = project_dir / "rules.txt"
    target_path = project_dir / "dns.txt"
    
    # 记录开始时间
    start_time = datetime.datetime.now()
    
    try:
        filter_dns_rules(source_path, target_path)
        duration = datetime.datetime.now() - start_time
        print(f"处理完成，耗时 {duration.total_seconds():.2f} 秒")
    except KeyboardInterrupt:
        print("操作被用户中断")