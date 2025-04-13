import datetime
import os
from pathlib import Path
from zoneinfo import ZoneInfo  # Python 3.9+ 标准库，替代pytz

def process_files():
    """处理文本文件并添加文件头信息"""
    # 时区设置（使用标准库替代pytz）
    beijing_tz = ZoneInfo("Asia/Shanghai")
    beijing_time = datetime.datetime.now(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')
    
    # 使用pathlib处理路径
    base_dir = Path(__file__).parent.parent  # 更安全的路径获取方式
    txt_files = list(base_dir.glob('*.txt'))
    
    for file_path in txt_files:
        # 跳过目录和非文本文件
        if not file_path.is_file():
            print(f"跳过非文件对象：{file_path}")
            continue
            
        try:
            # 读取内容并统计准确行数
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                line_count = len(content.splitlines())  # 更准确的行数统计方式
                
            # 构建文件头模板
            header = f"""\
[个人合并 2.0]
! Title: 去广告规则，酷安反馈反馈
! Homepage: https://github.com/qq5460168/666
! Expires: 12 Hours
! Version: {beijing_time}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}

"""
            # 原子化写入操作
            temp_file = file_path.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(content)
                
            # 替换原文件
            temp_file.replace(file_path)
            print(f"已处理：{file_path.name}")
            
        except UnicodeDecodeError:
            print(f"编码错误：{file_path} 不是UTF-8文本文件")
        except PermissionError:
            print(f"权限不足：无法修改 {file_path}")
        except Exception as e:
            print(f"处理 {file_path} 时发生未知错误：{str(e)}")

if __name__ == '__main__':
    process_files()