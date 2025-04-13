import os
import tempfile

def deduplicate_file(file_path):
    """去重文件并保留原始行顺序"""
    seen = set()  # 用于记录已出现过的行
    unique_lines = []  # 保存去重后且保持顺序的结果
    
    try:
        # 第一阶段：读取并过滤重复行
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line not in seen:
                    seen.add(line)
                    unique_lines.append(line)  # 按首次出现顺序记录
    except UnicodeDecodeError:
        print(f"错误：文件 '{file_path}' 不是UTF-8编码，已跳过。")
        return

    # 第二阶段：写入临时文件
    temp_fd, temp_name = tempfile.mkstemp(
        dir=os.path.dirname(file_path),  # 与原文件同目录
        suffix='.tmp'
    )
    os.close(temp_fd)  # 关闭文件描述符，后续使用文件路径操作
    
    try:
        with open(temp_name, 'w', encoding='utf-8') as fo:
            fo.writelines(unique_lines)  # 写入去重后的内容
        
        # 第三阶段：原子替换原文件（避免中断导致数据丢失）
        os.replace(temp_name, file_path)
    except Exception as e:
        print(f"写入文件 '{file_path}' 失败: {e}")
        if os.path.exists(temp_name):
            os.remove(temp_name)  # 清理临时文件
        raise

def process_directory(target_dir):
    """处理指定目录下的所有txt文件"""
    print(f"开始处理目录: {target_dir}")
    
    for filename in os.listdir(target_dir):
        file_path = os.path.join(target_dir, filename)
        
        # 仅处理普通文件且扩展名为.txt（不区分大小写）
        if os.path.isfile(file_path) and filename.lower().endswith('.txt'):
            print(f"正在处理: {filename}")
            try:
                deduplicate_file(file_path)
            except Exception as e:
                print(f"处理文件 '{filename}' 时出错: {e}")

if __name__ == '__main__':
    # 不修改工作目录，直接处理当前目录
    current_dir = os.getcwd()
    print(f"当前工作目录: {current_dir}")
    
    process_directory(current_dir)
    print("全部文件处理完成！")