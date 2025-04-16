import os

def read_error_domains(error_file):
    """读取错误域名列表"""
    if os.path.exists(error_file):
        with open(error_file, 'r', encoding='utf8') as f:
            error_domains = set(line.strip() for line in f if line.strip())
        print(f"从 {error_file} 读取到 {len(error_domains)} 个错误域名")
        return error_domains
    else:
        print(f"错误域名文件 {error_file} 不存在，跳过过滤步骤")
        return set()

def process_file(file, error_domains):
    """处理规则文件，去重并排除错误域名"""
    with open(file, 'r', encoding="utf8") as f:
        lines = f.readlines()
    
    # 去重并排除错误域名
    unique_lines = set(lines)
    filtered_lines = [line for line in unique_lines if not any(error_domain in line for error_domain in error_domains)]
    filtered_lines.sort()

    # 写入临时文件
    temp_file = 'test' + file
    with open(temp_file, 'w', encoding="utf8") as fo:
        fo.writelines(filtered_lines)
    
    # 替换原文件
    os.remove(file)
    os.rename(temp_file, file)
    print(f"文件 {file} 处理完成：去重并排除错误域名")

def main():
    print("规则去重中")
    
    # 配置错误域名文件路径
    error_file = os.path.join('data', 'rules', 'error.txt')
    error_domains = read_error_domains(error_file)
    
    # 切换到目标目录
    os.chdir(".././")  # 将当前目录更改为 .././
    files = os.listdir()  # 获取当前目录下的所有文件
    
    # 遍历文件并处理
    for file in files:
        if not os.path.isdir(file) and os.path.splitext(file)[1] == '.txt':  # 确保是 .txt 文件
            process_file(file, error_domains)
    
    print("规则去重完成")

if __name__ == '__main__':
    main()