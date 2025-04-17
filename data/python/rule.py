import os

def process_file(file):
    """检查并去除包含 m^$important 的错误规则"""
    with open(file, 'r', encoding="utf8") as f:
        lines = f.readlines()
    
    # 过滤掉包含 m^$important 的规则
    filtered_lines = [line for line in lines if "m^$important" not in line]

    # 写入临时文件
    temp_file = 'test_' + file
    with open(temp_file, 'w', encoding="utf8") as fo:
        fo.writelines(filtered_lines)
    
    # 替换原文件
    os.remove(file)
    os.rename(temp_file, file)
    print(f"文件 {file} 已处理，去除包含 m^$important 的规则")

def main():
    print("检查规则文件中")

    # 设置当前目录
    os.chdir(".././")  # 更改为 .././ 目录
    files = os.listdir()  # 获取当前目录下所有文件
    
    # 遍历文件并处理
    for file in files:
        if not os.path.isdir(file) and os.path.splitext(file)[1] == '.txt':  # 只处理 .txt 文件
            process_file(file)
    
    print("检查和清理完成")

if __name__ == '__main__':
    main()