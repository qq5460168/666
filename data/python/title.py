import datetime
import pytz
import glob

# 获取当前时间并转换为北京时间
utc_time = datetime.datetime.now(pytz.timezone('UTC'))
beijing_time = utc_time.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

# 获取文件列表
file_list = glob.glob('.././*.txt')  # 将路径替换为你的文件所在的目录

# 遍历文件列表
for file_path in file_list:
    # 打开文件并读取内容
    with open(file_path, 'r') as file:
        content = file.read()

    # 计算文件的行数
    line_count = content.count('\n') + 1

    # 在文件顶部插入内容
    new_content = f"[个人合并 2.0]\n" \
                  f"! Title: 去广告规则，反馈🐧群930869948\n" \
                  f"! Homepage: https://github.com/qq5460168/666\n" \
                  f"! Expires: 12 Hours\n" \
                  f"! Version: {beijing_time}（北京时间）\n" \
                  f"! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列\n" \
                  f"! Total count: {line_count}\n" \
                  f"{content}"

    # 将更新后的内容写入文件
    with open(file_path, 'w') as file:
        file.write(new_content)
