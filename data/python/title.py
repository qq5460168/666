import datetime
import pytz

# 获取当前时间并转换为北京时间
utc_time = datetime.datetime.now(pytz.timezone('UTC'))
beijing_time = utc_time.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

# 仅为没有头部的成品文件补充统一标题（rules.txt / allow.txt 由 shell 合并生成，自身无头部）。
# dns.txt / hosts.txt / invizible.txt / AdClose.txt / allow-ublock.txt 等由各自生成器
# （filter-dns.py / whitelist.py）写入格式专用头部，这里不再处理，避免成品文件双重标题。
file_list = ['../rules.txt', '../allow.txt']

# 已经存在头部的标记（命中即跳过，防止重复套标题）
HEADER_MARKS = ('[Adblock Plus', '[个人合并', '! Title', '# Title', '# AdClose')

for file_path in file_list:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except FileNotFoundError:
        continue

    # 若已有头部则跳过，避免重复添加
    if content.lstrip().startswith(HEADER_MARKS):
        continue

    # 计算文件的行数（不含标题）
    line_count = content.count('\n') + 1

    # 在文件顶部插入统一标题
    new_content = f"[个人合并 2.0]\n" \
                  f"! Title: 去广告规则，酷安反馈反馈\n" \
                  f"! Homepage: https://github.com/qq5460168/666\n" \
                  f"! Expires: 12 Hours\n" \
                  f"! Version: {beijing_time}（北京时间）\n" \
                  f"! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列\n" \
                  f"! Total count: {line_count}\n" \
                  f"{content}"

    # 将更新后的内容写入文件
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(new_content)
