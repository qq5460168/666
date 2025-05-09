import datetime

# 打开原始文件和目标文件
with open('.././rules.txt', 'r') as input_file, open('.././dns.txt', 'w') as dns_output_file, open('.././hosts.txt', 'w') as hosts_output_file:
    # 逐行读取原始文件内容
    for line in input_file:
        # 去除行尾的换行符
        line = line.strip()
        
        # 检查是否包含 "m^$important" 错误规则，如果包含则跳过
        if "m^$important" in line:
            print(f"跳过错误规则: {line}")
            continue
        
        # 检查行长度是否大于等于2，并且首字符是"||"并且结尾是"^"
        if len(line) >= 2 and line.startswith("||") and line.endswith("^"):
            # 写入到 DNS 格式文件
            dns_output_file.write(line + '\n')
            
            # 生成 Hosts 格式规则（0.0.0.0 <域名>）
            domain = line[2:-1]  # 去掉 "||" 和 "^"
            hosts_output_file.write(f"0.0.0.0 {domain}\n")