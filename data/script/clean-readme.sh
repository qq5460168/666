#!/bin/sh

# 提取规则总数
num_rules=`sed -n 's/^! Total count: //p' rules.txt`
num_dns=`sed -n 's/^! Total count: //p' dns.txt`
num_allow=`sed -n 's/^! Total count: //p' allow.txt`
num_hosts=`sed -n 's/^! Total count: //p' hosts.txt`  # 新增：提取 hosts 规则总数

# 获取当前时间（北京时间）
time=$(TZ=UTC-8 date +'%Y-%m-%d %H:%M:%S')

# 更新 README.md 中的内容
sed -i "s/^更新时间:.*/更新时间: $time （北京时间） /g" README.md
sed -i 's/^拦截规则数量.*/拦截规则数量: '$num_rules' /g' README.md
sed -i 's/^DNS拦截规则数量.*/DNS拦截规则数量: '$num_dns' /g' README.md
sed -i 's/^白名单规则数量.*/白名单规则数量: '$num_allow' /g' README.md
sed -i 's/^Hosts规则数量.*/Hosts规则数量: '$num_hosts' /g' README.md  # 新增：更新 Hosts 规则数量

exit