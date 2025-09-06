#!/bin/sh

# 提取已有规则文件总数
num_rules=`sed -n 's/^! Total count: //p' rules.txt`
num_dns=`sed -n 's/^! Total count: //p' dns.txt`
num_allow=`sed -n 's/^! Total count: //p' allow.txt`
num_hosts=`sed -n 's/^! Total count: //p' hosts.txt`

# 新增：提取其他规则文件的规则数量
num_qx=`sed -n 's/^! Total count: //p' qx.list`
num_clash=`sed -n 's/^! Total count: //p' clash.yaml`
num_clash_meta=`sed -n 's/^! Total count: //p' clash_meta.yaml`
num_shadowrocket=`sed -n 's/^! Total count: //p' Shadowrocket.list`
num_singbox=`sed -n 's/^! Total count: //p' singbox.srs`
num_invizible=`sed -n 's/^! Total count: //p' invizible.txt`
num_adclose=`sed -n 's/^! Total count: //p' AdClose.txt`
num_ublock_allow=`sed -n 's/^! Total count: //p' allow-ublock.txt`


# 获取当前时间（北京时间）
time=$(TZ=UTC-8 date +'%Y-%m-%d %H:%M:%S')

# 更新 README.md 中的内容
sed -i "s/^更新时间:.*/更新时间: $time （北京时间） /g" README.md
sed -i "s/^拦截规则数量.*/拦截规则数量: $num_rules /g" README.md
sed -i "s/^DNS拦截规则数量.*/DNS拦截规则数量: $num_dns /g" README.md
sed -i "s/^白名单规则数量.*/白名单规则数量: $num_allow /g" README.md
sed -i "s/^Hosts规则数量.*/Hosts规则数量: $num_hosts /g" README.md

# 更新新增的其他规则文件数量
sed -i "s/^Quantumult X规则数量.*/Quantumult X规则数量: $num_qx /g" README.md
sed -i "s/^Clash规则数量.*/Clash规则数量: $num_clash /g" README.md
sed -i "s/^Clash Meta规则数量.*/Clash Meta规则数量: $num_clash_meta /g" README.md
sed -i "s/^Shadowrocket规则数量.*/Shadowrocket规则数量: $num_shadowrocket /g" README.md
sed -i "s/^Singbox规则数量.*/Singbox规则数量: $num_singbox /g" README.md
sed -i "s/^Invizible Pro规则数量.*/Invizible Pro规则数量: $num_invizible /g" README.md
sed -i "s/^AdClose规则数量.*/AdClose规则数量: $num_adclose /g" README.md
sed -i "s/^uBlock白名单规则数量.*/uBlock白名单规则数量: $num_ublock_allow /g" README.md

exit