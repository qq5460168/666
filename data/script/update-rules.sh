#!/bin/sh
set -euo pipefail  # 增加错误处理，确保脚本更健壮
LC_ALL='C'

# 清理当前目录下的 txt 文件（建议明确路径，避免误删）
rm -f *.txt

echo '创建临时文件夹'
mkdir -p ./tmp/

# 添加补充规则
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp || exit  # 增加目录切换失败处理

echo '下载规则'
rules=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt" #大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"  #DD
  "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt" #AdRules DNS Filter
  "https://raw.hellogithub.com/hosts" #GitHub加速
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt" #测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/qq5460168/Who520/refs/heads/main/Other%20rules/Replenish.txt"#补充
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt" #mphin
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list" #周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt" #liwenjie119
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts" #FCM Hosts
  "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/refs/heads/main/black.txt" #晴雅
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt" #秋风规则
  "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts" #下一个ID见
  "https://raw.githubusercontent.com/tongxin0520/AdFilterForAdGuard/refs/heads/main/KR_DNS_Filter.txt" #tongxin0520
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/blacklist.txt" #Zisbusy
  "" #空行跳过
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt" #茯苓
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt" #茯苓白名单
  "" #空行跳过
)

allow=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt"
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt"
  "https://file-git.trli.club/file-hosts/allow/Domains" #冷漠
  "https://raw.githubusercontent.com/user001235/112/main/white.txt" #浅笑
  "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt" #jhsvip
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt" #liwenjie119
  "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt" #喵二白名单
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/whitelist.txt" #Zisbusy
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt" #茯苓
  "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt" #酷安cocieto
  ""#空行跳过
  ""
)

# 修复规则和白名单的并行下载逻辑
for i in "${!rules[@]}"; do
  url="${rules[$i]}"
  [ -z "$url" ] && continue
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - \
    -o "rules${i}.txt" --connect-timeout 60 -s "$url" | iconv -t utf-8 &
done

for i in "${!allow[@]}"; do
  url="${allow[$i]}"
  [ -z "$url" ] && continue
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - \
    -o "allow${i}.txt" --connect-timeout 60 -s "$url" | iconv -t utf-8 &
done

wait
echo '规则下载完成'

# 为每个文件添加空行结束（防止因末尾无换行导致处理错误）
for f in $(ls *.txt | sort -u); do
  echo -e '\n' >> "$f" &
done
wait

echo '处理规则中'

# 提取处理规则：过滤空行、注释、IP格式不符合要求的行
cat *.txt | sort -n | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | grep -Ev "local.*\.local.*$" \
  | sed 's/127.0.0.1/0.0.0.0/g' | sed 's/::/0.0.0.0/g' \
  | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' \
  | sort | uniq > base-src-hosts.txt &
wait

# Hosts规则转ABP规则
cat base-src-hosts.txt | grep -Ev '#|\$|@|!|/|\\|\*' \
  | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$" \
  | sed 's/127.0.0.1 //' | sed 's/0.0.0.0 //' \
  | sed "s/^/||&/g" | sed "s/$/&^/g" | sed '/^$/d' \
  | grep -v '^#' \
  | sort -n | uniq | awk '!a[$0]++' \
  | grep -E "^((\|\|)\S+\^)" > abp-rules.txt &

# 处理允许域名规则
cat *.txt | grep -v "#" | sed '/^$/d' \
  | sed "s/^/@@||&/g" | sed "s/$/&^/g" \
  | sort -n | uniq | awk '!a[$0]++' > abp-allows.txt &

# 处理hosts格式允许规则
cat *.txt | grep -v "#" | sed '/^$/d' \
  | sed "s/^/0.0.0.0 &/g" \
  | sort -n | uniq | awk '!a[$0]++' > hosts-allows.txt &

wait

echo '开始合并'

# 处理AdGuard规则
cat rules*.txt abp-rules.txt \
  | grep -Ev "^((\!)|(\[)).*" \
  | sort -n | uniq | awk '!a[$0]++' > tmp-rules.txt &

# 过滤有效规则格式
cat abp-rules.txt abp-allows.txt \
  | grep -E "^[(\@\@)|(\|\|)][^\/\^]+\^$" \
  | grep -Ev "([0-9]{1,3}.){3}[0-9]{1,3}" \
  | sort | uniq > ll.txt &

wait

# 处理允许清单
cat allow*.txt abp-allows.txt \
  | grep '^@' \
  | sort -n | uniq > tmp-allow.txt &
wait

# 移动结果文件到上级目录
cp tmp-allow.txt ../allow.txt
cp tmp-rules.txt ../rules.txt

echo '规则合并完成'

# 调用Python脚本处理重复规则和生成不同格式
python ../data/python/rule.py
python ../data/python/filter-dns.py

# 添加标题和日期
python ../data/python/title.py

wait
echo '更新成功'

exit 0
