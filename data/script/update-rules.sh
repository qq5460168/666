#!/bin/sh
set -euo pipefail

# 设置区域变量为 C
LC_ALL='C'

# 清理当前目录下所有 .txt 文件（建议确保脚本工作目录正确）
rm -f *.txt

echo "创建临时文件夹..."
mkdir -p ./tmp/

# 添加补充规则（建议检查源文件是否存在）
cp -f ./data/rules/adblock.txt ./tmp/rules01.txt
cp -f ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp

# 规则下载
echo "开始下载规则..."

# 定义下载链接数组（规则和白名单分别处理）
rules=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt" #大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"  #DD
  "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt" #AdRules DNS Filter
 # "https://raw.hellogithub.com/hosts" #GitHub加速
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt" #测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/qq5460168/Who520/refs/heads/main/Other%20rules/Replenish.txt"#补充
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt" #mphin
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list" #周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt" #liwenjie119
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts" #FCM Hosts
  "https://raw.githubusercontent.com/rssvcn/qy-Ads-Rule/main/black.txt" #晴雅
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt" #秋风规则
  "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts" #下一个ID见
  #"https://raw.githubusercontent.com/tongxin0520/AdFilterForAdGuard/refs/heads/main/KR_DNS_Filter.txt" #tongxin0520
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/blacklist.txt" #Zisbusy
  "https://raw.githubusercontent.com/qq5460168/Who520/refs/heads/main/Other%20rules/SMhosts.txt" #SMhosts
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Develop/FuLingRules/FuLingBlockList.txt" #茯苓
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Develop/FuLingRules/FuLingAllowList.txt" #茯苓白名单
  "" #
)

# 来源名数组：与 rules[] 按下标严格对齐（被整行注释的 URL 不占下标，
# 来源名数组必须同步去掉占位，否则错位）
rules_names=(
  "5460"
  "大萌主"
  "DD"
  "AdRules DNS Filter"
  "测试hosts"
  "白名单(dangchu)"
  "补充(Who520)"
  "mphin"
  "周木木"
  "liwenjie119"
  "FCM Hosts"
  "晴雅"
  "秋风规则"
  "下一个ID见"
  "Zisbusy"
  "SMhosts"
  "茯苓"
  "茯苓白名单"
  ""
)

allow=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt"
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt"
 # "https://file-git.trli.club/file-hosts/allow/Domains" #冷漠
  "https://raw.githubusercontent.com/user001235/112/main/white.txt" #浅笑
  "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt" #jhsvip
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt" #liwenjie119
  "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt" #喵二白名单
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/whitelist.txt" #Zisbusy
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Develop/FuLingRules/FuLingAllowList.txt" #茯苓
  "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt" #酷安cocieto
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"#DD
  ""
)

# 来源名数组：与 allow[] 按下标严格对齐（同上）
allow_names=(
  "dangchu白名单"
  "mphin白名单"
  "浅笑"
  "jhsvip"
  "liwenjie119白名单"
  "喵二白名单"
  "Zisbusy白名单"
  "茯苓白名单"
  "酷安cocieto"
  "DD"
  ""
)

# 使用并发curl下载规则和白名单，并通过 iconv 转码后存入文件
for i in "${!rules[@]}"; do
  url="${rules[$i]}"
  [ -z "$url" ] && continue
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - --connect-timeout 60 -s "$url" | iconv -t utf-8 > "rules${i}.txt" &
done

for i in "${!allow[@]}"; do
  url="${allow[$i]}"
  [ -z "$url" ] && continue
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - --connect-timeout 60 -s "$url" | iconv -t utf-8 > "allow${i}.txt" &
done

wait
echo "规则下载完成"

# ==============================================
# 为每个下载文件写入来源头（! 📋 规则来源 / ! 🔗 原始地址）
# 与 src_index 一并供 merge.py 按来源分区块溯源
# ==============================================
write_source_header() {
  _f="$1"; _name="$2"; _url="$3"
  { printf '! 📋 规则来源：%s\n! 🔗 原始地址：%s\n' "$_name" "$_url"; cat "$_f"; } > "$_f.hdr" && mv -f "$_f.hdr" "$_f"
}

# 黑名单来源头（rulesN.txt 与本地补充 rules01.txt）
for i in "${!rules[@]}"; do
  url="${rules[$i]}"
  [ -z "$url" ] && continue
  write_source_header "rules${i}.txt" "${rules_names[$i]}" "$url"
done
write_source_header "rules01.txt" "本地补充(data/rules/adblock.txt)" "本地文件"

# 白名单来源头（allowN.txt 与本地补充 allow01.txt）
for i in "${!allow[@]}"; do
  url="${allow[$i]}"
  [ -z "$url" ] && continue
  write_source_header "allow${i}.txt" "${allow_names[$i]}" "$url"
done
write_source_header "allow01.txt" "本地补充(data/rules/whitelist.txt)" "本地文件"

# ==============================================
# 生成来源索引清单（文件名<TAB>来源名<TAB>原始URL），
# 命名 src_index（无 .txt 后缀）避免被 cat *.txt / ls *.txt 误处理
# ==============================================
: > src_index
for i in "${!rules[@]}"; do
  url="${rules[$i]}"
  [ -z "$url" ] && continue
  printf 'rules%s.txt\t%s\t%s\n' "$i" "${rules_names[$i]}" "$url" >> src_index
done
printf 'rules01.txt\t本地补充(data/rules/adblock.txt)\t本地文件\n' >> src_index

for i in "${!allow[@]}"; do
  url="${allow[$i]}"
  [ -z "$url" ] && continue
  printf 'allow%s.txt\t%s\t%s\n' "$i" "${allow_names[$i]}" "$url" >> src_index
done
printf 'allow01.txt\t本地补充(data/rules/whitelist.txt)\t本地文件\n' >> src_index

# 为下载的每个文件添加空行结束（防止因末尾无换行导致处理错误）
for f in $(ls *.txt | sort -u); do
  echo "" >> "$f" &
done
wait

echo "开始处理规则"

# 提取处理规则：过滤空行、注释、IP格式不符合要求的行，并转换部分地址格式，然后排序去重
cat *.txt | sort -n | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | grep -Ev "local.*\.local.*$" \
  | sed 's/127.0.0.1/0.0.0.0/g' | sed 's/::/0.0.0.0/g' \
  | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' \
  | sort | uniq > base-src-hosts.txt
wait

echo "开始合并规则（按来源分区块，保留每条规则的上游来源）..."

# merge.py 负责：
#   - 黑名单(rules*.txt)按来源分区块合并 -> 仓库根 rules.txt
#   - 白名单(所有文件的 @@|| 行)按来源分区块合并 -> 仓库根 allow.txt
#   - error.txt 整行精确剔除（rules 与 allow 同时生效）
python ../data/python/merge.py

echo "规则合并完成"

# 调用 Python 脚本处理规则、生成各格式并添加标题
python ../data/python/filter-dns.py
python ../data/python/whitelist.py 

# 添加标题和日期
python ../data/python/title.py

wait
echo "更新成功"

exit 0
