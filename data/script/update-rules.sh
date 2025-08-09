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

rules=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt" #大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"  #DD
  "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt" #AdRules DNS Filter
  "https://raw.hellogithub.com/hosts" #GitHub加速
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt" #测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/qq5460168/Who520/refs/heads/main/Other%20rules/Replenish.txt" #补充
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt" #mphin
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list" #周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt" #liwenjie119
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts" #FCM Hosts
  "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/refs/heads/main/black.txt" #晴雅
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt" #秋风规则
  "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts" #下一个ID见
  "https://raw.githubusercontent.com/tongxin0520/AdFilterForAdGuard/refs/heads/main/KR_DNS_Filter.txt" #tongxin0520
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/blacklist.txt" #Zisbusy
  "" #
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt" #茯苓
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt" #茯苓白名单
  "" #
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
  "" #
  ""
)

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

for f in $(ls *.txt | sort -u); do
  echo "" >> "$f" &
done
wait

echo "开始处理规则"

cat *.txt | sort -n | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | grep -Ev "local.*\.local.*$" \
  | sed 's/127.0.0.1/0.0.0.0/g' | sed 's/::/0.0.0.0/g' \
  | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' \
  | sort | uniq > base-src-hosts.txt
wait

# -------- 域名有效性检测（保留注释） BEGIN --------
echo "开始域名有效性检测..."

china_dns=("223.5.5.5" "119.29.29.29" "114.114.114.114")
global_dns=("8.8.8.8" "1.1.1.1" "9.9.9.9")

check_domain() {
  local domain="$1"
  for dns in "${china_dns[@]}"; do
    if dig +timeout=2 +tries=1 +short @"$dns" "$domain" | grep -qE '^[0-9a-zA-Z]'; then
      return 0
    fi
  done
  for dns in "${global_dns[@]}"; do
    if dig +timeout=2 +tries=1 +short @"$dns" "$domain" | grep -qE '^[0-9a-zA-Z]'; then
      return 0
    fi
  done
  return 1
}

export -f check_domain
export china_dns global_dns

valid_file="valid-hosts.txt"
> "$valid_file"

cat base-src-hosts.txt | grep '^0\.0\.0\.0 ' | \
  while read -r line; do
    # 兼容 hosts 格式注释，如 0.0.0.0 domain.com # 注释
    domain=$(echo "$line" | awk '{print $2}')
    if [ -n "$domain" ] && check_domain "$domain"; then
      echo "$line" >> "$valid_file"
    fi
  done

mv "$valid_file" base-src-hosts.txt

echo "域名有效性检测完成"
# -------- 域名有效性检测（保留注释） END --------

echo "开始合并规则..."

cat rules*.txt | grep -Ev "^(#|!|\[)" | sed '/^$/d' | sort -u > tmp-rules.txt &

cat *.txt | grep '^@@||.*\^$' | sort -u > allow_ends_with_caret.txt
cat *.txt | grep '^@@||.*\^\$important$' | sort -u > allow_ends_with_important.txt

cat allow_ends_with_caret.txt allow_ends_with_important.txt | sort -u > tmp-allow.txt
wait

cp tmp-allow.txt ../allow.txt
cp tmp-rules.txt ../rules.txt

echo "规则合并完成"

python ../data/python/rule.py
python ../data/python/filter-dns.py
python ../data/python/title.py

wait
echo "更新成功"

exit 0
