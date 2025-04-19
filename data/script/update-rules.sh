#!/bin/sh
LC_ALL='C'

# 清理旧文件
rm -f *.txt
mkdir -p ./tmp/

echo '创建临时文件夹并添加补充规则'
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

# 定义规则和白名单数组
rules=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt" #大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt" #DD
  "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt" #AdRules DNS Filter
  "https://raw.hellogithub.com/hosts" #GitHub加速
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt" #测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt" #mphin
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list" #周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt" #liwenjie119
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts" #FCM Hosts
)

allow=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt" #mphin白名单
  "https://file-git.trli.club/file-hosts/allow/Domains" #冷漠
  "https://raw.githubusercontent.com/user001235/112/main/white.txt" #浅笑
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt" #liwenjie119
  "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt" #喵二白名单
)

download_rules() {
  local url=$1
  local output=$2

  if [ -n "$url" ]; then
    curl -m 60 --retry 5 --retry-delay 2 -k -L -C - -o "$output" --connect-timeout 60 -s "$url" | iconv -t utf-8
  fi
}

echo '开始下载规则文件'
for i in "${!rules[@]}"; do
  download_rules "${rules[$i]}" "./tmp/rules${i}.txt" &
done

for i in "${!allow[@]}"; do
  download_rules "${allow[$i]}" "./tmp/allow${i}.txt" &
done
wait
echo '规则下载完成'

# 处理规则文件，保留 # 后的备注信息
echo '处理规则中'
cat ./tmp/*.txt | sort -u | grep -Ev "^(\s*)$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | sed 's/127.0.0.1/0.0.0.0/g' \
  | sed 's/::/0.0.0.0/g' \
  | grep '0.0.0.0' \
  | sort | uniq > base-src-hosts.txt

# 将规则转换为 ABP 格式，保留注释
cat base-src-hosts.txt | sed '/^$/d' \
  | sed "s/^/||&/g" | sed "s/$/&^/g" \
  | sort -u > tmp-rules.txt

# 提取白名单规则
cat ./tmp/*.txt | grep '^@@||.*\^$' | sort -u > allow_ends_with_caret.txt
cat ./tmp/*.txt | grep '^@@||.*\^\$important$' | sort -u > allow_ends_with_important.txt
cat allow_ends_with_caret.txt allow_ends_with_important.txt | sort -u > tmp-allow.txt

# 合并结果
cp tmp-allow.txt ../allow.txt
cp tmp-rules.txt ../rules.txt
echo '规则合并完成'

# 调用 Python 脚本处理
python3 ../data/python/rule.py
python3 ../data/python/filter-dns.py
python3 ../data/python/title.py

echo '更新成功'
exit
