#!/bin/bash
set -e  # 开启脚本错误捕获

LC_ALL='C'

# 清理旧文件
echo "清理旧文件..."
rm -f *.txt
mkdir -p ./tmp/

# 添加补充规则
echo "添加补充规则..."
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp

# 定义规则数组
rules=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt" #大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"  #DD规则
  "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt" #AdRules DNS Filter
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt" #测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt" #mphin
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt" #liwenjie119
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts" #FCM Hosts
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingBlockList.txt" #茯苓
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/blacklist.txt" #Zisbusy
)

allow=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt"
  "https://file-git.trli.club/file-hosts/allow/Domains" #冷漠
  "https://raw.githubusercontent.com/user001235/112/main/white.txt" #浅笑
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt" #liwenjie119
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingAllowList.txt" #茯苓
)

# 下载规则函数
download_rules() {
  local url_list=("$@")
  local prefix="rules"
  for index in "${!url_list[@]}"; do
    local url="${url_list[$index]}"
    if [ -n "$url" ]; then
      output_file="${prefix}${index}.txt"
      echo "下载规则: $url -> $output_file"
      curl -m 60 --retry 5 -L -o "$output_file" "$url" || echo "下载失败: $url" >> ../download_errors.log
    fi
  done
}

# 执行下载
echo "下载规则列表..."
download_rules "${rules[@]}"
download_rules "${allow[@]}"

echo "规则下载完成！"

# 处理规则文件
echo "处理规则文件..."
for file in *.txt; do
  sed -i '/^$/d' "$file"  # 移除空行
  echo >> "$file"         # 添加空行
done

# 合并并去重规则
echo "合并和去重规则..."
cat rules*.txt | grep -Ev '^(!|\[)' | sort -u > tmp-rules.txt
cat allow*.txt | grep '^@@' | sort -u > tmp-allow.txt

# 移动最终结果
mv tmp-rules.txt ../rules.txt
mv tmp-allow.txt ../allow.txt

# 使用 Python 脚本进行进一步处理
echo "调用 Python 脚本处理..."
python ../data/python/rule.py
python ../data/python/filter-dns.py
python ../data/python/title.py

echo "规则更新成功！"
exit 0