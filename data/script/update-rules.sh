#!/bin/sh
set -euo pipefail

# 设置区域变量为 C，确保文本处理一致性
LC_ALL='C'

# 定义临时目录和输出文件路径
TMP_DIR="./tmp"
RULES_FILE="../rules.txt"
ALLOW_FILE="../allow.txt"
BASE_HOSTS_FILE="base-src-hosts.txt"

# 清理当前目录下所有 .txt 文件（确保脚本工作目录正确）
rm -f *.txt

echo "创建临时文件夹..."
mkdir -p "$TMP_DIR"

# 添加补充规则（检查源文件是否存在）
[ -f "./data/rules/adblock.txt" ] && cp -f ./data/rules/adblock.txt "$TMP_DIR/rules01.txt"
[ -f "./data/rules/whitelist.txt" ] && cp -f ./data/rules/whitelist.txt "$TMP_DIR/allow01.txt"

cd "$TMP_DIR" || { echo "无法进入临时目录 $TMP_DIR"; exit 1; }

# 规则下载
echo "开始下载规则..."

# 定义下载链接数组（规则和白名单分别处理）
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

# 并发下载规则和白名单，带进度提示，转码为UTF-8
download_resources() {
  local -n urls=$1
  local prefix=$2
  local count=0
  local total=$(printf "%s\n" "${urls[@]}" | grep -v '^$' | wc -l)
  
  for i in "${!urls[@]}"; do
    url="${urls[$i]}"
    [ -z "$url" ] && continue
    
    count=$((count + 1))
    echo "正在下载 $prefix ($count/$total): $url"
    curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate \
         -k -L -C - --connect-timeout 60 -s "$url" | iconv -t utf-8 > "${prefix}${i}.txt" &
    
    # 控制并发数，避免资源耗尽
    if (( count % 5 == 0 )); then
      wait -n 2>/dev/null || true
    fi
  done
  wait
}

# 下载规则和白名单
download_resources rules "rules"
download_resources allow "allow"

echo "规则下载完成"

# 为每个文件添加空行结束（防止因末尾无换行导致处理错误）
for f in $(ls *.txt 2>/dev/null | sort -u); do
  echo "" >> "$f" &
done
wait

echo "开始处理规则"

# 提取处理规则：过滤空行、注释、IP格式不符合要求的行，转换地址格式，排序去重
cat *.txt 2>/dev/null | sort -n | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | grep -Ev "local.*\.local.*$" \
  | sed 's/127.0.0.1/0.0.0.0/g; s/::/0.0.0.0/g' \
  | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' \
  | sort | uniq > "$BASE_HOSTS_FILE"
wait

echo "开始合并规则..."

# 合并规则：过滤注释行、空行，去重
cat rules*.txt 2>/dev/null | grep -Ev "^(#|!|\[)" | sed '/^$/d' | sort -u > tmp-rules.txt &

# 提取允许域名规则（AdGuard格式）
cat *.txt 2>/dev/null | grep -E '^@@\|\|.*\^(\$important)?$' | sort -u > tmp-allow.txt
wait

# 移动合并后的规则到上级目录
[ -f "tmp-allow.txt" ] && cp tmp-allow.txt "$ALLOW_FILE"
[ -f "tmp-rules.txt" ] && cp tmp-rules.txt "$RULES_FILE"

echo "规则合并完成"

# 调用Python脚本进一步处理
PYTHON_SCRIPTS=(
  "../data/python/rule.py"
  "../data/python/filter-dns.py"
  "../data/python/title.py"
)

for script in "${PYTHON_SCRIPTS[@]}"; do
  if [ -f "$script" ]; then
    echo "执行脚本: $script"
    python3 "$script"
  else
    echo "警告: 未找到脚本 $script，跳过执行"
  fi
done

wait
echo "更新成功"

# 清理临时文件
cd .. && rm -rf "$TMP_DIR"

exit 0
