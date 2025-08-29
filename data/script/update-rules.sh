#!/bin/sh
set -euo pipefail  # 严格错误处理
LC_ALL='C'

# 目录与文件路径定义
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
TMP_DIR=$(mktemp -d -t ad-rules-XXXXXX)  # 唯一临时目录
LOG_FILE="$ROOT_DIR/update.log"

# 初始化日志
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始规则更新" > "$LOG_FILE"

# 清理环境（退出时执行，包括异常情况）
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 清理临时文件完成" >> "$LOG_FILE"
    fi
}
trap cleanup EXIT INT TERM

# 切换到临时目录
cd "$TMP_DIR" || {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 切换到临时目录失败: $TMP_DIR" >> "$LOG_FILE"
    exit 1
}

# 规则源定义（去重空行）
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
# 去重并移除空行
allow=($(printf "%s\n" "${allow[@]}" | sort -u | grep -v '^$'))

# 并行下载规则
download_rules() {
    local type=$1
    shift
    local urls=("$@")
    local count=0
    
    for url in "${urls[@]}"; do
        [ -z "$url" ] && continue
        local filename="${type}${count}.txt"
        if curl -m 60 --retry-delay 2 --retry 3 --parallel -k -L -C - \
            -o "$filename" --connect-timeout 60 -s "$url"; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 成功下载: $url" >> "$LOG_FILE"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 下载失败: $url (可能网络超时或URL无效)" >> "$LOG_FILE"
        fi
        ((count++))
    done
    wait
}

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始下载规则（共 ${#rules[@]} 个规则源，${#allow[@]} 个白名单源）" >> "$LOG_FILE"
download_rules "rules" "${rules[@]}" &
download_rules "allow" "${allow[@]}" &
wait

# 补充本地规则
cp "$ROOT_DIR/data/rules/adblock.txt" "rules_local.txt" 2>/dev/null || {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 警告：本地规则 adblock.txt 不存在，跳过" >> "$LOG_FILE"
}
cp "$ROOT_DIR/data/rules/whitelist.txt" "allow_local.txt" 2>/dev/null || {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 警告：本地白名单 whitelist.txt 不存在，跳过" >> "$LOG_FILE"
}

# 规则预处理（清除空行、Windows换行符、元素规则）
for f in *.txt; do
    [ -f "$f" ] || continue
    sed -i.bak '/^\s*$/d; s/\r//g; /^##/d' "$f"  # 过滤##开头的元素规则
    echo >> "$f"  # 确保文件末尾有换行
    rm -f "$f.bak"
done

# 生成基础规则
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始处理规则" >> "$LOG_FILE"
cat *.txt | grep -v -E "^(#|!|\[|@|\/|\\|\*|::)" \
    | grep -v -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+(localhost|local)" \
    | sed 's/127.0.0.1/0.0.0.0/g' \
    | awk '$2 !~ /\./ {next} {print "0.0.0.0 " $2}' \
    | sort -u > base-src-hosts.txt

# 格式转换
cat base-src-hosts.txt | awk '{print "||" $2 "^"}' | sort -u > abp-rules.txt
cat allow*.txt | grep -v "^#" | sed 's/^/@@||/; s/$/^/' | sort -u > abp-allows.txt

# 统计规则数量
before=$(cat abp-rules.txt | wc -l)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 处理前规则数量: $before" >> "$LOG_FILE"

# 白名单排除逻辑（精确匹配）
grep -E '^@@\|\|.*\^' abp-allows.txt | sed -E 's/^@@\|\|(.*)\^$/\1/' > allow_domains.tmp
grep -F -x -v -f allow_domains.tmp abp-rules.txt > filtered-rules.tmp

# 统计排除后数量
after=$(cat filtered-rules.tmp | wc -l)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 排除白名单后规则数量: $after (移除了 $((before - after)) 条)" >> "$LOG_FILE"

# 合并最终规则
cat filtered-rules.tmp | sort -u > "$ROOT_DIR/rules.txt"
cat abp-allows.txt | sort -u > "$ROOT_DIR/allow.txt"

# 检查Python脚本是否存在
for script in "rule.py" "filter-dns.py" "title.py"; do
    script_path="$ROOT_DIR/data/python/$script"
    if [ ! -f "$script_path" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 错误：Python脚本不存在 - $script_path" >> "$LOG_FILE"
        exit 1
    fi
done

# 调用Python处理
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始格式转换" >> "$LOG_FILE"
python3 "$ROOT_DIR/data/python/rule.py" >> "$LOG_FILE" 2>&1
python3 "$ROOT_DIR/data/python/filter-dns.py" >> "$LOG_FILE" 2>&1
python3 "$ROOT_DIR/data/python/title.py" >> "$LOG_FILE" 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 更新完成" >> "$LOG_FILE"
exit 0
