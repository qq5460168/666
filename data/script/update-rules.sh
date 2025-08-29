#!/bin/sh
set -euo pipefail  # 严格错误处理
LC_ALL='C'
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
TMP_DIR="$ROOT_DIR/tmp"
LOG_FILE="$ROOT_DIR/update.log"

# 初始化日志
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始规则更新" > "$LOG_FILE"

# 清理环境
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 清理临时文件完成" >> "$LOG_FILE"
    fi
}
trap cleanup EXIT  # 退出时自动清理

# 创建工作目录
mkdir -p "$TMP_DIR" || {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 临时目录创建失败" >> "$LOG_FILE"
    exit 1
}
cd "$TMP_DIR" || {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 切换目录失败" >> "$LOG_FILE"
    exit 1
}

# 规则源定义
rules=(
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt"
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt"
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"
    "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt"
    "https://raw.hellogithub.com/hosts"
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt"
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt"
    "https://raw.githubusercontent.com/qq5460168/Who520/refs/heads/main/Other%20rules/Replenish.txt"
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt"
    "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list"
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt"
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts"
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/refs/heads/main/black.txt"
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts"
    "https://raw.githubusercontent.com/tongxin0520/AdFilterForAdGuard/refs/heads/main/KR_DNS_Filter.txt"
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/blacklist.txt"
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt"
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt"
)

allow=(
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt"
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt"
    "https://file-git.trli.club/file-hosts/allow/Domains"
    "https://raw.githubusercontent.com/user001235/112/main/white.txt"
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt"
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt"
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt"
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/refs/heads/main/Rules/whitelist.txt"
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt"
    "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt"
)

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
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 下载失败: $url" >> "$LOG_FILE"
        fi
        ((count++))
    done
    wait
}

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始下载规则" >> "$LOG_FILE"
download_rules "rules" "${rules[@]}" &
download_rules "allow" "${allow[@]}" &
wait

# 补充本地规则
cp "$ROOT_DIR/data/rules/adblock.txt" "rules_local.txt" 2>/dev/null || true
cp "$ROOT_DIR/data/rules/whitelist.txt" "allow_local.txt" 2>/dev/null || true

# 规则预处理
for f in *.txt; do
    [ -f "$f" ] || continue
    sed -i.bak '/^\s*$/d; s/\r//g' "$f"  # 清除空行和Windows换行符
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

# 白名单排除逻辑
grep -E '^@@\|\|.*\^' abp-allows.txt | sed -E 's/^@@\|\|(.*)\^$/\1/' > allow_domains.tmp
grep -F -v -f allow_domains.tmp abp-rules.txt > filtered-rules.tmp

# 合并最终规则
cat filtered-rules.tmp | sort -u > "$ROOT_DIR/rules.txt"
cat abp-allows.txt | sort -u > "$ROOT_DIR/allow.txt"

# 调用Python处理
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始格式转换" >> "$LOG_FILE"
python3 "$ROOT_DIR/data/python/rule.py" >> "$LOG_FILE" 2>&1
python3 "$ROOT_DIR/data/python/filter-dns.py" >> "$LOG_FILE" 2>&1
python3 "$ROOT_DIR/data/python/title.py" >> "$LOG_FILE" 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 更新完成" >> "$LOG_FILE"
exit 0
