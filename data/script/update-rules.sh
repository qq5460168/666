#!/bin/sh
set -euo pipefail

# 设置区域变量为 C，确保文本处理一致性
LC_ALL='C'

# 定义颜色和格式化输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

info() { echo -e "${BLUE}INFO: $*${NC}"; }
success() { echo -e "${GREEN}SUCCESS: $*${NC}"; }
warning() { echo -e "${YELLOW}WARNING: $*${NC}"; }
error() { echo -e "${RED}ERROR: $*${NC}"; }

# 清理当前目录下所有 .txt 文件（建议确保脚本工作目录正确）
info "清理当前目录下的旧规则文件..."
rm -f *.txt

# 创建临时文件夹并处理路径
TMP_DIR="./tmp"
info "创建临时文件夹: $TMP_DIR"
mkdir -p "$TMP_DIR" || { error "创建临时文件夹失败"; exit 1; }

# 添加补充规则（检查源文件是否存在）
info "复制本地补充规则..."
local_rules=(
  "./data/rules/adblock.txt:rules01.txt"
  "./data/rules/whitelist.txt:allow01.txt"
)

for item in "${local_rules[@]}"; do
  src="${item%:*}"
  dest="${item#*:}"
  if [ -f "$src" ]; then
    cp -f "$src" "$TMP_DIR/$dest" || warning "复制 $src 到 $dest 失败"
  else
    warning "本地规则文件不存在: $src，跳过复制"
  fi
done

cd "$TMP_DIR" || { error "无法进入临时目录 $TMP_DIR"; exit 1; }

# 规则下载
info "开始下载远程规则..."

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
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt" #茯苓
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt" #茯苓白名单
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
)

# 下载函数 - 带进度提示和错误处理
download_urls() {
  local type=$1
  shift
  local urls=("$@")
  local count=0
  local total=${#urls[@]}
  
  info "开始下载 ${type} 规则 (共 ${total} 个源)..."
  
  for i in "${!urls[@]}"; do
    url="${urls[$i]}"
    [ -z "$url" ] && continue
    
    count=$((count + 1))
    output_file="${type}${i}.txt"
    info "下载中 (${count}/${total}): ${url}"
    
    if curl -m 60 --retry-delay 2 --retry 3 --parallel --parallel-immediate \
         -k -L -C - --connect-timeout 30 -s "$url" | iconv -t utf-8 > "$output_file"; then
      success "成功下载: ${output_file}"
    else
      warning "下载失败: ${url} (将继续尝试其他链接)"
      rm -f "$output_file" # 清理失败的文件
    fi
  done
}

# 并发下载规则和白名单
download_urls "rules" "${rules[@]}" &
download_urls "allow" "${allow[@]}" &

wait # 等待所有下载完成
success "所有规则下载完成"

# 为下载的每个文件添加空行结束（防止因末尾无换行导致处理错误）
info "规范化文件格式..."
for f in $(ls *.txt 2>/dev/null | sort -u); do
  echo "" >> "$f" &
done
wait

# 提取处理规则：过滤空行、注释、IP格式不符合要求的行，并转换部分地址格式
info "开始处理基础规则..."
cat *.txt 2>/dev/null | sort -n | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | grep -Ev "local.*\.local.*$" \
  | sed 's/127.0.0.1/0.0.0.0/g' | sed 's/::/0.0.0.0/g' \
  | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' \
  | sort | uniq > base-src-hosts.txt
success "基础规则处理完成"

# 合并规则：过滤掉注释行、空行，并对 AdGuard 规则进行去重
info "开始合并规则..."
cat rules*.txt 2>/dev/null | grep -Ev "^(#|!|\[)" | sed '/^$/d' | sort -u > tmp-rules.txt &

# 从所有规则中提取允许域名（以 @@|| 开头的规则）
cat *.txt 2>/dev/null | grep '^@@||.*\^$' | sort -u > allow_ends_with_caret.txt
cat *.txt 2>/dev/null | grep '^@@||.*\^\$important$' | sort -u > allow_ends_with_important.txt

# 合并两种允许规则
cat allow_ends_with_caret.txt allow_ends_with_important.txt 2>/dev/null | sort -u > tmp-allow.txt
wait

# 移动合并后的规则到上级目录
info "保存合并结果..."
cp tmp-allow.txt ../allow.txt || { error "保存白名单规则失败"; exit 1; }
cp tmp-rules.txt ../rules.txt || { error "保存拦截规则失败"; exit 1; }
success "规则合并完成"

# 返回上级目录
cd .. || { error "无法返回上级目录"; exit 1; }

# 调用 Python 脚本进一步处理
info "运行规则优化脚本..."
python_scripts=(
  "./data/python/rule.py"
  "./data/python/filter-dns.py"
  "./data/python/title.py"
)

for script in "${python_scripts[@]}"; do
  if [ -f "$script" ]; then
    if python3 "$script"; then
      success "成功执行脚本: $script"
    else
      error "执行脚本失败: $script"
      exit 1
    fi
  else
    error "Python 脚本不存在: $script"
    exit 1
  fi
done

# 清理临时文件
info "清理临时文件..."
rm -rf "$TMP_DIR"

success "规则更新完成！"
exit 0
