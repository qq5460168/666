#!/bin/sh
set -euo pipefail

# 定义错误处理函数
handle_error() {
    echo "错误发生在第 $1 行，退出码 $2" >&2
    exit 1
}
trap 'handle_error $LINENO $?' ERR

# 验证文件存在性
check_file() {
    [ -f "$1" ] || {
        echo "错误: 文件 $1 不存在" >&2
        exit 1
    }
}

# 获取统计值的函数
get_count() {
    local file=$1
    check_file "$file"
    
    # 使用awk替代sed以提高可靠性
    count=$(awk -F': ' '/^! Total count: /{print $2; exit}' "$file")
    
    # 验证是否为数字
    if ! echo "$count" | grep -qE '^[0-9]+$'; then
        echo "错误: $file 中未找到有效统计值" >&2
        exit 1
    fi
    echo "$count"
}

# 获取统计信息
num_rules=$(get_count "rules.txt")
num_dns=$(get_count "dns.txt")
num_allow=$(get_count "allow.txt")

# 获取北京时间（修正时区标识）
time=$(TZ=Asia/Shanghai date +'%Y-%m-%d %H:%M:%S')

# 更新README文件
update_readme() {
    local pattern=$1
    local replacement=$2
    
    # 使用更安全的sed参数传递
    sed -i.bak -e "s|^${pattern}.*|${replacement}|" README.md && rm -f README.md.bak
}

check_file "README.md"

update_readme "更新时间:" "更新时间: $time （北京时间）"
update_readme "拦截规则数量:" "拦截规则数量: $num_rules"
update_readme "DNS拦截规则数量:" "DNS拦截规则数量: $num_dns"
update_readme "白名单规则数量:" "白名单规则数量: $num_allow"

echo "数据更新完成"
exit 0