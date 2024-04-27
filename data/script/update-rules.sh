#!/bin/sh
LC_ALL='C'

rm *.txt

wait
echo '创建临时文件夹'
mkdir -p ./tmp/

#添加补充规则
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp
#下载yhosts规则
#curl https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts | sed '/0.0.0.0 /!d; /#/d; s/0.0.0.0 /||/; s/$/\^/' > rules001.txt

#下载大圣净化规则
#curl https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts > rules002.txt
#sed -i '/视频/d;/奇艺/d;/微信/d;/localhost/d' rules002.txt
#sed -i '/127.0.0.1 /!d; s/127\.0\.0\.1 /||/; s/$/\^/' rules002.txt

#下载乘风视频过滤规则
#curl https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt | awk '!/^$/{if($0 !~ /[#^|\/\*\]\[\!]/){print "||"$0"^"} else if($0 ~ /[#\$|@]/){print $0}}' | sort -u > rules003.txt


echo '下载规则'
rules=(
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #5460
  "https://ghproxy.net/https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt" #大萌主
  "https://ghproxy.net/https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"  #DD
  "https://raw.gitmirror.com/Cats-Team/dns-filter/main/abp.txt" #AdRules DNS Filter
  "https://raw.hellogithub.com/hosts" #GitHub加速
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/0608.txt" #测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #白名单
  "https://raw.githubusercontent.com/loveqqzj/AdGuard/master/Mobile.txt" #loveqqzj
  "https://raw.githubusercontent.com/coco86p1sz/Self-use_AdguardRules/master/Self-userPhoneAdguardRules.txt" #coco86p1sz
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt" #mphin
  "" #
  "" #
 
  
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt" #秋风规则
 )

allow=(
 "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt" #
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt"
  ""
  ""
)

for i in "${!rules[@]}" "${!allow[@]}"
do
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - -o "rules${i}.txt" --connect-timeout 60 -s "${rules[$i]}" |iconv -t utf-8 &
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - -o "allow${i}.txt" --connect-timeout 60 -s "${allow[$i]}" |iconv -t utf-8 &
done
wait
echo '规则下载完成'

# 添加空格
file="$(ls|sort -u)"
for i in $file; do
  echo -e '\n' >> $i &
done
wait

echo '处理规则中'

cat | sort -n| grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
 | grep -Ev "local.*\.local.*$" \
 | sed s/127.0.0.1/0.0.0.0/g | sed s/::/0.0.0.0/g |grep '0.0.0.0' |grep -Ev '.0.0.0.0 ' | sort \
 |uniq >base-src-hosts.txt &
wait
cat base-src-hosts.txt | grep -Ev '#|\$|@|!|/|\\|\*'\
 | grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$" \
 | sed 's/127.0.0.1 //' | sed 's/0.0.0.0 //' \
 | sed "s/^/||&/g" |sed "s/$/&^/g"| sed '/^$/d' \
 | grep -v '^#' \
 | sort -n | uniq | awk '!a[$0]++' \
 | grep -E "^((\|\|)\S+\^)" & #Hosts规则转ABP规则

cat | sed '/^$/d' | grep -v '#' \
 | sed "s/^/@@||&/g" | sed "s/$/&^/g"  \
 | sort -n | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat | sed '/^$/d' | grep -v "#" \
 |sed "s/^/@@||&/g" | sed "s/$/&^/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat | sed '/^$/d' | grep -v "#" \
 |sed "s/^/0.0.0.0 &/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat *.txt | sed '/^$/d' \
 |grep -E "^\/[a-z]([a-z]|\.)*\.$" \
 |sort -u > l.txt &

cat \
 | sed "s/^/||&/g" | sed "s/$/&^/g" &

cat \
 | sed "s/^/0.0.0.0 &/g" &


echo 开始合并

cat rules*.txt \
 |grep -Ev "^((\!)|(\[)).*" \
 | sort -n | uniq | awk '!a[$0]++' > tmp-rules.txt & #处理AdGuard的规则

cat \
 | grep -E "^[(\@\@)|(\|\|)][^\/\^]+\^$" \
 | grep -Ev "([0-9]{1,3}.){3}[0-9]{1,3}" \
 | sort | uniq > ll.txt &
wait


cat *.txt | grep '^@' \
 | sort -n | uniq > tmp-allow.txt & #允许清单处理
wait

cp tmp-allow.txt .././allow.txt
cp tmp-rules.txt .././rules.txt

echo 规则合并完成

# Python 处理重复规则
python .././data/python/rule.py
python .././data/python/filter-dns.py

# Start Add title and date
python .././data/python/title.py


wait
echo '更新成功'

exit
