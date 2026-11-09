#! /bin/bash
set -e
WORK_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE="https://ip-21801.rivers.chaitin.cn/api/share/ip_group/"
LIST="leichi_black_all"
TMP="$WORK_DIR/tmp"
DIST="$WORK_DIR/dist"
mkdir -p "$TMP" "$DIST"

URLS=(
  1b54b445642b4b6ea3b9259d844aeb29
  986a6a2a747e42d88b2679bf494fb57c
  4b86eb4055014a3cbb2c497ba3d5057a
  acac1ffdf22748359d0e5d0e3e37f25d
  9fd9cb6726a14e9595051a4412042c5f
  e85c5b6b2efb46078fcd6076c9ad12df
  36a83dbc39374235b99a5004a0956fcd
  c9358c26f9f1471dbdfe4da7d4e63b07
  d6e08b2fb7c5421cb970e66673f42d97
  b3591bae27dc451eb8ba0242f22b4008
  1a64f8cebca84d3cb022436e3c1a83a2
  2a0fbffdef7e4d87b807a6db2ca27d84
  b0b4509cbb844f27b6a33ba07a8d8412
  91e6df40ca22439494f5a37cdd62d0a6
  59d799619dfd49e8980f3218aad398e4
)

RSC="$DIST/leichi_black.rsc"
: > "$RSC"

{
  echo "# 由 leichi-blacklist 自动生成，勿手改"
  echo "# 源：雷池 WAF 分享分组 x ${#URLS[@]}"
  echo "# 生成时间: $(date -Is)"
  echo "/log info \"[leichi] 开始导入黑名单 -> $LIST\""
} >> "$RSC"

# ---------- IPv4 ----------
{
  echo "/ip firewall address-list remove [find list=\"$LIST\"]"
  echo "/ip firewall address-list"
} >> "$RSC"

for id in "${URLS[@]}"; do
  part="$TMP/$id.txt.part"; out="$TMP/$id.txt"
  if curl -s --retry 3 --max-time 90 "${BASE}${id}?format=cidr" -o "$part"; then
    mv "$part" "$out"
  else
    echo "!! 拉取失败，保留缓存: $id" >&2
    rm -f "$part"; [ -f "$out" ] || continue
  fi
  # 先 tr 砍掉 \r，再过滤非法行、去重
  tr -d '\r' < "$out" \
    | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$' \
    | sort -u \
    | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}'
done >> "$RSC"

# ---------- IPv6 ----------
{
  echo "/ipv6 firewall address-list remove [find list=\"$LIST\"]"
  echo "/ipv6 firewall address-list"
} >> "$RSC"

for id in "${URLS[@]}"; do
  out="$TMP/$id.txt"; [ -f "$out" ] || continue
  tr -d '\r' < "$out" \
    | grep -E '^[0-9a-fA-F:]+:/[0-9]+$' \
    | sort -u \
    | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}'
done >> "$RSC"

echo "/log info \"[leichi] 黑名单导入完成: $LIST\"" >> "$RSC"

v4=$(grep -cE '^:do \{add address=[0-9]+\.[0-9]+' "$RSC")
v6=$(grep -cE '^:do \{add address=[0-9a-fA-F:]+:' "$RSC")

echo "===== 生成结果 ====="
echo "v4 有效条目: $v4"
echo "v6 有效条目: $v6"
echo "产物: $RSC ($(wc -c < "$RSC") 字节)"

# 兜底：有效条目太少就直接失败，防止空壳被推上去
if [ "$((v4 + v6))" -lt 100 ]; then
  echo "!! 有效条目不足 100，判定生成失败"
  exit 1
fi
