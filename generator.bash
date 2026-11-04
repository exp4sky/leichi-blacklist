#! /bin/bash
set -e
WORK_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE="https://ip-21801.rivers.chaitin.cn/api/share/ip_group/"
LIST="leichi_black_all"
TMP="$WORK_DIR/tmp"
DIST="$WORK_DIR/dist"
mkdir -p "$TMP" "$DIST"

# 6 个雷池分享分组；要增删直接改这里
URLS=(
  1b54b445642b4b6ea3b9259d844aeb29
  986a6a2a747e42d88b2679bf494fb57c
  4b86eb4055014a3cbb2c497ba3d5057a
  acac1ffdf22748359d0e5d0e3e37f25d
  9fd9cb6726a14e9595051a4412042c5f
  e85c5b6b2efb46078fcd6076c9ad12df
)

: > "$DIST/leichi_black.rsc"

{
  echo "# 由 leichi-blacklist 自动生成，勿手改"
  echo "# 源：雷池 WAF 分享分组 x ${#URLS[@]}"
  echo "# 生成时间: $(date -Is)"
  echo "/log info \"[leichi] 开始导入黑名单 -> $LIST\""
} >> "$DIST/leichi_black.rsc"

# ---------- IPv4 ----------
{
  echo "/ip firewall address-list remove [find list=\"$LIST\"]"
  echo "/ip firewall address-list"
} >> "$DIST/leichi_black.rsc"

for id in "${URLS[@]}"; do
  part="$TMP/$id.txt.part"
  out="$TMP/$id.txt"
  if curl -s --retry 3 --max-time 90 "${BASE}${id}?format=cidr" -o "$part"; then
    mv "$part" "$out"
  else
    echo "!! 拉取失败，保留缓存: $id" >&2
    rm -f "$part"
    [ -f "$out" ] || continue
  fi
  # 只认纯 IPv4 CIDR，顺手去重、过滤注释与脏行
  grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$' "$out" \
    | sort -u \
    | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}'
done >> "$DIST/leichi_black.rsc"

# ---------- IPv6 ----------
{
  echo "/ipv6 firewall address-list remove [find list=\"$LIST\"]"
  echo "/ipv6 firewall address-list"
} >> "$DIST/leichi_black.rsc"

for id in "${URLS[@]}"; do
  out="$TMP/$id.txt"
  [ -f "$out" ] || continue
  grep -E '^[0-9a-fA-F:]+:/[0-9]+$' "$out" \
    | sort -u \
    | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}'
done >> "$DIST/leichi_black.rsc"

echo "/log info \"[leichi] 黑名单导入完成: $LIST\"" >> "$DIST/leichi_black.rsc"

v4=$(grep -cE '^:do \{add address=[0-9]+\.[0-9]+' "$DIST/leichi_black.rsc")
v6=$(grep -cE '^:do \{add address=[0-9a-fA-F:]+:' "$DIST/leichi_black.rsc")
echo "OK v4=$v4 v6=$v6 -> $DIST/leichi_black.rsc"
