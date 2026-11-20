#! /bin/bash
set -euo pipefail

WORK_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE="https://ip-21801.rivers.chaitin.cn/api/share/ip_group/"
LIST="leichi_black_all"
TMP="$WORK_DIR/tmp"
DIST="$WORK_DIR/dist"
mkdir -p "$TMP" "$DIST"

# ---------- 下载参数集中管理 ----------
CURL_OPTS=(
  -fsS                      # 关键：HTTP >=400 直接非 0 退出
  --connect-timeout 10      # 建连（含 DNS）最多 10s
  --max-time 90             # 单次请求总上限
  --retry 4                 # 超时/408/429/5xx 自动重试
  --retry-delay 3           # 重试间隔 3s，退避
  --retry-max-time 120      # 重试总耗时上限
  --retry-connrefused       # 连接被拒也重试
  -H 'Accept: text/plain'
)

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

# ---------- 拉取（带重试 + 最小条数校验） ----------
# 用法: fetch <id> <最小合法行数>
fetch() {
  local id="$1" min_lines="$2"
  local part="$TMP/$id.part" out="$TMP/$id.txt" n
  local code body

  for attempt in 1 2 3; do
    echo "  · [$id] 第 $attempt 次拉取..." >&2
    code=$(curl "${CURL_OPTS[@]}" -w '%{http_code}' \
                --max-time 90 "${BASE}${id}?format=cidr" -o "$part" || true)

    if [[ "$code" != "200" ]]; then
      echo "  !! [$id] HTTP $code" >&2
      rm -f "$part"; sleep $((attempt * 5)); continue
    fi

    # 立刻校验：至少要有 min_lines 行合法 CIDR，否则视为脏数据
    n=$(tr -d '\r' < "$part" | grep -cE '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$' || true)
    if [[ "$n" -lt "$min_lines" ]]; then
      echo "  !! [$id] 只解析到 $n 条，少于 $min_lines，判定为脏响应" >&2
      rm -f "$part"; sleep $((attempt * 5)); continue
    fi

    mv "$part" "$out"
    echo "  ✓ [$id] 拿到 $n 条" >&2
    return 0
  done

  # 三次都失败：有旧缓存就降级用，否则返回失败让上层决定
  if [[ -s "$out" ]]; then
    echo "  ⚠ [$id] 全部重试失败，降级使用缓存 $(wc -l < "$out") 条" >&2
    return 0
  fi
  echo "  ✗ [$id] 拉取失败且无缓存" >&2
  return 1
}

RSC="$DIST/leichi_black.rsc"
: > "$RSC"

{
  echo "# 由 leichi-blacklist 自动生成，勿手改"
  echo "# 源：雷池 WAF 分享分组 x ${#URLS[@]}"
  echo "# 生成时间: $(date -Is)"
  echo "/log info \"[leichi] 开始导入黑名单 -> $LIST\""
} >> "$RSC"

# ---------- IPv4（每个源至少要有 1 条才算成功） ----------
{
  echo "/ip firewall address-list remove [find list=\"$LIST\"]"
  echo "/ip firewall address-list"
} >> "$RSC"

fail=0
for id in "${URLS[@]}"; do
  if fetch "$id" 1; then
    tr -d '\r' < "$TMP/$id.txt" \
      | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$' \
      | sort -u \
      | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}'
  else
    fail=$((fail + 1))
  fi
done >> "$RSC"

# ---------- IPv6 ----------
{
  echo "/ipv6 firewall address-list remove [find list=\"$LIST\"]"
  echo "/ipv6 firewall address-list"
} >> "$RSC"

for id in "${URLS[@]}"; do
  out="$TMP/$id.txt"; [ -f "$out" ] || continue
  tr -d '\r' < "$out" \
    | grep -E '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/[0-9]+$' \
    | sort -u \
    | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}'
done >> "$RSC"

echo "/log info \"[leichi] 黑名单导入完成: $LIST\"" >> "$RSC"

v4=$(grep -cE '^:do \{add address=[0-9]+\.[0-9]+' "$RSC")
v6=$(grep -cE '^:do \{add address=[0-9a-fA-F:]+:' "$RSC")

echo "===== 生成结果 ====="
echo "v4 有效条目: $v4"
echo "v6 有效条目: $v6"
echo "失败源数量: $fail"
echo "产物: $RSC ($(wc -c < "$RSC") 字节)"

# 兜底：条目太少 或 失败源过半 → 判定生成失败
total=$((v4 + v6))
if [ "$total" -lt 100 ] || [ "$fail" -gt $((${#URLS[@]} / 2)) ]; then
  echo "!! 校验不通过（total=$total fail=$fail），判定生成失败"
  exit 1
fi
