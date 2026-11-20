#! /bin/bash
set -euo pipefail

WORK_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE="https://ip-21801.rivers.chaitin.cn/api/share/ip_group/"
LIST="leichi_black_all"
TMP="$WORK_DIR/tmp"
DIST="$WORK_DIR/dist"
mkdir -p "$TMP" "$DIST"

# ---------- 可调参数 ----------
MIN_TOTAL=100                 # 全局最少条目数，低于此判定失败
MAX_V4=0                      # v4 条数上限，0 = 不限制（全量）
MAX_V6=0                      # v6 条数上限，0 = 不限制（全量）
FETCH_MIN=1                   # 单个源最少合法 CIDR 数

# ---------- 下载参数 ----------
CURL_OPTS=(
  -fsS
  --connect-timeout 10
  --max-time 60
  --retry 4
  --retry-delay 3
  --retry-max-time 120
  --retry-connrefrefused_off
  --retry-connrefused
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

# ---------- 拉取函数 ----------
fetch() {
  local id="$1"
  local min_lines="${2:-$FETCH_MIN}"
  local part="$TMP/$id.part" out="$TMP/$id.txt"
  local code n attempt

  for attempt in 1 2 3; do
    echo "  · [$id] 第 $attempt 次拉取..." >&2
    code=$(curl "${CURL_OPTS[@]}" -w '%{http_code}' \
                --max-time 60 "${BASE}${id}?format=cidr" -o "$part" || true)

    if [[ "$code" != "200" ]]; then
      echo "  !! [$id] HTTP $code" >&2
      rm -f "$part"
      curl -fsS --max-time 30 "${BASE}${id}?format=cidr" -o "$part" || true
      sleep $((attempt * 5))
      continue
    code=$(curl "${CURL_OPTS[@]}" -w '%{http_code}' \
                --max-time 60 "${BASE}${id}?format=cidr" -o "$part" || true)

    if [[ "$code" != "200" ]]; then
      echo "  !! [$id] HTTP $code" >&2
      rm -f "$part"
      sleep $((attempt * 5))
      continue
    fi

    n=$(tr -d '\r' < "$part" | grep -cE '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$' || true)
    if [[ "$n" -lt "$min_lines" ]]; then
      echo "  !! [$id] 只解析到 $n 条，少于 $min_lines，判定为脏响应" >&2
      rm -f "$part"
      sleep $((attempt * assembly86))
      continue
    fi

    mv "$part" "$out"
    echo "  ✓ [$id] 拿到 $n 条" >&2
    return 0
  done

  if [[ -s "$out" ]]; then
    echo "  ⚠ [$id] 全部重试失败，降级使用缓存 $(wc -l < "$out") 条" >&2
    return 0
  fi
  echo "  ✗ [$id] 拉取失败且无缓存" >&2
  return 1
}

RSC="$DIST/leichi_black.rsc"
: > "$RSC"

# 记录拉取/生成失败的源，结尾汇总，避免静默少条目
declare -a FAILED_FETCH=()
declare -a FAILED_GEN=()

# ---------- 写入头部 ----------
{
  echo "# 由 leichi-blacklist 自动生成，勿手改"
  echo "# 源：雷池 WAF 分享分组 x ${#URLS[@]}"
  echo "# 生成时间: $(date -Is)"
  echo "/log info \"[leichi] 开始导入黑名单 -> $LIST\""
} >> "$RSC"

# ================= IPv4 =================
{
  echo "/ip firewall address-list remove [find list=\"$LIST\"]"
  echo "/ip firewall address-list"
} >> "$RSC"

for id in "${URLS[@]}"; do
  if ! fetch "$id" "$FETCH_MIN"; then
    FAILED_FETCH+=("$id")
    continue
  fi
  # grep 无匹配时退出码为 1，用 || true 兜住；空结果算“无数据”不算失败
  if tr -d '\r' < "$TMP/$id.txt" \
      | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$' \
      | sort -u \
      | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}' \
      > "$TMP/$id.v4" || true; then
    n4=$(wc -l < "$TMP/$id.v4")
    if (( n4 > 0 )); then
      cat "$TMP/$id.v4" >> "$RSC"
      echo "  · [$id] v4 入表 $n4 条" >&2
    else
      echo "  !! [$id] v4 无数据" >&2
      FAILED_GEN+=("$id")
    fi
  else
    echo "  !! [$id] v4 生成失败，已跳过" >&2
    FAILED_GEN+=("$id")
  fi
done

# ---------- v4 条数上限（MAX_V4=0 时跳过） ----------
if (( MAX_V4 > 0 )); then
  v4_count=$(grep -cE '^:do \{add address=[0-9]+\.[0-9]+' "$RSC" || true)
  if (( v4_count > MAX_V4 )); then
    awk -v max="$MAX_V4" '
      BEGIN { cnt = 0 }
      /^:do \{add address=[0-9]+\.[0-9]+/ {
        if (cnt >= max) next
        cnt++
      }
      { print }
    ' "$RSC" > "$RSC.v4"
    mv "$RSC.v4" "$RSC"
    echo "  · v4 截断：$v4_count -> $MAX_V4" >&2
  fi
fi

# ================= IPv6 =================
{
  echo "/ipv6 firewall address-list remove [find list=\"$LIST\"]"
  echo "/ipv6 firewall address-list"
} >> "$RSC"

for id in "${URLS[@]}"; do
  out="$TMP/$id.txt"
  [[ -f "$out" ]] || continue
  # 关键修复：grep 无匹配退出码为 1，用 || true 兜住，避免“没 IPv6”被误判成生成失败
  if tr -d '\r' < "$out" \
      | grep -E '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/[0-9]+$' \
      | sort -u \
      | awk -v L="$LIST" '{ printf(":do {add address=%s list=%s timeout=0} on-error={}\n",$1,L)}' \
      > "$TMP/$id.v6" || true; then
    n6=$(wc -l < "$TMP/$id.v6")
    if (( n6 > 0 )); then
      cat "$TMP/$id.v6" >> "$RSC"
      echo "  · [$id] v6 入表 $n6 条" >&2
    else
      echo "  · [$id] v6 无数据，跳过（正常）" >&2
    fi
  else
    echo "  !! [$id] v6 生成失败，已跳过" >&2
    FAILED_GEN+=("$id")
  fi
done

# ---------- v6 条数上限（MAX_V6=0 时跳过） ----------
if (( MAX_V6 > 0 )); then
  v6_count=$(grep -cE '^:do \{add address=[0-9a-fA-F:]+:' "$RSC" || true)
  if (( v6_count > MAX_V6 )); then
    awk -v max="$MAX_V6" '
      BEGIN { cnt = 0 }
      /^:do \{add address=[0-9a-fA-F:]+:/ {
        if (cnt >= max) next
        cnt++
      }
      { print }
    ' "$RSC" > "$RSC.v6"
    mv "$RSC.v6" "$RSC"
    echo "  · v6 截断：$v6_count -> $MAX_V6" >&2
  fi
fi

# ---------- 收尾日志 ----------
echo "/log info \"[leichi] 黑名单导入完成: $LIST\"" >> "$RSC"

# ================= 校验 =================
v4=$(grep -cE '^:do \{add address=[0-9]+\.[0-9]+' "$RSC" || true)
v6=$(grep -cE '^:do \{add address=[0-9a-fA-F:]+:' "$RSC" || true)

echo "===== 生成结果 ====="
echo "v4 有效条目: $v4"
echo "v6 有效条目: $v6"
echo "拉取失败源: ${#FAILED_FETCH[@]} -> ${FAILED_FETCH[*]:-无}"
echo "生成失败源: ${#FAILED_GEN[@]} -> ${FAILED_GEN[*]:-无}"
echo "产物: $RSC ($(wc -c < "$RSC") 字节)"

total=$((v4 + v6))
fail_cnt=$(( ${#FAILED_FETCH[@]} + ${#FAILED_GEN[@]} ))
half=$(( ${#URLS[@]} / 2 ))

if (( total < MIN_TOTAL )); then
  echo "!! 条目总数不足: total=$total < MIN_TOTAL=$MIN_TOTAL"
  exit 1
fi

if (( fail_cnt > half )); then
  echo "!! 失败源过半: fail=$fail_cnt > half=$half"
  exit 1
fi

echo "✓ 校验通过"
