#!/bin/bash
# ===================================================================
# link-scheduler.sh — 链路调度器 (链路健康探测与连接自愈调度)
#
# 策略: 直连节点健康用直连; 配置中继时劣化切换(防抖 2 轮)。
#       单节点模式主路径是自愈重建 (activate 重启 sing-box = 全新 QUIC 五元组):
#       a) 握手健康但吞吐连续 2 轮死 (DPI 咬存量连接) → 重建
#       b) 单节点模式握手连续 HEAL_FAIL_N 轮死 → 重建重试
#       重建带 HEAL_COOLDOWN 冷却, 防风暴。
#
# 判定: POST /api/nodes/test 测目标节点握手 — ok 且 latency<3000ms 为健康。
# 状态: /opt/hy2-gateway/data/.link-scheduler-state
#       (五列: ok_cnt fail_cnt round slow_cnt last_heal_ts, 跨次持久)
# 日志: /opt/hy2-gateway/data/link-scheduler.log
#
# 部署: systemd timer 每 2 分钟单发 (scripts/systemd/link-scheduler.{service,timer})
# 单发无状态竞争; 本脚本一次运行只做一轮探测+至多一次切换。
# ===================================================================
set -u
DATA_DIR="/opt/hy2-gateway/data"
SCHED_STATE="$DATA_DIR/.link-scheduler-state"
LOG="$DATA_DIR/link-scheduler.log"
RELAY_OFF="$DATA_DIR/.relay-disabled"   # 存在即禁用降级中继(仅记录不切换); 删除即恢复
# gateway_state.json/api_token 由容器内 root 写, 宿主普通用户不可读 — 经 docker exec 读
DOCKER="docker exec hy2-gateway"
TOKEN=$($DOCKER cat /data/api_token 2>/dev/null)
API="http://127.0.0.1:8080"
DIRECT_TAG="${DIRECT_TAG:-}"            # 可选: 指定直连主节点 tag (未设置则自动跟随当前激活节点)
RELAY_TAG="${RELAY_TAG:-}"              # 可选: 指定备用中继节点 tag
HEALTH_MS=3000               # 直连节点握手延迟阈值
DEBOUNCE=2                   # 连续 N 次同结论才切换
# 吞吐探测+自愈: 握手探测是新连接, 测不到存量 QUIC 连接被 DPI 咬合
# 劣化; 经容器 diag-in(127.0.0.1:19090, 与用户流量共用出站连接)定期拉小文件测速,
# 握手健康但吞吐连续 2 轮低于阈值 → activate 当前节点重建 sing-box 连接 (自愈)。
DIAG_PROXY="socks5h://127.0.0.1:19090"
DIAG_PROXY_AUTH="${DIAG_PROXY_AUTH:-}"
TP_URL="https://speed.cloudflare.com/__down?bytes=1000000"
THRESH_KB=400                # KB/s 自愈阈值 (健康直连 1-3MB/s; 半死态实测 68-211KB/s
                             #  横跳, 200 会边界抖动漏判 — 400 保证半死稳定触发且不误伤)
TP_EVERY=5                   # 每 N 轮(2min/轮)做一次吞吐探测, 控探测流量成本
TP_TIMEOUT=25                # 吞吐探测超时(秒)
HEAL_FAIL_N=3                # 单节点模式握手连续 N 轮失败 → 重建自愈
HEAL_COOLDOWN=600            # 自愈重建冷却(秒), 两次重建至少间隔 10 分钟防风暴

log() {
    if [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 2097152 ]; then
        tail -n 1000 "$LOG" > "$LOG.tmp" && mv -f "$LOG.tmp" "$LOG"
    fi
    echo "$(date '+%F %T') $*" >> "$LOG"
}

jqstate() { $DOCKER jq -r "$1" /data/gateway_state.json 2>/dev/null; }

if [ -z "$TOKEN" ]; then
    log "ERROR: token 获取失败(容器未运行?), 退出"
    exit 1
fi

ACTIVE_ID=$(jqstate '.active_node_id')
if [ -n "$DIRECT_TAG" ]; then
    DIRECT_ID=$(jqstate ".nodes[] | select(.tag==\"$DIRECT_TAG\") | .id" | head -1)
else
    DIRECT_ID="$ACTIVE_ID"
fi
if [ -n "$RELAY_TAG" ]; then
    RELAY_ID=$(jqstate ".nodes[] | select(.tag==\"$RELAY_TAG\") | .id" | head -1)
else
    RELAY_ID=""
fi
if [ -z "$DIRECT_ID" ] || [ "$DIRECT_ID" = "null" ]; then
    log "ERROR: 直连/活动节点缺失, 退出"
    exit 1
fi
# 单节点模式: relay 缺失或未配置时降级运行 — 探测+吞吐自愈照常,
# 仅失去降级切换 (relay-disabled 时同样不切)。
if [ -z "$RELAY_ID" ] || [ "$RELAY_ID" = "null" ]; then
    RELAY_ID=""
    log "WARN: relay 节点不在库, 单节点模式运行"
fi

# --- 探测直连节点 ---
PROBE=$(timeout 40 curl -s -X POST "$API/api/nodes/test" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"ids\":[\"$DIRECT_ID\"]}" 2>/dev/null)
OK="false"; LAT="null"
if [ -n "$PROBE" ]; then
    OK=$(echo "$PROBE" | jq -r '.results[0].ok // false')
    LAT=$(echo "$PROBE" | jq -r '.results[0].latency_ms // "null"')
fi
HEALTHY=false
[ "$OK" = "true" ] && [ "$LAT" != "null" ] && [ "$LAT" -lt "$HEALTH_MS" ] 2>/dev/null && HEALTHY=true

# --- 防抖计数 (跨次持久; 五列: ok_cnt fail_cnt round slow_cnt last_heal_ts) ---
OKC=0; FAILC=0; ROUND=0; SLOWC=0; LASTHEAL=0
[ -f "$SCHED_STATE" ] && read -r OKC FAILC ROUND SLOWC LASTHEAL < "$SCHED_STATE" 2>/dev/null
# 状态文件损坏/旧版四列 → 空值兜底, 防 [ ]/(( )) 整数报错
OKC=${OKC:-0}; FAILC=${FAILC:-0}; ROUND=${ROUND:-0}; SLOWC=${SLOWC:-0}; LASTHEAL=${LASTHEAL:-0}
PREV_FAILC=$FAILC                       # 本轮计数更新前快照上一轮失败数
if [ "$HEALTHY" = "true" ]; then OKC=$((OKC+1)); FAILC=0; else FAILC=$((FAILC+1)); OKC=0; fi

# --- 吞吐探测 (每 TP_EVERY 轮例行; 上轮已慢, 或刚从握手断档恢复(上轮 fail>=2) 则每轮测) ---
# 去掉"握手健康才测"前置 — 握手失败轮底层死则 curl 返 0, SLOWC 照常
# 积累; 恢复后立即满足重建条件, 自愈最坏延迟从 12min+ 压到 ~4min。
SPD_KB=0
ROUND=$((ROUND+1)); [ "$ROUND" -gt "$TP_EVERY" ] && ROUND=1
if [ "$ROUND" -eq "$TP_EVERY" ] || [ "${SLOWC:-0}" -gt 0 ] || [ "$PREV_FAILC" -ge 2 ]; then
    CURL_AUTH_ARGS=()
    [ -n "$DIAG_PROXY_AUTH" ] && CURL_AUTH_ARGS=(-U "$DIAG_PROXY_AUTH")
    SPD=$(timeout "$TP_TIMEOUT" curl -sS -x "$DIAG_PROXY" "${CURL_AUTH_ARGS[@]}" -o /dev/null \
        -w '%{speed_download}' "$TP_URL" 2>/dev/null || echo 0)
    SPD=${SPD%%.*}                      # 去 curl 可能输出的小数尾
    SPD_KB=$(( ${SPD:-0} / 1024 ))
    log "throughput: ${SPD_KB}KB/s (阈值 ${THRESH_KB}KB/s)"
    if [ "$SPD_KB" -lt "$THRESH_KB" ]; then SLOWC=$((SLOWC+1)); else SLOWC=0; fi
fi
echo "$OKC $FAILC $ROUND $SLOWC $LASTHEAL" > "$SCHED_STATE"

# --- 决策 ---
TARGET=""
if [ "$FAILC" -ge "$DEBOUNCE" ] && [ -n "$RELAY_ID" ]; then TARGET="$RELAY_ID"
elif [ "$OKC" -ge "$DEBOUNCE" ]; then TARGET="$DIRECT_ID"
fi

# 中继禁用开关: UDP 长流全面受限时, 中继(hy2/UDP 第一跳)同样可能无吞吐;
# 存在 flag 时直连劣化仅记录, 不再切中继; 恢复: rm flag。
if [ -f "$RELAY_OFF" ] && [ -n "$RELAY_ID" ] && [ "$TARGET" = "$RELAY_ID" ]; then
    log "relay-disabled: 直连劣化仅记录, 不降级中继 (恢复: rm $RELAY_OFF)"
    TARGET=""
fi

# --- 自愈重建: 吞吐连续 2 轮死, 或单节点模式握手连续 HEAL_FAIL_N 轮死 ---
# 重建 = activate 当前节点 → backend restart=True 重启 sing-box (幂等, 新 QUIC 五元组)。
# 仅在无节点切换计划时执行 (TARGET 非空说明要切节点, 重建交给切换流程)。
# 冷却 HEAL_COOLDOWN 秒防重建风暴; 尝试即记冷却 (curl 前落盘, 失败也占坑)。
NOW=$(date +%s)
HEAL_WHY=""
if [ $(( NOW - LASTHEAL )) -ge "$HEAL_COOLDOWN" ]; then
    if [ "$SLOWC" -ge 2 ] && [ -z "$TARGET" ]; then
        HEAL_WHY="存量连接被咬 (吞吐连续${SLOWC}轮<${THRESH_KB}KB/s)"
    elif [ "$FAILC" -ge "$HEAL_FAIL_N" ] && [ -z "$TARGET" ] && [ -z "$RELAY_ID" ]; then
        # 单节点无中继可切 (2026-11-18 中转已砍): 握手连死唯一出路是重建重试
        HEAL_WHY="单节点握手连续${FAILC}轮失败"
    fi
fi
if [ -n "$HEAL_WHY" ]; then
    LASTHEAL=$NOW
    echo "$OKC $FAILC $ROUND $SLOWC $LASTHEAL" > "$SCHED_STATE"
    R=$(curl -s -X POST "$API/api/nodes/$ACTIVE_ID/activate" -H "Authorization: Bearer $TOKEN")
    if echo "$R" | jq -e '.status == "success"' >/dev/null 2>&1; then
        log "SELF-HEAL: ${HEAL_WHY}, 已重建连接 ✓"
        SLOWC=0
    else
        log "SELF-HEAL FAILED: $R"
    fi
    echo "$OKC $FAILC $ROUND $SLOWC $LASTHEAL" > "$SCHED_STATE"
fi

TAG_NOW=$(jqstate ".nodes[] | select(.id==\"$ACTIVE_ID\") | .tag")
log "probe: healthy=$HEALTHY ok=$OK lat=${LAT}ms | 计数 ok=$OKC fail=$FAILC | 当前=$TAG_NOW"

# --- 切换 (目标与当前不同才动作) ---
if [ -n "$TARGET" ] && [ "$TARGET" != "$ACTIVE_ID" ]; then
    R=$(curl -s -X POST "$API/api/nodes/$TARGET/activate" -H "Authorization: Bearer $TOKEN")
    if echo "$R" | jq -e '.status == "success"' >/dev/null 2>&1; then
        log "SWITCH: $TAG_NOW -> $([ "$TARGET" = "$DIRECT_ID" ] && echo "$DIRECT_TAG(直连)" || echo "$RELAY_TAG(中继)") ✓"
    else
        log "SWITCH FAILED: $R"
    fi
fi
