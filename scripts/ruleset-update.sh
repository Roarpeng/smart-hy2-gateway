#!/bin/bash
# ============================================================================
# ruleset-update.sh — Smart Hysteria 2 Gateway 地理分流规则集更新
#
# 用法:
#   ruleset-update.sh     (无参数; 由 hy2-ruleset-update.timer 每周一 04:30
#                          触发, 也可手动执行)
#
# 流程:
#   1. 从上游下载 geosite-cn.srs / geoip-cn.srs 到 mktemp -d 暂存目录
#   2. 校验每个文件存在且 > 1KB, 任一失败 -> 日志 + exit 1
#      (systemd 会显示 failed, 下周期 Persistent/重试兜底)
#   3. 原子替换仓库侧 ruleset/ (同目录临时文件 + rename, 杜绝半成品)
#   4. docker cp 投递到容器 /usr/local/share/sing-box/
#      (docker 不可用/容器不在 -> WARN 跳过, 不算失败)
#   5. 重建 ipset hy2_cn (内核层中国 IP 直连, 数据源 = 同一份 geoip-cn.srs,
#      与 sing-box 判定单一数据源):
#        容器内 sing-box rule-set decompile -> jq 提取全部 ip_cidr
#        -> 临时集填充 -> ipset swap 原子切换 -> destroy 临时集
#      swap 后内核里已有 iptables 规则即时命中新数据, 无需改规则
#   6. 代理当前 on (存在 HY2_PRE 链) 时 ensure 两条 mangle match-set RETURN
#      规则, 与 proxy-switch.sh 插入的规则逐字一致:
#        iptables -t mangle -I HY2_PRE 2 -m set --match-set hy2_cn dst -j RETURN
#        iptables -t mangle -I HY2_OUT 3 -m set --match-set hy2_cn dst -j RETURN
#      (-C 检查不带位置; 已存在则跳过)
#   7. 探活后端 API -> GET /api/state -> 剔除后端附加的 "status" 键
#      -> POST /api/apply 回传, 触发 sing-box 重建配置 -> check -> 重启,
#      让新 geosite 生效。已核实 backend_app.py: /api/state 归一化返回
#      与 POST /api/apply 的 StateModel 同构 (含节点 id), 可直接回传。
#
# 失败语义:
#   - 下载/校验/仓库落盘失败 -> exit 1 (systemd failed)
#   - 容器/ipset/iptables/API 任一步骤失败 -> WARN 后继续, 不中断
#     (旧数据仍在运行, sing-box 下次重启自然加载新规则集)
#   - 不允许 docker restart 作为自动手段
#
# 配置来源优先级: 环境变量 > 内置默认值
#   可覆盖项: REPO_DIR SRC_BASE CHNROUTE_SET API
# ============================================================================
set -euo pipefail
export PATH="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR="${REPO_DIR:-/opt/hy2-gateway}"
SRC_BASE="${SRC_BASE:-https://raw.githubusercontent.com}"
CHNROUTE_SET="${CHNROUTE_SET:-hy2_cn}"
API="${API:-http://127.0.0.1:8080}"

GEOSITE_URL="$SRC_BASE/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
GEOIP_URL="$SRC_BASE/SagerNet/sing-geoip/rule-set/geoip-cn.srs"

RULESET_DIR="$REPO_DIR/ruleset"
CONTAINER=hy2-gateway
CONTAINER_RULESET_DIR=/usr/local/share/sing-box
NEW_SET="${CHNROUTE_SET}_new"

# ---------------------------------------------------------------------------
# 基础工具 (log 风格与 proxy-switch.sh 一致)
# ---------------------------------------------------------------------------
log() {
    echo "[ruleset-update] $*" >&2
    if command -v logger >/dev/null 2>&1; then
        logger -t HY2_RULESET -- "$*" 2>/dev/null || true
    fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------------------
# 1. 下载 + 校验 (任一失败 -> exit 1)
# ---------------------------------------------------------------------------
download() {
    # download <url> <目标文件>
    # --max-time 兜底: 只有 connect-timeout 时, 慢速挂起会让 systemd oneshot
    # 服务一直卡着 (直到 DefaultTimeoutStartSec 被杀并标失败)
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 120 -o "$2" "$1"
}

srs_ok() {
    # 文件存在、非空且 > 1KB (拦截 404 错误页/半成品)
    local f="$1"
    [ -s "$f" ] && [ "$(wc -c < "$f")" -gt 1024 ]
}

[[ $EUID -eq 0 ]] || log "WARN: 非 root 运行, docker/ipset/iptables 操作大概率失败 (继续尝试)"
command -v curl >/dev/null 2>&1 || { log "ERROR: 缺少依赖 curl"; exit 1; }

if ! download "$GEOSITE_URL" "$TMP_DIR/geosite-cn.srs"; then
    log "ERROR: 下载失败: $GEOSITE_URL"
    exit 1
fi
if ! download "$GEOIP_URL" "$TMP_DIR/geoip-cn.srs"; then
    log "ERROR: 下载失败: $GEOIP_URL"
    exit 1
fi
for f in geosite-cn.srs geoip-cn.srs; do
    if ! srs_ok "$TMP_DIR/$f"; then
        log "ERROR: 校验失败: $TMP_DIR/$f (不存在/为空/<=1KB)"
        exit 1
    fi
done
log "下载完成: geosite-cn.srs $(wc -c < "$TMP_DIR/geosite-cn.srs") B, geoip-cn.srs $(wc -c < "$TMP_DIR/geoip-cn.srs") B"

# ---------------------------------------------------------------------------
# 2. 原子替换仓库侧 (同目录临时文件 + rename, 任一时刻文件都是完整的)
# ---------------------------------------------------------------------------
mkdir -p "$RULESET_DIR"
for f in geosite-cn.srs geoip-cn.srs; do
    cp -f "$TMP_DIR/$f" "$RULESET_DIR/.$f.tmp"
    mv -f "$RULESET_DIR/.$f.tmp" "$RULESET_DIR/$f"
done
log "仓库侧规则集已更新: $RULESET_DIR/{geosite-cn.srs,geoip-cn.srs}"

# ---------------------------------------------------------------------------
# 3. 容器侧投递 (docker 不可用/容器不在 -> WARN 跳过, 不算失败)
# ---------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    ok=1
    docker cp "$RULESET_DIR/geosite-cn.srs" "$CONTAINER:$CONTAINER_RULESET_DIR/" 2>/dev/null || ok=0
    docker cp "$RULESET_DIR/geoip-cn.srs" "$CONTAINER:$CONTAINER_RULESET_DIR/" 2>/dev/null || ok=0
    if [[ $ok -eq 1 ]]; then
        log "容器侧规则集已投递: $CONTAINER:$CONTAINER_RULESET_DIR/"
    else
        log "WARN: docker cp 投递失败 (容器未运行?), 容器内维持旧版规则集"
    fi
else
    log "WARN: 未检测到 docker, 跳过容器侧投递"
fi

# ---------------------------------------------------------------------------
# 4. 重建 ipset (内核层中国 IP 直连; 失败一律 WARN 保留旧集)
# ---------------------------------------------------------------------------
rebuild_ipset() {
    local cidr_file="$TMP_DIR/geoip-cn.cidr" count=0 entries="?"

    command -v ipset >/dev/null 2>&1 || { log "WARN: 未检测到 ipset, 跳过内核层直连集更新 (sing-box 判定兜底)"; return 0; }
    command -v jq >/dev/null 2>&1 || { log "WARN: 未检测到 jq, 跳过内核层直连集更新"; return 0; }

    # 容器内 decompile -> JSON (只读操作)
    if ! docker exec "$CONTAINER" sing-box rule-set decompile \
            "$CONTAINER_RULESET_DIR/geoip-cn.srs" > "$TMP_DIR/geoip-cn.json" 2>/dev/null; then
        log "WARN: sing-box rule-set decompile 失败 (容器不可用?), 跳过 ipset 更新"
        return 0
    fi

    # 提取全部 ip_cidr 数组元素 (decompile 结构: {"version":N,"rules":[{"ip_cidr":[...]}]});
    # []? 使缺 ip_cidr 的规则/键缺失时静默跳过而非报错。
    # 再过滤只留 IPv4: 上游 (MaxMind 派生) 混有 IPv6 CN 段, 而本集 family inet
    # 且网关仅接管 IPv4 —— 混入会使 ipset restore 整体失败
    jq -r '.rules[]?.ip_cidr[]?' "$TMP_DIR/geoip-cn.json" 2>/dev/null \
        | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' > "$cidr_file" || true
    count="$(grep -c . "$cidr_file" 2>/dev/null || true)"
    count="${count:-0}"
    if [[ "$count" -lt 1 ]]; then
        log "WARN: decompile 未提取到任何 ip_cidr, 保留现有 $CHNROUTE_SET"
        return 0
    fi

    # 临时集: hash:net family inet maxelem 65536
    ipset create "$NEW_SET" hash:net family inet maxelem 65536 -exist 2>/dev/null || true
    ipset flush "$NEW_SET" 2>/dev/null || true

    # 批量灌入 (逐行 "add <set> <cidr> -exist"; -exist 使重复等单条错误不致命)
    if ! while read -r cidr; do
             printf 'add %s %s -exist\n' "$NEW_SET" "$cidr"
         done < "$cidr_file" | ipset restore -exist 2>/dev/null; then
        log "WARN: ipset restore 灌入失败, 保留现有 $CHNROUTE_SET"
        ipset destroy "$NEW_SET" 2>/dev/null || true
        return 0
    fi

    # 主集不存在则先建 (首次部署), 再原子切换
    ipset create "$CHNROUTE_SET" hash:net family inet maxelem 65536 -exist 2>/dev/null || true
    if ! ipset swap "$NEW_SET" "$CHNROUTE_SET" 2>/dev/null; then
        log "WARN: ipset swap 失败, 保留现有 $CHNROUTE_SET"
        ipset destroy "$NEW_SET" 2>/dev/null || true
        return 0
    fi
    ipset destroy "$NEW_SET" 2>/dev/null || true

    entries="$(ipset list "$CHNROUTE_SET" 2>/dev/null | awk '/^Number of entries:/ {print $4; exit}')"
    log "ipset $CHNROUTE_SET 已原子切换: 灌入 $count 条 CIDR (当前条目数: ${entries:-?})"
}
rebuild_ipset

# ---------------------------------------------------------------------------
# 5. 代理 on 时确保 mangle 直连回程规则 (全部容错, 不中断)
#    -C 检查不带位置; 不存在才按固定位点 -I, 与 proxy-switch.sh 逐字一致。
#    插入可能失败 (典型: ipset 未安装/集合未建, iptables -m set 无从匹配),
#    失败必须如实 WARN —— 不能"吞掉错误仍报已插入"
# ---------------------------------------------------------------------------
ensure_cn_rule() {
    # ensure_cn_rule <链> <插入位次>
    # 位次与 proxy-switch.sh 构建序一致: HY2_PRE=4 (RJ45,DNS:53 之后),
    # HY2_OUT=5 (UID,RJ45,DNS:53 之后) —— 必须后于 DNS 劫持(否则国内 DNS
    # 查询被内核放行绕过劫持)、先于 catch-all
    local chain="$1" pos="$2"
    if iptables -t mangle -C "$chain" -m set --match-set "$CHNROUTE_SET" dst -j RETURN 2>/dev/null; then
        return 0  # 已在位
    fi
    if iptables -t mangle -I "$chain" "$pos" -m set --match-set "$CHNROUTE_SET" dst -j RETURN 2>/dev/null; then
        log "已插入: $chain 位${pos} -m set --match-set $CHNROUTE_SET dst -j RETURN"
    else
        log "WARN: $chain 中国 IP 直连规则插入失败 (ipset $CHNROUTE_SET 不存在?), sing-box 判定兜底"
    fi
}

if iptables -t mangle -L HY2_PRE >/dev/null 2>&1; then
    ensure_cn_rule HY2_PRE 4
    ensure_cn_rule HY2_OUT 5
else
    log "代理当前 off (无 HY2_PRE 链), 跳过 iptables match-set 规则 (on 时由 proxy-switch.sh 插入)"
fi

# ---------------------------------------------------------------------------
# 6. 触发 sing-box 重载 (让新 geosite 生效; 不允许 docker restart)
# ---------------------------------------------------------------------------
reload_singbox() {
    local state_json=""

    if ! curl -fsS -m 8 "$API/api/status" >/dev/null 2>&1; then
        log "WARN: 后端 API 不可达 ($API), 规则集已就位, sing-box 下次重启生效"
        return 0
    fi

    state_json="$(curl -fsS -m 8 "$API/api/state" 2>/dev/null || true)"
    if [[ -z "$state_json" ]] || ! command -v jq >/dev/null 2>&1; then
        log "WARN: 无法获取/规整 /api/state, 规则集已就位, sing-box 下次重启生效"
        return 0
    fi

    # 剔除后端附加的 "status" 标记键 (仅未初始化时出现, StateModel 无此字段);
    # 规整后为空对象 (未初始化) 则不回传, 避免凭空生成空状态文件
    state_json="$(printf '%s' "$state_json" | jq -c 'if (type == "object") then del(.status) else empty end' 2>/dev/null || true)"
    if ! printf '%s' "$state_json" | jq -e 'type == "object" and length > 0' >/dev/null 2>&1; then
        log "WARN: /api/state 为空/未初始化, 跳过重载 (规则集已就位, sing-box 下次重启生效)"
        return 0
    fi

    if printf '%s' "$state_json" | curl -fsS -m 40 -X POST -H 'Content-Type: application/json' \
            -d @- "$API/api/apply" >/dev/null 2>&1; then
        log "sing-box 已重载 (/api/apply): 新 geosite-cn/geoip-cn 已生效"
    else
        log "WARN: /api/apply 回传失败, 规则集已就位, sing-box 下次重启生效"
    fi
}
reload_singbox

log "规则集更新流程完成"
