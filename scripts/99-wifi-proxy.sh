#!/bin/bash
# ============================================================================
# 99-wifi-proxy.sh — NetworkManager dispatcher 钩子 (Smart Hysteria 2 Gateway)
# 安装位: /etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh
#
# NetworkManager 以两个参数调用本脚本: <接口名> <动作>
# 仅处理状态文件中指定的 Wi-Fi 接口 (默认 wlp2s0)。
#
# 策略 (状态文件顶层 wifi_policy, 缺失/空/非法值一律按 whitelist, fail-secure):
#   whitelist     默认。按 SSID 白名单判断:
#                   SSID 为空    : 隐藏网络/连接未就绪, 无法证明可信 -> 开代理
#                                  (刻意收紧: 宁可误开代理, 不放行身份不明的网络)
#                   SSID 在白名单 (jq 精确匹配): 关代理, 走直连
#                   其他 SSID    : 开代理, 全量走 Hysteria 2 隧道
#   always_proxy  恒开代理: 即使命中白名单也不放行 (日志注明"策略强制代理")
#   always_direct 恒关代理: 即使 SSID 不可信/为空也不开 (日志注明"策略强制直连")
#
# 事件矩阵:
#   up | connectivity-change: 按上表策略决策 (always_* 直接短路, 不再看 SSID)
#   down: 任何策略都关代理 (proxy-switch off 内部会确保 VMnet -> Wi-Fi 直连通路)
#   其他动作 (dhcp4-change / vpn-up / ...): 忽略, 直接退出
#
# 容错: jq 缺失 / 状态文件缺失或损坏 -> 回落默认值
#       (wifi_iface=wlp2s0, wifi_policy=whitelist, 白名单视为空 => 一律开代理,
#        fail-secure)
# ============================================================================
set -euo pipefail
export PATH="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

STATE_FILE="${STATE_FILE:-/opt/hy2-gateway/data/gateway_state.json}"
PROXY_SWITCH="${PROXY_SWITCH:-/usr/local/bin/proxy-switch.sh}"

INTERFACE="${1:-}"
ACTION="${2:-}"

# --- 状态文件读取 (容错: 文件/jq 缺失或 JSON 非法均回落空串) ---------------
state_get() {
    local key="$1"
    [[ -r "$STATE_FILE" ]] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    jq -r --arg k "$key" \
        'if (type == "object") and has($k) and (.[$k] != null) then (.[$k] | tostring) else "" end' \
        "$STATE_FILE" 2>/dev/null || true
}

# 目标 Wi-Fi 接口: 环境变量 > 状态文件 > 默认 wlp2s0
wifi_iface="$(state_get wifi_iface)"
[[ -n "$wifi_iface" ]] || wifi_iface="wlp2s0"
wifi_iface="${WIFI_IFACE:-$wifi_iface}"

log() {
    echo "[99-wifi-proxy] $*" >&2
    if command -v logger >/dev/null 2>&1; then
        logger -t HY2_DISPATCH -- "$*" 2>/dev/null || true
    fi
}

# 调用 proxy-switch 切换; 失败只记录, 不让 dispatcher 以非零退出
proxy_ctl() {
    local state="$1" reason="$2"
    if [[ -x "$PROXY_SWITCH" ]]; then
        if ! "$PROXY_SWITCH" "$state"; then
            log "WARN: $PROXY_SWITCH $state 执行返回非零"
        fi
    else
        log "WARN: 找不到可执行的 $PROXY_SWITCH, 无法切换代理"
    fi
    log "决策: proxy $state ($reason)"
}

# 当前活动 Wi-Fi 的 SSID; 空串 = 无活动连接 / 隐藏网络 / 尚未就绪
# nmcli -t 输出形如 "yes:MySSID"; SSID 本身可含冒号, 因此只剥 "yes:" 前缀
current_ssid() {
    local line
    line="$(nmcli -t -f active,ssid dev wifi 2>/dev/null | grep -m1 '^yes:' || true)"
    printf '%s' "${line#yes:}"
}

# jq 精确匹配白名单 (仅应在 if 条件中调用; 任何异常都返回"不在白名单")
ssid_whitelisted() {
    local ssid="$1"
    [[ -r "$STATE_FILE" ]] || return 1
    command -v jq >/dev/null 2>&1 || return 1
    jq -e --arg s "$ssid" 'any(.whitelist[]?; . == $s)' "$STATE_FILE" >/dev/null 2>&1
}

# --- 主流程 -----------------------------------------------------------------
if [[ -z "$INTERFACE" || -z "$ACTION" ]]; then
    log "WARN: 参数缺失 (期望 <接口> <动作>), 忽略本次调用"
    exit 0
fi

# 只处理目标 Wi-Fi 接口; 有线 enp3s0 / vmnet1 等其他接口的事件直接忽略
if [[ "$INTERFACE" != "$wifi_iface" ]]; then
    exit 0
fi

case "$ACTION" in
    up|connectivity-change)
        # 读取策略: 缺失/空/非法值都落入 *) 分支 => 按 whitelist 处理 (fail-secure)
        wifi_policy="$(state_get wifi_policy)"
        case "$wifi_policy" in
            always_proxy)
                # 策略优先: 恒开代理, 即使命中白名单也不放行, 不进入 SSID 判断
                proxy_ctl on "策略强制代理 (wifi_policy=always_proxy), SSID '$(current_ssid)'"
                ;;
            always_direct)
                # 策略优先: 恒关代理, 即使 SSID 不可信/为空也不开, 不进入 SSID 判断
                proxy_ctl off "策略强制直连 (wifi_policy=always_direct), SSID '$(current_ssid)'"
                ;;
            *)
                # whitelist (默认): 空串 = 字段缺失; 其他未知值告警后同样回落 whitelist
                if [[ "$wifi_policy" != "whitelist" && -n "$wifi_policy" ]]; then
                    log "WARN: wifi_policy='$wifi_policy' 非法 (期望 whitelist|always_proxy|always_direct), 按 whitelist 处理"
                fi
                ssid="$(current_ssid)"
                if [[ -z "$ssid" ]]; then
                    # 刻意收紧 (相对早期原型): SSID 为空 => 不可信 => 开代理。
                    # 隐藏网络与"连接尚未就绪"都落在这里, 宁可误开不误放;
                    # 后续 connectivity-change 事件拿到真实 SSID 后会自动纠正。
                    log "WARN: $INTERFACE $ACTION 时 SSID 为空 (隐藏网络/未就绪), 按不可信处理"
                    proxy_ctl on "SSID 为空, fail-secure"
                elif ssid_whitelisted "$ssid"; then
                    proxy_ctl off "SSID '$ssid' 命中白名单, 走直连"
                else
                    proxy_ctl on "SSID '$ssid' 不在白名单, 走 Hysteria 2 隧道"
                fi
                ;;
        esac
        ;;
    down)
        # Wi-Fi 断开: 不再清除 TProxy 规则。
        # 断网期间规则无害(无流量可劫持), 且 down->off->up 依赖事件恢复,
        # 在 Wi-Fi 波动场景会造成规则丢失窗口(实测踩坑); 直连通路由
        # MASQUERADE 常驻规则兜底。清除规则只发生在明确的直连决策时。
        log "决策: 保持现有规则 ($INTERFACE down, 断网不清规则)"
        ;;
    *)
        # 其他动作不改变代理状态
        ;;
esac

exit 0
