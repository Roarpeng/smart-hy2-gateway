#!/bin/bash
# ============================================================================
# proxy-switch.sh — Smart Hysteria 2 Gateway 宿主机 TProxy 开关
#
# 用法:
#   proxy-switch.sh on|off|status        (enable / disable 为别名)
#
# on:
#   1. sysctl 尽力设置 net.ipv4.ip_forward / net.ipv4.ip_nonlocal_bind
#      / net.core.default_qdisc fq (fq 对 QUIC pacing 友好, Hysteria 2 出站)
#   2. 幂等清理旧规则 (链引用 -> 链 -> ip rule -> 路由表)
#   3. 策略路由: fwmark -> table -> local 路由回环, 截获交给 sing-box
#   4. mangle HY2_PRE: RJ45 直连(1) -> DNS:53 劫持(2,3) -> 中国IP集(4)
#      -> 保留网段 RETURN 绕行 -> catch-all TPROXY
#   5. HY2_OUT 同构: UID 防回环(1) -> RJ45(2) -> DNS:53 打标(3,4)
#      -> 中国IP集(5) -> 保留网段 -> catch-all MARK
#      (DNS 必须先于保留网段: 网络推私网 DNS 时按保留段放行会漏出污染)
#   6. PREROUTING 挂 HY2_PRE (转发流量/虚拟机) + OUTPUT 挂 HY2_OUT (本机)
#   7. 确保 FORWARD 放行 VMnet 源/回程 (mangle RETURN 绕行的保留网段
#      流量仍要过 FORWARD 链, Docker 宿主默认策略 DROP 会将其丢弃)
#
# off:
#   清除全部 TProxy 规则; 并确保 VMnet -> Wi-Fi 直连通路
#   (ip_forward + MASQUERADE + FORWARD ACCEPT) 始终可用。
#
# status:
#   逐项打印各组件存在性, 恒定 exit 0。
#
# 配置来源优先级: 环境变量 > 状态文件(jq) > 内置默认值
#   状态文件: /opt/hy2-gateway/data/gateway_state.json (STATE_FILE 可覆盖)
#   可覆盖项: TPROXY_PORT FWMARK TABLE WIFI_DEV VMNET_IFACE VMNET_SUBNET SINGBOX_UID CHNROUTE_SET
#   (CHNROUTE_SET 默认 hy2_cn, 元素由 /usr/local/bin/ruleset-update.sh 每周维护)
#
# 全部 iptables/ip 调用容错 (2>/dev/null || true 风格),
# 脚本可重复执行, 不因 set -e 中断。
# ============================================================================
set -euo pipefail
export PATH="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

# ---------------------------------------------------------------------------
# 配置解析: 环境变量 > 状态文件 > 默认值
# ---------------------------------------------------------------------------
STATE_FILE="${STATE_FILE:-/opt/hy2-gateway/data/gateway_state.json}"

# 从状态文件取字段; 文件缺失 / jq 缺失 / 键缺失 / 非法 JSON 一律返回空串
state_get() {
    local key="$1"
    [[ -r "$STATE_FILE" ]] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    jq -r --arg k "$key" \
        'if (type == "object") and has($k) and (.[$k] != null) then (.[$k] | tostring) else "" end' \
        "$STATE_FILE" 2>/dev/null || true
}

# pick <环境变量名> <状态文件字段> <默认值>
pick() {
    local env_name="$1" key="$2" default="$3" val=""
    val="${!env_name:-}"
    [[ -n "$val" ]] || val="$(state_get "$key")"
    [[ -n "$val" ]] || val="$default"
    printf '%s\n' "$val"
}

TPROXY_PORT="$(pick TPROXY_PORT tproxy_port 12345)"
FWMARK="$(pick FWMARK fwmark 1)"
TABLE="$(pick TABLE table 100)"
RJ45_DEV="$(pick RJ45_DEV rj45_iface enp3s0)"
WIFI_DEV="$(pick WIFI_DEV wifi_iface wlp2s0)"
VMNET_IFACE="$(pick VMNET_IFACE vmnet_iface vmnet1)"
VMNET_SUBNET="$(pick VMNET_SUBNET vmnet_subnet 192.168.100.0/24)"
SINGBOX_UID="$(pick SINGBOX_UID singbox_uid 930)"
# 中国 IP 段 ipset 集合名: 由 /usr/local/bin/ruleset-update.sh 创建与维护,
# 本脚本只引用匹配, 不负责其生命周期 (见 do_on 步骤 7 注释)
CHNROUTE_SET="$(pick CHNROUTE_SET chnroute_set hy2_cn)"

# 目的地为保留网段的流量 RETURN 绕行 (不进隧道):
#   覆盖本机/VMnet 访问局域网、链路本地、组播广播等场景。
#   注意判断的是"目的地" —— VMnet 虚拟机的源流量去公网时目的地是公网地址,
#   不命中这些 RETURN, 仍会进 TProxy; 只有去往保留地址的流量才直连。
RESERVED_NETS=(
    0.0.0.0/8
    10.0.0.0/8
    127.0.0.0/8
    169.254.0.0/16
    172.16.0.0/12
    192.168.0.0/16
    224.0.0.0/4
    240.0.0.0/4
)

# ---------------------------------------------------------------------------
# 基础工具 (全部容错, 不让 set -e 中断)
# ---------------------------------------------------------------------------
log() {
    echo "[proxy-switch] $*" >&2
    if command -v logger >/dev/null 2>&1; then
        logger -t HY2_PROXY -- "$*" 2>/dev/null || true
    fi
}

# iptables / ip 静默容错: 规则已存在/不存在/无权限 均不报错中断
ipt() { iptables "$@" 2>/dev/null || true; }
ipx() { ip "$@" 2>/dev/null || true; }

# run_warn <描述> <命令...>: 失败仅告警, 继续
run_warn() {
    local desc="$1"
    shift
    if "$@" 2>/dev/null; then
        return 0
    fi
    log "WARN: $desc 失败 (best-effort, 继续)"
}

# sysctl 尽力设置, 失败仅告警不中断
sysctl_best_effort() {
    local key="$1" value="$2"
    if command -v sysctl >/dev/null 2>&1 && sysctl -w "$key=$value" >/dev/null 2>&1; then
        return 0
    fi
    log "WARN: sysctl $key=$value 设置失败 (best-effort, 继续)"
}

# ---------------------------------------------------------------------------
# 幂等清理: 先摘链引用, 再删链, 最后清策略路由与路由表
# (删除类命令用有界循环, 最多删 3 条, 兼容历史残留的重复规则)
# ---------------------------------------------------------------------------
cleanup_tproxy() {
    local i
    for i in 1 2 3; do
        iptables -t mangle -D PREROUTING -j HY2_PRE 2>/dev/null || break
    done
    for i in 1 2 3; do
        iptables -t mangle -D OUTPUT -j HY2_OUT 2>/dev/null || break
    done
    ipt -t mangle -F HY2_PRE
    ipt -t mangle -X HY2_PRE
    ipt -t mangle -F HY2_OUT
    ipt -t mangle -X HY2_OUT
    for i in 1 2 3; do
        ip rule del fwmark "$FWMARK" table "$TABLE" 2>/dev/null || break
    done
    ipx route flush table "$TABLE"
}

# ---------------------------------------------------------------------------
# 确保 VMnet 转发直连通路 (on/off 两态都调用):
#   - off 态: Host-Only 虚拟机直连上网的必经路径
#   - on 态 : mangle RETURN 绕行的流量仍要走 FORWARD 转发 —— 除保留网段外,
#             内核层中国 IP 直连 (hy2_cn) 启用后, VM 的国内公网流量也走
#             这条路径, 而 RETURN 出来的包源地址仍是 192.168.100.x 私网,
#             没有 SNAT 会被上游路由器直接丢弃 (表现为 VM 国内流量黑洞)
# ---------------------------------------------------------------------------
ensure_forward_rules() {
    if ! iptables -C FORWARD -s "$VMNET_SUBNET" -j ACCEPT 2>/dev/null; then
        run_warn "添加 FORWARD ACCEPT (-s $VMNET_SUBNET)" \
            iptables -A FORWARD -s "$VMNET_SUBNET" -j ACCEPT
    fi
    # 回程放行: 仅放行 -s 方向会挡掉虚拟机流量的回包
    if ! iptables -C FORWARD -d "$VMNET_SUBNET" -o "$VMNET_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        run_warn "添加 FORWARD ACCEPT 回程 (-d $VMNET_SUBNET -o $VMNET_IFACE)" \
            iptables -A FORWARD -d "$VMNET_SUBNET" -o "$VMNET_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
    # SNAT: 所有被 mangle RETURN 放行、经 FORWARD 转发出 $WIFI_DEV 的 VM
    # 流量 (保留网段 + 中国 IP 内核直连) 都需要伪装成宿主地址才能回包;
    # 代理 on 时同样必须 —— sing-box 处理的流量自带源地址, 与此规则无关,
    # 但内核直连绕行的流量只有这一条 NAT 出路
    if ! iptables -t nat -C POSTROUTING -s "$VMNET_SUBNET" -o "$WIFI_DEV" -j MASQUERADE 2>/dev/null; then
        run_warn "添加 MASQUERADE ($VMNET_SUBNET -> $WIFI_DEV)" \
            iptables -t nat -A POSTROUTING -s "$VMNET_SUBNET" -o "$WIFI_DEV" -j MASQUERADE
    fi
}

# ---------------------------------------------------------------------------
# on: 开启 TProxy 代理
# ---------------------------------------------------------------------------
do_on() {
    [[ $EUID -eq 0 ]] || log "WARN: 非 root 运行, iptables/ip/sysctl 操作大概率失败 (继续尝试)"
    log "开启代理: TPROXY端口=$TPROXY_PORT FWMARK=$FWMARK TABLE=$TABLE 出口网卡=$WIFI_DEV"

    # 1. 内核参数 (尽力设置)
    sysctl_best_effort net.ipv4.ip_forward 1
    sysctl_best_effort net.ipv4.ip_nonlocal_bind 1
    # fq 对 QUIC pacing 友好 (Hysteria 2 出站): Hysteria 2 基于 QUIC 依赖
    # 精确发包节奏控速, 默认 qdisc (如 pfifo_fast/cake) 会干扰其 pacing
    sysctl_best_effort net.core.default_qdisc fq

    # 2. 幂等清理旧规则
    cleanup_tproxy

    # 3. 策略路由: 打了 FWMARK 的包查 TABLE 表, 表内 local 路由将其送回
    #    本机 loopback, 从而被 PREROUTING 的 TPROXY 规则截获交给 sing-box
    run_warn "ip rule add fwmark $FWMARK table $TABLE" \
        ip rule add fwmark "$FWMARK" table "$TABLE"
    run_warn "ip route add local default (table $TABLE)" \
        ip route add local 0.0.0.0/0 dev lo table "$TABLE"

    # 4. mangle 自定义链
    ipt -t mangle -N HY2_PRE
    ipt -t mangle -N HY2_OUT

    # 5. HY2_PRE (PREROUTING, 虚拟机/转发流量) —— 固定顺序:
    #    RJ45(1) -> DNS(2,3) -> 中国IP集(4) -> 保留网段 -> catch-all TPROXY
    # 5.1 通道A 有线硬直连
    ipt -t mangle -A HY2_PRE -i "$RJ45_DEV" -j RETURN

    # 5.2 DNS 端口劫持 (必须先于保留网段 RETURN):
    #     网络环境可能把 DHCP DNS 推成路由器/私网地址 (实测 10.x), 按保留
    #     网段放行的话明文查询根本到不了 sing-box, 直漏上游被污染
    #     (换网即复发: gemini 解析到轮换假 IP)。53 端口一律进 TProxy,
    #     由 sing-box 端口级规则移交拆分 DNS 干净应答
    ipt -t mangle -A HY2_PRE -p udp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    ipt -t mangle -A HY2_PRE -p tcp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"

    # 5.3 内核层中国 IP 直连: 目的地命中 $CHNROUTE_SET 的流量在 mangle 层
    #     直接 RETURN, 省去"进 sing-box 用户态再按 geoip-cn 判回直连"一跳;
    #     必须排在 DNS 劫持之后 —— 否则发往国内 DNS 的查询会被内核放行,
    #     再次绕过劫持。集合缺失仅告警回落 sing-box 判定, 不中断。
    #     位置固定第 4 条 (ruleset-update.sh 与后端 ensure 逻辑同位插入);
    #     元素由后端启动/每周 ruleset-update 重建, swap 原子换表即时生效;
    #     本脚本只做只读匹配, 绝不 create/destroy/flush 该集合。
    if command -v ipset >/dev/null 2>&1 && ipset list "$CHNROUTE_SET" >/dev/null 2>&1; then
        ipt -t mangle -A HY2_PRE -m set --match-set "$CHNROUTE_SET" dst -j RETURN
        CN_SET_OK=1
    else
        log "WARN: ipset $CHNROUTE_SET 不存在, 中国 IP 直连回落 sing-box 判定 (后端启动时会自动重建)"
    fi

    # 5.4 目的地为保留网段 -> RETURN 绕行 (本机/VMnet 访问局域网不进隧道)
    local net
    for net in "${RESERVED_NETS[@]}"; do
        ipt -t mangle -A HY2_PRE -d "$net" -j RETURN
    done

    # 5.5 catch-all: 其余全部交给 sing-box
    ipt -t mangle -A HY2_PRE -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    ipt -t mangle -A HY2_PRE -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    ipt -t mangle -A PREROUTING -j HY2_PRE

    # 6. HY2_OUT (OUTPUT, 本机流量) —— 固定顺序:
    #    UID 防回环(1) -> RJ45(2) -> DNS(3,4) -> 中国IP集(5) -> 保留网段 -> catch-all MARK
    ipt -t mangle -A HY2_OUT -o "$RJ45_DEV" -j RETURN
    # 6.1 DNS 先于保留网段打标 (理由同 5.2: 私网 DNS 也要进拆分 DNS)
    ipt -t mangle -A HY2_OUT -p udp --dport 53 -j MARK --set-mark "$FWMARK"
    ipt -t mangle -A HY2_OUT -p tcp --dport 53 -j MARK --set-mark "$FWMARK"
    # 6.2 内核层中国 IP 直连 (位置固定第 5 条, 与 ensure 逻辑一致)
    if [[ "${CN_SET_OK:-0}" -eq 1 ]]; then
        ipt -t mangle -A HY2_OUT -m set --match-set "$CHNROUTE_SET" dst -j RETURN
    fi
    # 6.3 保留网段绕行
    for net in "${RESERVED_NETS[@]}"; do
        ipt -t mangle -A HY2_OUT -d "$net" -j RETURN
    done
    # 6.4 catch-all 打标, 由策略路由送回本机 TProxy
    ipt -t mangle -A HY2_OUT -p tcp -j MARK --set-mark "$FWMARK"
    ipt -t mangle -A HY2_OUT -p udp -j MARK --set-mark "$FWMARK"

    # 6.5 回环防护 (必须保持为 HY2_OUT 首条规则):
    #     sing-box 以 UID 930 运行, 其自身出站 (含 cn-dns 上游查询) 若再被
    #     OUTPUT 劫持会形成 "sing-box -> TProxy -> sing-box -> ..." 死循环
    ipt -t mangle -I HY2_OUT 1 -m owner --uid-owner "$SINGBOX_UID" -j RETURN
    ipt -t mangle -A OUTPUT -j HY2_OUT

    # 9. FORWARD 放行 (见 ensure_forward_rules 注释: RETURN 绕行流量所需)
    ensure_forward_rules

    log "代理已开启: 全量流量 (本机 + VMnet $VMNET_SUBNET) -> TProxy :$TPROXY_PORT (Hysteria 2)"

    # 决策落盘: 后端 rule-guard 每 30s 对齐此期望态, 规则被意外清除时自动恢复
    echo "on" > "$(dirname "$STATE_FILE")/last_decision" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# off: 关闭代理, 恢复直连
# ---------------------------------------------------------------------------
do_off() {
    [[ $EUID -eq 0 ]] || log "WARN: 非 root 运行, iptables/ip/sysctl 操作大概率失败 (继续尝试)"
    log "关闭代理, 恢复直连"

    # 1. 清除全部 TProxy 规则 (幂等)
    cleanup_tproxy

    # 2. 保留/确保直连通路: Host-Only 虚拟机上网依赖宿主转发 + 伪装,
    #    无论代理开关状态, 这条通路必须始终存在 (MASQUERADE 现统一由
    #    ensure_forward_rules 保证, on 态同样需要 —— 见其注释)
    sysctl_best_effort net.ipv4.ip_forward 1

    # 放行 VMnet 源/回程转发 (幂等, 与 on 态共用同一助手)
    ensure_forward_rules

    log "已恢复直连: VMnet $VMNET_SUBNET 经 $WIFI_DEV MASQUERADE 出网通路已确保"

    # 决策落盘: 后端 rule-guard 每 30s 对齐此期望态 (见 do_on 注释)
    echo "off" > "$(dirname "$STATE_FILE")/last_decision" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# status: 逐项检查
# ---------------------------------------------------------------------------
report() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '[在] %s\n' "$desc"
    else
        printf '[无] %s\n' "$desc"
    fi
}

sysctl_value() {
    local key="$1" val="?"
    if command -v sysctl >/dev/null 2>&1; then
        val="$(sysctl -n "$key" 2>/dev/null || echo '?')"
    fi
    printf '%s' "$val"
}

do_status() {
    echo "============ HY2 Gateway TProxy 状态 ============"
    if [[ -r "$STATE_FILE" ]]; then
        echo "状态文件: $STATE_FILE [可读]"
    else
        echo "状态文件: $STATE_FILE [缺失/不可读, 已回落默认值]"
    fi
    printf '生效配置: TPROXY_PORT=%s FWMARK=%s(%s) TABLE=%s WIFI_DEV=%s VMNET_IFACE=%s VMNET_SUBNET=%s SINGBOX_UID=%s\n' \
        "$TPROXY_PORT" "$FWMARK" "$(printf '0x%x' "$FWMARK" 2>/dev/null || echo '?')" \
        "$TABLE" "$WIFI_DEV" "$VMNET_IFACE" "$VMNET_SUBNET" "$SINGBOX_UID"
    echo
    echo "--- mangle 表 ---"
    report "自定义链 HY2_PRE" iptables -t mangle -L HY2_PRE
    report "自定义链 HY2_OUT" iptables -t mangle -L HY2_OUT
    report "PREROUTING 挂载 HY2_PRE" iptables -t mangle -C PREROUTING -j HY2_PRE
    report "OUTPUT 挂载 HY2_OUT" iptables -t mangle -C OUTPUT -j HY2_OUT
    report "HY2_OUT 首条 owner UID=$SINGBOX_UID RETURN (回环防护)" \
        iptables -t mangle -C HY2_OUT -m owner --uid-owner "$SINGBOX_UID" -j RETURN
    report "RJ45 硬直连: HY2_PRE -i $RJ45_DEV RETURN" \
        iptables -t mangle -C HY2_PRE -i "$RJ45_DEV" -j RETURN
    report "RJ45 硬直连: HY2_OUT -o $RJ45_DEV RETURN" \
        iptables -t mangle -C HY2_OUT -o "$RJ45_DEV" -j RETURN
    report "TCP TPROXY -> :$TPROXY_PORT" \
        iptables -t mangle -C HY2_PRE -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    report "UDP TPROXY -> :$TPROXY_PORT" \
        iptables -t mangle -C HY2_PRE -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    report "本机 TCP MARK" iptables -t mangle -C HY2_OUT -p tcp -j MARK --set-mark "$FWMARK"
    report "本机 UDP MARK" iptables -t mangle -C HY2_OUT -p udp -j MARK --set-mark "$FWMARK"
    echo
    echo "--- 策略路由 ---"
    if ip rule show 2>/dev/null | grep -q "lookup $TABLE"; then
        echo "[在] ip rule fwmark $FWMARK lookup $TABLE"
    else
        echo "[无] ip rule fwmark $FWMARK lookup $TABLE"
    fi
    if ip route show table "$TABLE" 2>/dev/null | grep -q "local"; then
        echo "[在] table $TABLE local 路由 (0.0.0.0/0 dev lo)"
    else
        echo "[无] table $TABLE local 路由 (0.0.0.0/0 dev lo)"
    fi
    echo
    echo "--- DNS 劫持 (53 端口先行, 私网 DNS 同样接管) ---"
    report "HY2_PRE UDP:53 TPROXY" \
        iptables -t mangle -C HY2_PRE -p udp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    report "HY2_PRE TCP:53 TPROXY" \
        iptables -t mangle -C HY2_PRE -p tcp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
    report "HY2_OUT UDP:53 MARK" iptables -t mangle -C HY2_OUT -p udp --dport 53 -j MARK --set-mark "$FWMARK"
    report "HY2_OUT TCP:53 MARK" iptables -t mangle -C HY2_OUT -p tcp --dport 53 -j MARK --set-mark "$FWMARK"
    echo
    echo "--- 中国 IP 直连 (内核层 $CHNROUTE_SET) ---"
    if command -v ipset >/dev/null 2>&1 && ipset list "$CHNROUTE_SET" >/dev/null 2>&1; then
        local chn_cnt
        # ipset list 输出的 Members 段每行一个成员 (IP/CIDR 均以数字开头),
        # 其余头部字段行不以数字开头, 故按行首数字计行; 取不到则显示 [无]
        chn_cnt="$(ipset list "$CHNROUTE_SET" | grep -c '^[0-9]' || true)"
        echo "[在] ipset $CHNROUTE_SET (元素数: ${chn_cnt:-[无]})"
    else
        echo "[无] ipset $CHNROUTE_SET (先运行 ruleset-update.sh)"
    fi
    report "HY2_PRE 中国 IP RETURN (-m set $CHNROUTE_SET dst)" \
        iptables -t mangle -C HY2_PRE -m set --match-set "$CHNROUTE_SET" dst -j RETURN
    report "HY2_OUT 中国 IP RETURN (-m set $CHNROUTE_SET dst)" \
        iptables -t mangle -C HY2_OUT -m set --match-set "$CHNROUTE_SET" dst -j RETURN
    echo
    echo "--- 直连通路 (off 态保障) ---"
    report "MASQUERADE $VMNET_SUBNET -> $WIFI_DEV" \
        iptables -t nat -C POSTROUTING -s "$VMNET_SUBNET" -o "$WIFI_DEV" -j MASQUERADE
    report "FORWARD ACCEPT -s $VMNET_SUBNET" \
        iptables -C FORWARD -s "$VMNET_SUBNET" -j ACCEPT
    report "FORWARD ACCEPT 回程 -d $VMNET_SUBNET -o $VMNET_IFACE" \
        iptables -C FORWARD -d "$VMNET_SUBNET" -o "$VMNET_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    echo
    echo "--- 内核参数 ---"
    printf 'net.ipv4.ip_forward       = %s\n' "$(sysctl_value net.ipv4.ip_forward)"
    printf 'net.ipv4.ip_nonlocal_bind = %s\n' "$(sysctl_value net.ipv4.ip_nonlocal_bind)"
    echo "=================================================="
}

usage() {
    cat <<'EOF'
用法: proxy-switch.sh on|off|status

  on | enable    开启 TProxy: mangle 劫持 + 策略路由, 全量流量走 Hysteria 2 隧道
                 (中国 IP 命中 hy2_cn ipset 时在内核 mangle 层直接直连,
                  并尽力设置 net.core.default_qdisc=fq, QUIC pacing 友好)
  off | disable  关闭 TProxy: 清除规则恢复直连 (保留 VMnet -> Wi-Fi 伪装通路)
  status         检查各组件存在性 (恒定 exit 0)

配置优先级: 环境变量 > /opt/hy2-gateway/data/gateway_state.json > 默认值
可覆盖变量: STATE_FILE TPROXY_PORT FWMARK TABLE RJ45_DEV WIFI_DEV VMNET_IFACE VMNET_SUBNET SINGBOX_UID CHNROUTE_SET
(CHNROUTE_SET 默认 hy2_cn, 元素由 /usr/local/bin/ruleset-update.sh 每周维护)
EOF
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        on|enable)      do_on ;;
        off|disable)    do_off ;;
        status)         do_status ;;
        -h|--help|help) usage ;;
        *)              usage >&2; exit 1 ;;
    esac
}

main "$@"
