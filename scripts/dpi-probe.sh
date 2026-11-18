#!/bin/bash
# ===================================================================
# dpi-probe.sh — 链路"连接时长相关劣化"取证器
#
# 背景: 宽带链路"刚连上正常, 持续一段时间后国际方向劣化"。
# 三假设: H1 DPI 对长会话 UDP 流咬合(限速丢包) / H2 MTU 分片丢包 /
#         H3 NAT 表老化。本脚本采集劣化曲线, 判别实验另行手动执行。
#
# 每 60s 采一行 CSV (列固定, 逗号分隔):
#   ts                    时间戳 epoch
#   icmp_intl_loss/rtt    国际 ICMP 丢包%/avg RTT ms (8.8.8.8, 5包)
#   icmp_cn_rtt           国内 ICMP avg RTT ms (223.5.5.5, 3包) — 基线
#   tcp_intl              国际 TCP443 握手 ms (github IP 直连, 不经代理)
#   dns_tunnel_ms         经 sing-box 隧道的国外域名解析 ms (反映 UDP 隧道健康)
#   relay_port            当前 sing-box→中继节点 UDP 源端口 (变化=QUIC重连, 被咬痕迹)
#   notes                异常备注
#
# 用法: ./dpi-probe.sh <输出CSV路径> [轮询间隔秒, 默认60]
# 停止: kill <pid> (脚本自写 pidfile 于 CSV 同目录)
# ===================================================================
set -u
CSV="${1:-/opt/hy2-gateway/data/dpi-probe.csv}"
INTERVAL="${2:-60}"
PIDFILE="${CSV%.csv}.pid"
GITHUB_IP="140.82.114.4"          # github.com 固定 IP, 避免 DNS 干扰 TCP 探测
RELAY_IP="${RELAY_IP:-}"
RELAY_PORT_DST="${RELAY_PORT_DST:-}"

echo $$ > "$PIDFILE"
mkdir -p "$(dirname "$CSV")"
[ -f "$CSV" ] || echo "ts,icmp_intl_loss,icmp_intl_rtt,icmp_cn_rtt,tcp_intl,dns_tunnel_ms,relay_port,notes" >> "$CSV"

tcp_handshake_ms() {  # 国际 TCP 握手耗时; 失败输出 -1
    local t0 t1
    t0=$(date +%s%N)
    if timeout 5 bash -c "exec 3<>\/dev/tcp/${GITHUB_IP}/443" 2>/dev/null; then
        t1=$(date +%s%N); echo $(( (t1 - t0) / 1000000 ))
    else
        echo -1
    fi
}

dns_tunnel_ms() {     # 经隧道的国外域名解析 (被 tproxy 劫持→sing-box→隧道), 超时 -1
    local t0 t1
    t0=$(date +%s%N)
    if timeout 4 dig +time=3 +tries=1 @8.8.8.8 google.com +noall +answer 2>/dev/null | grep -q .; then
        t1=$(date +%s%N); echo $(( (t1 - t0) / 1000000 ))
    else
        echo -1
    fi
}

relay_src_port() {    # sing-box 到中继的 UDP 源端口; 未配置或无会话输出 0 (ss -un 无 State 列: $3=local $4=peer)
    if [[ -z "$RELAY_IP" || -z "$RELAY_PORT_DST" ]]; then
        echo 0
        return 0
    fi
    ss -H -un 2>/dev/null | awk -v peer="${RELAY_IP}:${RELAY_PORT_DST}" \
        '$4 == peer {sub(/.*:/, "", $3); print $3; exit}' | grep -E '^[0-9]+$' || echo 0
}

LAST_PORT=""
while true; do
    TS=$(date +%s)
    # 国际 ICMP (5 包统计)
    P=$(ping -c 5 -W 2 8.8.8.8 2>/dev/null)
    LOSS=$(echo "$P" | grep -oE '[0-9]+(?=% packet loss)' | head -1)
    LOSS=${LOSS:-100}
    RTT_I=$(echo "$P" | grep -oE '= [0-9.]+/' | head -1 | grep -oE '[0-9.]+' || echo -1)
    # 国内 ICMP 基线
    RTT_C=$(ping -c 3 -W 2 223.5.5.5 2>/dev/null | grep -oE '= [0-9.]+/' | head -1 | grep -oE '[0-9.]+' || echo -1)
    TCP=$(tcp_handshake_ms)
    DNS=$(dns_tunnel_ms)
    PORT=$(relay_src_port)
    NOTES=""
    [ -n "$LAST_PORT" ] && [ "$LAST_PORT" != "0" ] && [ "$PORT" != "$LAST_PORT" ] && NOTES="quic_reconnect(${LAST_PORT}->${PORT})"
    LAST_PORT="$PORT"
    echo "${TS},${LOSS},${RTT_I},${RTT_C},${TCP},${DNS},${PORT},${NOTES}" >> "$CSV"
    sleep "$INTERVAL"
done
