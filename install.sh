#!/bin/bash
# ============================================================================
# install.sh — Smart Hysteria 2 Gateway 宿主机侧安装脚本
# 仓库根目录即部署目录 /opt/hy2-gateway。
#
# 职责:
#   1. 安装 proxy-switch.sh  -> /usr/local/bin/proxy-switch.sh                    (755)
#   2. 安装 99-wifi-proxy.sh -> /etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh (755, root:root)
#   3. /opt/hy2-gateway/data/gateway_state.json 不存在时生成默认状态 (600)
#      —— current_node 为占位值: 后端下发节点前 sing-box 不启动, 属预期行为
#
# 幂等: 可重复执行; 已存在的状态文件不会被覆盖。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SRC_PROXY_SWITCH="$SCRIPT_DIR/scripts/proxy-switch.sh"
SRC_DISPATCHER="$SCRIPT_DIR/scripts/99-wifi-proxy.sh"

DST_PROXY_SWITCH=/usr/local/bin/proxy-switch.sh
DISPATCHER_DIR=/etc/NetworkManager/dispatcher.d
DST_DISPATCHER="$DISPATCHER_DIR/99-wifi-proxy.sh"

STATE_DIR=/opt/hy2-gateway/data
STATE_FILE="$STATE_DIR/gateway_state.json"

# --- root 检查 ---
if [[ $EUID -ne 0 ]]; then
    echo "错误: 本脚本需要 root 权限, 请执行: sudo $0" >&2
    exit 1
fi

# --- 源文件检查 ---
for f in "$SRC_PROXY_SWITCH" "$SRC_DISPATCHER"; do
    if [[ ! -f "$f" ]]; then
        echo "错误: 缺少源文件 $f" >&2
        exit 1
    fi
done

# --- 安装 proxy-switch.sh ---
install -m 755 -o root -g root "$SRC_PROXY_SWITCH" "$DST_PROXY_SWITCH"
echo "[OK] 已安装: $DST_PROXY_SWITCH"

# --- 安装 NetworkManager dispatcher 钩子 ---
mkdir -p "$DISPATCHER_DIR"
install -m 755 -o root -g root "$SRC_DISPATCHER" "$DST_DISPATCHER"
echo "[OK] 已安装: $DST_DISPATCHER"
if ! command -v nmcli >/dev/null 2>&1; then
    echo "警告: 未检测到 nmcli (NetworkManager), dispatcher 钩子将不会被触发" >&2
fi

# --- 默认状态文件 (不存在才生成) ---
mkdir -p "$STATE_DIR"
if [[ -f "$STATE_FILE" ]]; then
    echo "[跳过] 状态文件已存在, 不覆盖: $STATE_FILE"
else
    cat > "$STATE_FILE" <<'EOF'
{
  "whitelist": ["Office-Secure", "Home_Gigabit_5G", "Lab_Internal_WLAN"],
  "current_node": {
    "tag": "hy2-out",
    "server": "",
    "port": 443,
    "password": ""
  },
  "wifi_iface": "wlp2s0",
  "rj45_iface": "enp3s0",
  "vmnet_iface": "vmnet8",
  "vmnet_subnet": "192.168.100.0/24",
  "wifi_policy": "whitelist",
  "tproxy_port": 12345,
  "fwmark": 1,
  "table": 100
}
EOF
    chown root:root "$STATE_FILE"
    chmod 600 "$STATE_FILE"
    echo "[OK] 已生成默认状态文件: $STATE_FILE"
    echo "     (current_node 为占位值: 后端下发节点前 sing-box 不启动, 属预期行为)"
fi

# --- JSON 合法性校验 (尽力) ---
if command -v jq >/dev/null 2>&1; then
    if ! jq empty "$STATE_FILE" >/dev/null 2>&1; then
        echo "警告: $STATE_FILE 不是合法 JSON, 请检查" >&2
    fi
fi

# --- 收尾提示 ---
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
[[ -n "$HOST_IP" ]] || HOST_IP="<宿主机IP>"

cat <<EOF

============================================================
 安装完成。后续步骤:
   1. 启动后端容器 (仓库部署目录 /opt/hy2-gateway):
        docker compose up -d --build
   2. 打开管理控制台:
        http://$HOST_IP:8080
   3. 查看 Wi-Fi 事件与代理切换日志:
        journalctl -t HY2_DISPATCH -t HY2_PROXY --since today
   4. 手动验证:
        proxy-switch.sh status
        proxy-switch.sh on  && proxy-switch.sh status
        proxy-switch.sh off && proxy-switch.sh status
 提示: dispatcher 钩子即时生效, 断开/重连一次 Wi-Fi 即可触发切换。
============================================================
EOF
