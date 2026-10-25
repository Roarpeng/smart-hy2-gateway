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
#   4. 安装 ruleset-update.sh -> /usr/local/bin/ruleset-update.sh                (755)
#   5. 安装 systemd 单元 hy2-ruleset-update.{service,timer} 并启用
#      (每周一 04:30 ±10 分钟自动更新 geosite/geoip CN + ipset hy2_cn)
#   6. 安装 VMnet1 DHCP 网关服务 (hy2-vmnet1-dhcp.sh + service)
#      VMware Host-Only 的 DHCP 默认不下发 option routers, 虚拟机会"有 IP 没网关";
#      本服务重写 dhcpd.conf 后自带网关 192.168.100.1 与 DNS。
#      非 VMware 宿主由 unit 的 ConditionPathExists 自动跳过。
#   7. 安装尾声 best-effort 首跑一次 ruleset-update.sh (离线失败只 WARN)
#
# 幂等: 可重复执行; 已存在的状态文件不会被覆盖。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SRC_PROXY_SWITCH="$SCRIPT_DIR/scripts/proxy-switch.sh"
SRC_DISPATCHER="$SCRIPT_DIR/scripts/99-wifi-proxy.sh"
SRC_RULESET_UPDATE="$SCRIPT_DIR/scripts/ruleset-update.sh"
SRC_RULESET_SERVICE="$SCRIPT_DIR/scripts/systemd/hy2-ruleset-update.service"
SRC_RULESET_TIMER="$SCRIPT_DIR/scripts/systemd/hy2-ruleset-update.timer"
SRC_VMNET_DHCP="$SCRIPT_DIR/scripts/hy2-vmnet1-dhcp.sh"
SRC_VMNET_DHCP_SERVICE="$SCRIPT_DIR/scripts/systemd/hy2-vmnet1-dhcp.service"

DST_PROXY_SWITCH=/usr/local/bin/proxy-switch.sh
DST_RULESET_UPDATE=/usr/local/bin/ruleset-update.sh
DST_VMNET_DHCP=/usr/local/bin/hy2-vmnet1-dhcp.sh
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
for f in "$SRC_PROXY_SWITCH" "$SRC_DISPATCHER" "$SRC_RULESET_UPDATE" \
         "$SRC_RULESET_SERVICE" "$SRC_RULESET_TIMER" \
         "$SRC_VMNET_DHCP" "$SRC_VMNET_DHCP_SERVICE"; do
    if [[ ! -f "$f" ]]; then
        echo "错误: 缺少源文件 $f" >&2
        exit 1
    fi
done

# --- 依赖检查 (ruleset-update.sh 所需; 缺失仅告警, 不阻断安装) ---
for dep in curl jq; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "警告: 未检测到 $dep, 规则集每周自动更新将无法工作" >&2
    fi
done
if ! command -v ipset >/dev/null 2>&1; then
    echo "警告: 未检测到 ipset, 内核层中国 IP 直连不可用 (sing-box 规则判定兜底)" >&2
fi

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

# --- 安装 ruleset-update.sh (规则集每周更新) ---
install -m 755 -o root -g root "$SRC_RULESET_UPDATE" "$DST_RULESET_UPDATE"
echo "[OK] 已安装: $DST_RULESET_UPDATE"

# --- 安装 systemd 定时单元 (每周一 04:30 ±10 分钟更新规则集; 非 systemd 容错) ---
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    install -m 644 -o root -g root "$SRC_RULESET_SERVICE" /etc/systemd/system/hy2-ruleset-update.service
    install -m 644 -o root -g root "$SRC_RULESET_TIMER" /etc/systemd/system/hy2-ruleset-update.timer
    systemctl daemon-reload 2>/dev/null || true
    if systemctl enable --now hy2-ruleset-update.timer 2>/dev/null; then
        echo "[OK] 已安装并启用: hy2-ruleset-update.timer (每周一 04:30 ±10 分钟)"
    else
        echo "警告: hy2-ruleset-update.timer 启用失败, 请检查 systemd 环境" >&2
    fi
else
    echo "警告: 非 systemd 环境, 已跳过定时器安装; 可用 cron 每周调用 $DST_RULESET_UPDATE" >&2
fi

# --- 安装 VMnet1 DHCP 网关服务 (Host-Only 下发默认网关/DNS) ---
install -m 755 -o root -g root "$SRC_VMNET_DHCP" "$DST_VMNET_DHCP"
echo "[OK] 已安装: $DST_VMNET_DHCP"
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    install -m 644 -o root -g root "$SRC_VMNET_DHCP_SERVICE" /etc/systemd/system/hy2-vmnet1-dhcp.service
    systemctl daemon-reload 2>/dev/null || true
    if ! command -v vmnet-dhcpd >/dev/null 2>&1; then
        echo "[跳过] 未检测到 vmnet-dhcpd (非 VMware 宿主), 已安装单元但不启用"
    elif systemctl enable --now hy2-vmnet1-dhcp.service 2>/dev/null; then
        systemctl restart hy2-vmnet1-dhcp.service 2>/dev/null || true
        echo "[OK] 已安装并启用: hy2-vmnet1-dhcp.service (vmnet1 网关 192.168.100.1)"
    else
        echo "警告: hy2-vmnet1-dhcp.service 启用失败, 请检查 /etc/vmware/networking 中 VNET_1_DHCP" >&2
    fi
else
    echo "警告: 非 systemd 环境, 已跳过 hy2-vmnet1-dhcp.service" >&2
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
  "vmnet_iface": "vmnet1",
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

# --- 首跑一次规则集更新 (best-effort: 离线失败不影响安装退出码) ---
if "$DST_RULESET_UPDATE"; then
    echo "[OK] 规则集首跑完成 (geosite/geoip CN 已同步, 详见 HY2_RULESET 日志)"
else
    echo "警告: 规则集首跑失败 (离线?), 定时器下周一 04:30 会自动重试" >&2
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
        journalctl -t HY2_DISPATCH -t HY2_PROXY -t HY2_RULESET --since today
   4. 手动验证:
        proxy-switch.sh status
        proxy-switch.sh on  && proxy-switch.sh status
        proxy-switch.sh off && proxy-switch.sh status
        systemctl list-timers hy2-ruleset-update.timer
        systemctl status hy2-vmnet1-dhcp.service   # VMware 环境下 vmnet1 网关/DNS 下发
 提示: dispatcher 钩子即时生效, 断开/重连一次 Wi-Fi 即可触发切换。
============================================================
EOF
