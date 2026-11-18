#!/bin/bash
# ============================================================================
# vmnet-ensure.sh — 确保 VMware vmnet 字符设备存在
#
# 背景: /dev 为 tmpfs, 重启即清空; 正常由 vmnet 模块加载时自动创建节点。
#       竞态: 若 vmware.service (vmware-networks --start) 早于节点就绪,
#       vmnet1 的 netifup 会被跳过, 接口永不创建; 虚拟机网卡则因
#       "MACVNetPortOpenDevice: can't open vmnet device" 被标记为
#       startdisconnected 后永不重试 —— 表现即虚拟机永久断网。
#
# 本脚本由 vmnet-guard.service 在 vmware.service *之前* 运行:
#   立即按主设备号 119 (vmnet) 补建缺失节点 (mknod 不依赖模块已加载,
#   模块随后加载即生效), 使 vmware-networks --start 一次成功。
#   接口级兜底 (节点在而接口缺) 由 hy2-vmnet1-dhcp.service 重启自愈负责。
#
# 幂等, 不触碰已存在的节点。
# ============================================================================
set -u

MAJOR=119
NODES="0 1 8"

created=0
for n in $NODES; do
    node="/dev/vmnet$n"
    [ -e "$node" ] && continue
    if mknod "$node" c "$MAJOR" "$n" 2>/dev/null; then
        chmod 600 "$node"
        created=$((created + 1))
        logger -t vmnet-ensure -- "created $node (c $MAJOR $n)" 2>/dev/null || true
    else
        logger -t vmnet-ensure -- "WARN: failed to create $node" 2>/dev/null || true
    fi
done

logger -t vmnet-ensure -- "done, created=$created" 2>/dev/null || true
exit 0
