#!/bin/bash
# ============================================================================
# vmnet-ensure.sh — 确保 VMware vmnet 字符设备存在
#
# 背景: /dev 为 tmpfs, 重启即清空; vmware.service 开机时创建 /dev/vmnetN。
#       若虚拟机在设备节点就绪前启动, vmx 会报
#       "MACVNetPortOpenDevice: can't open vmnet device", 并把网卡标记为
#       startdisconnected 后永不重试 —— 表现即虚拟机永久断网。
#
# 本脚本作为开机兜底: 等待 vmware.service 后检查 /dev/vmnet0/1/8,
# 缺失则按主设备号 119 (vmnet) 补建。幂等, 不触碰已存在的节点。
# ============================================================================
set -u

MAJOR=119
NODES="0 1 8"
WAIT_SEC=20

for _ in $(seq 1 "$WAIT_SEC"); do
    [ -e /dev/vmnet1 ] && break
    sleep 1
done

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

if [ -e /dev/vmnet1 ] && ! ip link show vmnet1 >/dev/null 2>&1; then
    logger -t vmnet-ensure -- "WARN: vmnet1 interface missing, vmware.service may have failed" 2>/dev/null || true
fi

logger -t vmnet-ensure -- "done, created=$created" 2>/dev/null || true
exit 0
