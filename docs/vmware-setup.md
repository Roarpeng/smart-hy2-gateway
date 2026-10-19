# VMware 虚拟网络与虚拟机配置指南（vmware-setup.md）

本文说明 VMware Workstation 17 虚拟网络（VMnet0 / VMnet8）与虚拟机内部双网卡（eth0 / eth1）的标准配置。宿主机侧的网关部署见 [deploy.md](deploy.md)。

## 目录

1. [目标拓扑](#1-目标拓扑)
2. [Virtual Network Editor 配置](#2-virtual-network-editor-配置)
3. [为何选 Host-Only 而非 NAT](#3-为何选-host-only-而非-nat)
4. [虚拟机网卡添加顺序与对应关系](#4-虚拟机网卡添加顺序与对应关系)
5. [虚拟机内部 netplan 双网卡配置](#5-虚拟机内部-netplan-双网卡配置)
6. [配置验证](#6-配置验证)

---

## 1. 目标拓扑

| 虚拟机网卡 | 虚拟网络 | 模式 | 用途 |
|-----------|---------|------|------|
| eth0 | VMnet0 | Bridged（显式桥接 enp3s0） | 工控 / 内网专线直连，不经过宿主机防火墙 |
| eth1 | VMnet8 | Host-Only 192.168.100.0/24 | 默认路由出口，经宿主机 192.168.100.1 智能分流 |

关键点：eth0 的数据帧在二层直接出入物理 RJ45 口，宿主机 iptables / TProxy 完全不可见（通道A · 恒直连）；eth1 的全部互联网流量交给宿主机（通道B），由 dispatcher 按 `wifi_policy` 决策——默认 `whitelist` 走代理、白名单 SSID 例外直连，亦可设为强制代理 / 强制直连。

## 2. Virtual Network Editor 配置

宿主机 Ubuntu 终端执行：

```bash
sudo vmware-netcfg
```

### 2.1 网卡 1（直连通路）：VMnet0

| 配置项 | 值 |
|--------|-----|
| 网络类型 | Bridged（桥接模式） |
| Bridged to | **显式指定 `enp3s0`**，切勿选择 Automatic |

效果：虚拟机 eth0 获得物理路由器分配的内网 IP，与工控设备同二层，直连且不受宿主防火墙影响。

注意：选择 Automatic 时 VMware 可能桥接到 Wi-Fi 或其他网卡，导致内网通路漂移。必须显式锁定有线网卡名。

### 2.2 网卡 2（代理通路）：VMnet8

| 配置项 | 值 |
|--------|-----|
| 网络类型 | **Host-Only**（如原为 NAT，改为 Host-Only） |
| 子网 IP | `192.168.100.0` |
| 子网掩码 | `255.255.255.0` |
| 宿主侧网关 | `192.168.100.1`（即宿主机在 vmnet8 虚拟接口上的 IP） |

效果：虚拟机出站流量经默认网关 192.168.100.1 交入宿主机内核路由，稳定穿过宿主机 PREROUTING 链，`HY2_PRE` 的 TPROXY 规则即可在此拦截并送入 sing-box。代理关闭时由 `proxy-switch.sh off` 的 MASQUERADE 兜底直连。

建议同时关闭 VMnet8 的 DHCP（虚拟机 eth1 使用静态 IP，避免地址漂移）。

## 3. 为何选 Host-Only 而非 NAT

| 对比项 | NAT 模式 | Host-Only 模式（本项目采用） |
|--------|---------|------------------------------|
| 转发路径 | 由 `vmware-natd` 用户态守护进程转发 | 宿主机内核直接路由 |
| 流量在宿主侧出现的链 | 经 NAT 后表现为本机 OUTPUT 流量 | 作为转发流量稳定经过 PREROUTING |
| 与 TPROXY 的兼容性 | TPROXY 只在 PREROUTING 链生效，NAT 流量路径绕过它，拦截行为不稳定 | 流量稳定穿过 PREROUTING，`HY2_PRE` 可靠截获 |
| 直连态（代理关闭） | 依赖 vmware-natd | 由脚本 `ip_forward` + MASQUERADE 兜底，行为可控 |

结论：**NAT 模式下流量走 vmware-natd 用户态转发，进入的是 OUTPUT 链，TPROXY（PREROUTING）路径不稳定；Host-Only 模式流量稳定经宿主 PREROUTING，是 TProxy 透明代理的唯一可靠前提。** 直连需求由脚本在 off 态打 MASQUERADE 兜底，不依赖 vmware-natd。

## 4. 虚拟机网卡添加顺序与对应关系

Linux 虚拟机按 PCI 枚举顺序命名网卡，即**添加顺序决定 eth0/eth1**：

1. 虚拟机设置（VM → Settings → Network Adapter）：第一块网卡选 **Custom → VMnet0**（对应 eth0）。
2. 点击 Add → Network Adapter 添加第二块：选 **Custom → VMnet8**（对应 eth1）。
3. 若网卡次序与预期相反（eth0/eth1 对调），两种修正方式任选：
   - 在 VMware 设置中删除后按上述顺序重新添加；
   - 或交换 netplan 中 eth0 / eth1 的配置块。

启动虚拟机后核对映射：

```bash
ip -br link                 # 应看到 eth0 与 eth1 两个接口
dmesg | grep -iE 'eth[01]' # 查看网卡注册顺序与 MAC
```

eth0 的 MAC 应与 VMware 设置中 Network Adapter 1 一致；确认无误后再进入下一步。

## 5. 虚拟机内部 netplan 双网卡配置

编辑 `/etc/netplan/01-netcfg.yaml`：

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    # eth0 对应 VMnet0（RJ45 直连，用于工控/内网专线）
    eth0:
      dhcp4: true
      dhcp4-overrides:
        route-metric: 200     # 较高跃点值，防止抢夺默认网关

    # eth1 对应 VMnet8（Wi-Fi 智能网关出口，用于日常互联网）
    eth1:
      dhcp4: false
      addresses: [192.168.100.50/24]
      routes:
        - to: default
          via: 192.168.100.1
          metric: 100         # 较低跃点值，作为默认出口
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
```

要点：

- `eth0` 用 DHCP 从物理路由器取址，`route-metric: 200` 压低优先级，仅用于内网网段通信，不抢默认路由。
- `eth1` 静态 `192.168.100.50/24`，默认路由指向宿主 `192.168.100.1`，`metric: 100` 保证它成为唯一默认出口。
- DNS 使用公共地址。代理开启时 UDP 53 同样经 Hysteria 2 隧道由远端解析，属预期行为。

应用并验证：

```bash
sudo netplan apply
ip -4 addr show eth1     # 应为 192.168.100.50/24
ip route                 # default via 192.168.100.1 metric 100 (eth1)
```

## 6. 配置验证

在虚拟机内逐项验证：

```bash
# 1. 内网通路（eth0 桥接直连，不依赖宿主）：ping 工控设备或物理路由器
ping -I eth0 <工控设备IP>

# 2. 网关可达：宿主机 vmnet8 接口
ping 192.168.100.1

# 3. 互联网出口（默认策略 whitelist 下）：
#    宿主 Wi-Fi 连白名单 SSID → 出口 IP 为本地运营商
#    宿主 Wi-Fi 连非白名单 SSID → 出口 IP 为 Hysteria 2 节点
#    （强制代理/强制直连模式下出口恒定，不随 SSID 变化）
curl -s ifconfig.me && echo

# 4. DNS
resolvectl status | grep -A2 'DNS Server'
```

若第 2 步不通，回查 [第 2 节](#2-virtual-network-editor-配置) 的 VMnet8 子网与宿主 vmnet8 接口 IP；若第 3 步在两种 SSID 下出口 IP 相同，回查宿主机分流状态（见 [deploy.md 第 5 节](deploy.md#5-wi-fi-切换自动分流测试)）。
