# VMware 虚拟网络与虚拟机配置指南（vmware-setup.md）

本文说明 VMware Workstation 17 虚拟网络（VMnet0 / VMnet1）与虚拟机内部双网卡（eth0 / eth1 或 Windows 的两块以太网）的标准配置。宿主机侧的网关部署见 [deploy.md](deploy.md)。

> **网络选择**：本项目默认使用 **VMnet1 Host-Only 192.168.100.0/24**。如果你更习惯 VMnet8，也可以把 VMnet8 从 NAT 改为 Host-Only，并把状态文件中的 `vmnet_iface` 改为 `vmnet8`；但 **不能使用 NAT**，否则流量走 `vmware-natd`，会绕过宿主 `PREROUTING`，TProxy 无法可靠接管。

## 目录

1. [目标拓扑](#1-目标拓扑)
2. [Virtual Network Editor 配置](#2-virtual-network-editor-配置)
3. [为何选 Host-Only 而非 NAT](#3-为何选-host-only-而非-nat)
4. [虚拟机网卡添加顺序与对应关系](#4-虚拟机网卡添加顺序与对应关系)
5. [虚拟机内部双网卡配置](#5-虚拟机内部双网卡配置)
6. [配置验证](#6-配置验证)

---

## 1. 目标拓扑

| 虚拟机网卡 | 虚拟网络 | 模式 | 用途 |
|-----------|---------|------|------|
| eth0 / 以太网 1 | VMnet0 | Bridged（显式桥接 enp3s0） | 工控 / 内网专线直连，不经过宿主机防火墙 |
| eth1 / 以太网 2 | VMnet1 | Host-Only 192.168.100.0/24 | 默认路由出口，经宿主机 192.168.100.1 智能分流 |

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

### 2.2 网卡 2（代理通路）：VMnet1

| 配置项 | 值 |
|--------|-----|
| 网络类型 | **Host-Only**（不要选 NAT，也不要选 Bridged） |
| 子网 IP | `192.168.100.0` |
| 子网掩码 | `255.255.255.0` |
| 宿主侧网关 | `192.168.100.1`（即宿主机在 `vmnet1` 虚拟接口上的 IP） |
| DHCP | 建议关闭；虚拟机内使用静态 IP |

效果：虚拟机出站流量经默认网关 192.168.100.1 交入宿主机内核路由，稳定穿过宿主机 PREROUTING 链，`HY2_PRE` 的 TPROXY 规则即可在此拦截并送入 sing-box。代理关闭时由 `proxy-switch.sh off` 的 MASQUERADE 兜底直连。

> VMware 自带的 Host-Only DHCP 默认不提供 `option routers`，虚拟机可能只拿到 IP 而没有默认网关。本项目推荐静态地址，避免这个坑。

## 3. 为何选 Host-Only 而非 NAT

| 对比项 | NAT 模式 | Host-Only 模式（本项目采用） |
|--------|---------|------------------------------|
| 转发路径 | 由 `vmware-natd` 用户态守护进程转发 | 宿主机内核直接路由 |
| 流量在宿主侧出现的链 | 经 NAT 后表现为本机 OUTPUT 流量 | 作为转发流量稳定经过 PREROUTING |
| 与 TPROXY 的兼容性 | TPROXY 只在 PREROUTING 链生效，NAT 流量路径绕过它，拦截行为不稳定 | 流量稳定穿过 PREROUTING，`HY2_PRE` 可靠截获 |
| 直连态（代理关闭） | 依赖 vmware-natd | 由脚本 `ip_forward` + MASQUERADE 兜底，行为可控 |

结论：**NAT 模式下流量走 vmware-natd 用户态转发，进入的是 OUTPUT 链，TPROXY（PREROUTING）路径不稳定；Host-Only 模式流量稳定经宿主 PREROUTING，是 TProxy 透明代理的唯一可靠前提。** 直连需求由脚本在 off 态打 MASQUERADE 兜底，不依赖 vmware-natd。

## 4. 虚拟机网卡添加顺序与对应关系

Linux 虚拟机按 PCI 枚举顺序命名网卡，即**添加顺序决定 eth0/eth1**；Windows 通常在“网络连接”中显示为“以太网 1 / 以太网 2”。

1. 虚拟机设置（VM → Settings → Network Adapter）：第一块网卡选 **Custom → VMnet0**（对应 eth0 / 以太网 1）。
2. 点击 Add → Network Adapter 添加第二块：选 **Custom → VMnet1**（对应 eth1 / 以太网 2）。
3. 若网卡次序与预期相反，两种修正方式任选：
   - 在 VMware 设置中删除后按上述顺序重新添加；
   - 或交换 Linux netplan 中 eth0 / eth1 的配置块。

启动虚拟机后核对映射：

```bash
# Linux
ip -br link                 # 应看到 eth0 与 eth1 两个接口
dmesg | grep -iE 'eth[01]' # 查看网卡注册顺序与 MAC
```

```powershell
# Windows（管理员 PowerShell）
Get-NetAdapter | Format-Table Name, InterfaceDescription, MacAddress, Status
```

确认第二块网卡（代理通路）已启用，且对应 VMnet1。

## 5. 虚拟机内部双网卡配置

### 5.1 Linux（netplan）

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

    # eth1 对应 VMnet1（Wi-Fi 智能网关出口，用于日常互联网）
    eth1:
      dhcp4: false
      addresses: [192.168.100.50/24]
      routes:
        - to: default
          via: 192.168.100.1
          metric: 100         # 较低跃点值，作为默认出口
      nameservers:
        addresses: [223.5.5.5, 1.1.1.1]
```

应用并验证：

```bash
sudo netplan apply
ip -4 addr show eth1     # 应为 192.168.100.50/24
ip route                 # default via 192.168.100.1 metric 100 (eth1)
```

### 5.2 Windows 11（图形界面）

1. 打开“设置 → 网络和 Internet → 高级网络设置 → 网络适配器”，找到代理网卡（通常是“以太网 2”）。
2. 右键 → 属性 → Internet 协议版本 4 (TCP/IPv4) → 属性。
3. 选择“使用下面的 IP 地址”：
   - IP 地址：`192.168.100.50`
   - 子网掩码：`255.255.255.0`
   - 默认网关：`192.168.100.1`
4. 选择“使用下面的 DNS 服务器地址”：
   - 首选：`223.5.5.5`
   - 备用：`1.1.1.1`
5. 保存后在该网卡上禁用/启用一次，或执行 `ipconfig /renew`。

### 5.3 Windows 11（管理员命令）

以管理员身份打开命令提示符，把 `<代理网卡名>` 换成实际名称（例如 `以太网 2` 或 `Ethernet1 2`）：

```bat
netsh interface ipv4 set address name="<代理网卡名>" static 192.168.100.50 255.255.255.0 192.168.100.1
netsh interface ipv4 set dnsservers name="<代理网卡名>" static 223.5.5.5 primary
netsh interface ipv4 add dnsservers name="<代理网卡名>" 1.1.1.1 index=2
ipconfig
```

要点：

- `eth0` / 以太网 1 用 DHCP 从物理路由器取址，保持较高跃点，仅用于内网网段通信，不抢默认路由。
- `eth1` / 以太网 2 静态 `192.168.100.50/24`，默认路由指向宿主 `192.168.100.1`，作为唯一默认出口。
- DNS 使用公共地址。代理开启时 UDP 53 同样经 Hysteria 2 隧道由远端解析，属预期行为。
- 若同一网段已有其他设备占用 `.50`，换一个未被占用的地址即可。

## 6. 配置验证

在虚拟机内逐项验证：

```bash
# Linux
# 1. 内网通路（eth0 桥接直连，不依赖宿主）：ping 工控设备或物理路由器
ping -I eth0 <工控设备IP>

# 2. 网关可达：宿主机 vmnet1 接口
ping 192.168.100.1

# 3. 互联网出口（默认策略 whitelist 下）：
#    宿主 Wi-Fi 连白名单 SSID → 出口 IP 为本地运营商
#    宿主 Wi-Fi 连非白名单 SSID → 出口 IP 为 Hysteria 2 节点
#    （强制代理/强制直连模式下出口恒定，不随 SSID 变化）
curl -s ifconfig.me && echo
```

```powershell
# Windows（管理员 PowerShell）
ping 192.168.100.1
(Invoke-WebRequest -UseBasicParsing https://ifconfig.me/ip).Content
```

如果 Windows `curl.exe` 报 `URL rejected: Bad hostname`，先用浏览器打开 `https://ifconfig.me/ip` 或使用上面的 PowerShell 命令验证；这通常是本机 curl/URL 解析问题，不代表代理链路不通。

若第 2 步不通，回查 [第 2 节](#2-virtual-network-editor-配置) 的 VMnet1 子网与宿主 `vmnet1` 接口 IP；若第 3 步在两种 SSID 下出口 IP 相同，回查宿主机分流状态（见 [deploy.md 第 5 节](deploy.md#5-wi-fi-切换自动分流测试)）。
