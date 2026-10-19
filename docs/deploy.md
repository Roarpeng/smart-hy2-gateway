# 部署运维手册（deploy.md）

本文面向运维人员，覆盖 Smart Hysteria 2 Gateway 在 Ubuntu 宿主机上的完整部署、验证、测试、排障与卸载流程。VMware 虚拟网络配置不在本文范围，见 [vmware-setup.md](vmware-setup.md)。

## 目录

1. [前置条件](#1-前置条件)
2. [部署步骤](#2-部署步骤)
3. [首次配置](#3-首次配置)
4. [验证清单](#4-验证清单)
5. [Wi-Fi 切换自动分流测试](#5-wi-fi-切换自动分流测试)
6. [故障排查表](#6-故障排查表)
7. [卸载](#7-卸载)

---

## 1. 前置条件

| 项目 | 要求 |
|------|------|
| 操作系统 | Ubuntu 22.04 / 24.04（宿主机，双网卡 enp3s0 + wlp2s0） |
| 容器环境 | Docker Engine + docker compose 插件 |
| 虚拟化 | VMware Workstation 17 |
| 系统工具 | `jq`、NetworkManager（`nmcli`） |

> **仅接管 IPv4**：TProxy 规则集只覆盖 iptables（IPv4），IPv6 流量不进隧道。双栈 Wi-Fi 环境下如需避免 IPv6 出口，建议对 Wi-Fi 连接禁用 IPv6：`nmcli connection modify "<连接名>" ipv6.method disabled`。

检查命令（全部可执行即满足）：

```bash
cat /etc/os-release | grep -E '22.04|24.04'
docker version && docker compose version
vmware --version
jq --version && nmcli --version
```

## 2. 部署步骤

### 2.1 目录放置

仓库根目录即部署目录，必须位于 `/opt/hy2-gateway`（dispatcher 钩子与状态文件路径均已按此写死）：

```bash
git clone <仓库地址> /opt/hy2-gateway
# 或： sudo cp -r ./NetWork /opt/hy2-gateway

cd /opt/hy2-gateway
```

### 2.2 install.sh 做了什么

```bash
sudo ./install.sh
```

安装脚本完成三件事，全部幂等，可重复执行：

1. 安装 TProxy 开关脚本：`scripts/proxy-switch.sh` → `/usr/local/bin/proxy-switch.sh`（可执行）。
2. 安装 NetworkManager 钩子：`scripts/99-wifi-proxy.sh` → `/etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh`（可执行）。
3. 生成种子状态文件：`/opt/hy2-gateway/data/gateway_state.json`（不存在时写入初始骨架，含白名单、`wifi_policy: whitelist` 与节点占位），权限设为 600。

### 2.3 构建并启动容器

```bash
docker compose up -d --build
```

容器要点：

- 容器名 `hy2-gateway`，`network_mode: host` + `privileged` + `NET_ADMIN`，直接操作宿主网络栈。
- sing-box 1.10.x 以 TProxy `:12345` 接收透明代理流量，Hysteria 2 (QUIC) 出站；以 UID 930 + `setcap cap_net_admin` 运行。
- FastAPI WebUI 监听 `:8080`，托管 `web/index.html`，提供 `/api/state`、`/api/apply`、`/api/status`、`/api/proxy`、`/api/interfaces`（宿主网卡枚举，供下拉选择）、`/api/nettest`（宿主机视角分段连通性诊断）。
- 挂载 `./data:/data`（状态与 sing-box 配置）。Wi-Fi 事件感知在宿主 dispatcher 侧完成，容器不挂载 dbus。

确认容器运行：

```bash
docker ps --filter name=hy2-gateway
docker logs hy2-gateway
```

## 3. 首次配置

1. 浏览器打开 `http://宿主IP:8080`。
2. 节点配置页：粘贴 v2rayN 的 `hy2://` 分享链接或节点 JSON，控制台自动解析服务器、端口、密码、SNI、obfs 等字段。
3. 白名单页：添加可信 Wi-Fi 的 SSID（例如家庭、公司办公网）。
4. 策略页：选择无线通道策略（默认「走代理·白名单例外」，即 `wifi_policy=whitelist`；可切换「强制代理」`always_proxy` / 「强制直连」`always_direct`）。策略页按双通道分组呈现：通道A（RJ45 有线）恒直连，通道B（Wi-Fi 无线）受 `wifi_policy` 控制。
5. 点击「下发 / 应用」。后端会：
   - 将配置写入 `/opt/hy2-gateway/data/gateway_state.json`；
   - 生成 sing-box 配置；
   - 执行 `sing-box check`，**校验通过后才重启 sing-box**；失败则返回错误信息且不重启，旧配置继续生效。
6. 后端离线（容器未启动）时，控制台自动进入演示模式：可查看与预填配置，但写操作不下发；后端恢复后控制台自动回到在线模式。
7. 控制台「当前 Wi-Fi」在线时可能显示「未感知」——SSID 感知在宿主 dispatcher 侧，容器内无 nmcli。真实 SSID 与切换记录以 `journalctl -t HY2_DISPATCH -t HY2_PROXY` 为准。

下发后配置在下一次 Wi-Fi 事件时自动生效；需要立即切换可手动执行：

```bash
sudo /usr/local/bin/proxy-switch.sh on    # 开启 TProxy 透明代理
sudo /usr/local/bin/proxy-switch.sh off   # 清除规则，恢复直连
```

## 4. 验证清单

以下命令均在宿主机执行。假设 Wi-Fi 已连接一个**非白名单** SSID，且无线通道策略为默认 `whitelist`（此时代理应为 on 状态）。

**策略路由**——应看到 `fwmark 0x1 lookup 100`：

```bash
ip rule
```

**路由表 100**——应看到 `local default dev lo`：

```bash
ip route show table 100
```

**mangle 链 HY2_PRE**——应有私网 RETURN 规则和 TCP/UDP TPROXY `:12345` 规则：

```bash
iptables -t mangle -S HY2_PRE
```

**mangle 链 HY2_OUT**——首规则应为 `-m owner --uid-owner 930 -j RETURN`（放行 sing-box 自身流量防回环），其后为私网 RETURN 与 MARK 规则：

```bash
iptables -t mangle -L HY2_OUT | head
```

**内核参数**——均应为 1：

```bash
sysctl net.ipv4.ip_forward net.ipv4.ip_nonlocal_bind
```

**分流日志**——应看到 dispatcher 判定与 proxy-switch 动作记录：

```bash
journalctl -t HY2_DISPATCH -t HY2_PROXY --since -10min
```

**容器日志**——sing-box 与 FastAPI 启动、配置重载记录：

```bash
docker logs hy2-gateway
```

**WebUI 后端健康**——应返回 JSON 状态：

```bash
curl http://127.0.0.1:8080/api/status
```

**网卡枚举与连通性诊断**——interfaces 返回宿主全部网卡（控制台下拉数据源），nettest 做 DNS/直连/节点分段探测：

```bash
curl http://127.0.0.1:8080/api/interfaces
curl -X POST http://127.0.0.1:8080/api/nettest -H 'Content-Type: application/json' -d '{"target":"www.google.com"}'
```

**虚拟机出口验证**——在虚拟机内执行；代理开启时因地理分流，国内与国外出口不同（国内直连、国外经节点）：

```bash
curl -s myip.ipip.net          # 国内服务: 应显示本地运营商出口 (直连)
curl -s https://api.ipify.org  # 国外服务: 应显示 Hysteria 2 节点 IP (隧道)
curl -s ifconfig.me && echo    # 同上对照
```

> 地理分流规则（geosite-cn / geoip-cn）随仓库 `ruleset/` 目录内置，构建与运行均零外联；更新规则集：从 [sing-geosite](https://gitlab.com/SagerNet/sing-geosite)/[sing-geoip](https://gitlab.com/SagerNet/sing-geoip) 的 rule-set 分支取最新 `.srs` 覆盖后 `docker compose up -d --build`。

## 5. Wi-Fi 切换自动分流测试

目的：验证 dispatcher 能自动切换 on/off。以下主流程基于默认策略 `wifi_policy=whitelist`（白名单 SSID 直连、其余走代理）；`always_proxy` / `always_direct` 两种强制模式的验证见本节末尾「策略模式验证」。

```bash
# 1. 宿主机：实时观察分流日志
journalctl -f -t HY2_DISPATCH -t HY2_PROXY

# 2. 连接一个【白名单内】的 SSID
nmcli device wifi connect "Home-WiFi" password "<密码>"
# 期望日志（dispatcher 决策 + proxy-switch 动作）：
#   HY2_DISPATCH: 决策: proxy off (SSID 'Home-WiFi' 命中白名单, 走直连)
#   HY2_PROXY:    关闭代理, 恢复直连
# 此时 ip rule 不应有 fwmark 0x1 记录，虚拟机 curl 直连出网。

# 3. 切换到【非白名单】SSID
nmcli device wifi connect "CoffeeShop-Free" password "<密码>"
# 期望日志：
#   HY2_DISPATCH: 决策: proxy on (SSID 'CoffeeShop-Free' 不在白名单, 走 Hysteria 2 隧道)
#   HY2_PROXY:    代理已开启: 全量流量 (本机 + VMnet 192.168.100.0/24) -> TProxy :12345 (Hysteria 2)
# ip rule 重新出现 fwmark 0x1 lookup 100。

# 4. 关闭 Wi-Fi
nmcli radio wifi off
# 期望日志：
#   HY2_DISPATCH: 决策: proxy off (wlp2s0 down, 恢复直连)
#   （off 内部会补 MASQUERADE 直连通路）
nmcli radio wifi on   # 测试完恢复
```

每次切换后在虚拟机内用 `curl -s ifconfig.me` 对比出口 IP：直连态为本地运营商出口，代理态为节点出口。

### 策略模式验证（wifi_policy）

dispatcher 按顶层状态字段 `wifi_policy` 三态决策：`whitelist` 即上面主流程；`always_proxy` 在 Wi-Fi up / connectivity-change 时恒开代理、忽略白名单（Wi-Fi down 事件仍会关闭代理）；`always_direct` 恒关代理。切换方法：控制台策略页修改 `wifi_policy` →「下发」→ 再切换一次 Wi-Fi 触发 dispatcher 重新决策。

```bash
# 宿主机：实时观察分流日志
journalctl -f -t HY2_DISPATCH -t HY2_PROXY

# 1. 策略页切「强制代理」(always_proxy) 下发后，连【白名单内】SSID —— 代理应仍为 on
nmcli device wifi connect "Home-WiFi" password "<密码>"
# 期望日志：HY2_DISPATCH: 决策: proxy on (SSID 'Home-WiFi' ...)（日志注明策略强制代理、白名单命中被忽略）
#   此时 ip rule 仍有 fwmark 0x1 lookup 100，虚拟机 curl -s ifconfig.me 出口为节点 IP

# 2. 策略页切「强制直连」(always_direct) 下发后，连【非白名单】SSID —— 代理应仍为 off
nmcli device wifi connect "CoffeeShop-Free" password "<密码>"
# 期望日志：HY2_DISPATCH: 决策: proxy off (SSID 'CoffeeShop-Free' ...)（日志注明策略强制直连、未命中白名单也不开代理）
#   此时 ip rule 无 fwmark 0x1 记录，虚拟机出口为本地运营商出口

# 3. 策略页恢复「走代理·白名单例外」(whitelist) 下发后，连另一【非白名单】SSID —— 回到主流程行为
nmcli device wifi connect "AnotherNet" password "<密码>"
# 期望日志：HY2_DISPATCH: 决策: proxy on (SSID 'AnotherNet' 不在白名单, 走 Hysteria 2 隧道)
```

## 6. 故障排查表

| 症状 | 原因 | 处置 |
|------|------|------|
| Wi-Fi 已连白名单，但 `ip rule` 仍有 fwmark 0x1，虚拟机流量仍走代理 | TProxy 规则残留（dispatcher 未触发或脚本执行中断）；若 `wifi_policy=always_proxy` 则属预期行为（见下一行） | 手动执行 `sudo /usr/local/bin/proxy-switch.sh off` 清除；再检查 `journalctl -t HY2_DISPATCH --since -10min` 是否有对应事件 |
| 切了白名单不生效 / 连白名单 SSID 仍走代理 | `wifi_policy` 处于 `always_proxy`（强制代理，忽略白名单） | 控制台策略页切回「白名单例外」（whitelist）模式并「下发」；随后切换一次 Wi-Fi 触发 dispatcher 重新决策 |
| 容器反复重启或起不来 | 镜像构建失败（sing-box 下载不通）或 privileged/权限不足 | `docker logs hy2-gateway` 查看具体报错；构建阶段下载 sing-box 失败时重跑 `docker compose up -d --build`，或修改 compose 的 `build.args.SINGBOX_VERSION`；确认 `privileged: true` 与 `cap_add: NET_ADMIN` 生效 |
| 代理关闭（off 态）时虚拟机无法上网 | `ip_forward` 未开启或 MASQUERADE 未生效，Host-Only 流量无人转发 | 重放 `sudo /usr/local/bin/proxy-switch.sh off`（脚本会确保 ip_forward=1 与 MASQUERADE）；检查 `iptables -t nat -S | grep MASQUERADE` 与 `sysctl net.ipv4.ip_forward` |
| 虚拟机 DNS 解析异常或缓慢 | TProxy 同时截获 UDP，DNS（UDP 53）查询也经 Hysteria 2 隧道由远端解析，属预期行为；若 DNS 服务器位于私网则直连 | 虚拟机 DNS 改用公共地址 `1.1.1.1`、`8.8.8.8`；确认节点侧可正常解析；私网 DNS 会命中 RETURN 规则直连，需保证该网段可达 |
| 控制台点「下发」后节点不生效 | 生成的 sing-box 配置未通过 `sing-box check`，后端拒绝重启 | 查看控制台 `/api/apply` 返回的错误信息定位字段（密码/SNI/端口）；`docker logs hy2-gateway` 查看 check 输出；修正后重新下发 |
| 虚拟机完全无法连通宿主 192.168.100.1 | VMnet8 子网/掩码配置错误或虚拟机 netplan 未应用 | 按 [vmware-setup.md](vmware-setup.md) 核对 VMnet8 为 Host-Only 192.168.100.0/24；虚拟机内 `sudo netplan apply` 后 `ip route` 复查 |
| 开机后分流不自动生效 | dispatcher 脚本未安装或不可执行 | `ls -l /etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh` 确认存在且可执行；重跑 `sudo ./install.sh` |

## 7. 卸载

```bash
# 1. 清除 TProxy 规则，恢复宿主直连
sudo /usr/local/bin/proxy-switch.sh off

# 2. 停止并删除容器（--rmi local 同时删除本地构建的镜像）
cd /opt/hy2-gateway && docker compose down --rmi local

# 3. 删除宿主侧脚本
sudo rm -f /usr/local/bin/proxy-switch.sh
sudo rm -f /etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh

# 4. 删除部署目录（含明文密码的状态文件，确认后执行）
sudo rm -rf /opt/hy2-gateway
```

卸载后重启 NetworkManager 或切换一次 Wi-Fi，确认 `journalctl` 中不再出现 `HY2_DISPATCH` 事件。
