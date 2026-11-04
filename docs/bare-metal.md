# 纯宿主部署（非 VMware）

适用于只有 Ubuntu 物理机、不需要虚拟机双网卡的场景。

## 与完整部署的差异

| 项目 | 纯宿主 | VMware 工位 |
|---|---|---|
| `vmnet-guard` / `hy2-vmnet1-dhcp` | 可忽略（unit 会因条件跳过） | 需要 |
| 虚拟机上网映射 | 可不填 | 建议按控制台建议绑定 |
| 通道网卡 | 任选两张物理/无线口 | 同上，另加 vmnet |

## 步骤

1. `sudo ./install.sh`
2. `ALLOW_LAN=0 docker compose up -d --build`（默认仅本机访问）
3. 打开 `http://127.0.0.1:8080`，粘贴 `data/api_token`
4. 「双通道」页：选择恒直连网卡与策略代理网卡（可互换介质）
5. 导入节点并启用；在「运行状态」用连通性诊断确认

## 健康检查

```bash
curl -s http://127.0.0.1:8080/api/health
curl -s -H "Authorization: Bearer $(sudo tr -d '[:space:]' < /opt/hy2-gateway/data/api_token)" \
  http://127.0.0.1:8080/api/status
```

排障一键直连：`sudo /usr/local/bin/proxy-switch.sh off`
