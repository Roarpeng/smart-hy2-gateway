/* ============================================================
   Smart Hy2 Gateway 控制台逻辑 (精简版: 节点配置 / 网卡配置 / 状态)
   - 后端 API 层 + 演示模式无缝回退
   - v2rayN hy2:// 链接 / sing-box JSON 解析
   - 双通道网卡配置 (A 有线恒直连 / B 无线走代理 + wifi_policy)
   - 状态视图: sing-box / TProxy 规则 / 通道策略 / Wi-Fi 通道
   说明: 源码不含任何真实凭据; 真实分享链接由使用者粘贴, 不经过源码。
   ============================================================ */
"use strict";

// 系统全局状态
const appState = {
  activeTab: 'status',
  whitelist: ['Office-Secure', 'Home_Gigabit_5G'],
  currentWifiSsid: null,      // 仅由后端 /api/status 实况填充; 演示态为 null
  network: {
    rj45Dev: 'enp3s0',
    wifiDev: 'wlp2s0',
    vmnetDev: 'vmnet8',
    tproxyPort: 12345,
    fwmark: '0x1',
    table: 100,
    wifiPolicy: 'whitelist'
  },
  runtime: null,              // /api/status 实况; null = 未知
  currentNode: {
    tag: '未命名节点',
    server: '',
    port: 443,
    password: '',
    sni: '',
    insecure: false,
    obfsType: '',
    obfsPassword: '',
    upMbps: 100,
    downMbps: 300
  }
};

const POLICY_LABELS = {
  whitelist: '走代理 · 白名单例外',
  always_proxy: '强制代理',
  always_direct: '强制直连'
};

// ===================================================================
// 后端 API 层：真实网关通信 + 演示模式无缝回退
// ===================================================================
let DEMO_MODE = false;        // true = 后端不可用，全部操作退回本地模拟
let DEMO_TOAST_SHOWN = false; // 「已切换演示模式」提示全局只弹一次
const API_TIMEOUT_MS = 2500;      // 常规只读请求
const API_LONG_TIMEOUT_MS = 40000; // 下发/切换类请求：需覆盖 check+重启的最坏耗时
let statusPollTimer = null;
let demoReconnectTimer = null;    // 演示模式下周期探测后端，恢复可达时自动回在线

// fetch 包装：默认 2500ms 超时；任何网络层失败 -> 进入演示模式
async function apiFetch(path, opts = {}, timeoutMs = API_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(path, { ...opts, signal: controller.signal });
    markOnline(); // 能收到 HTTP 响应（含 4xx/5xx）即视为后端可达
    return res;
  } catch (err) {
    enterDemoMode();
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function enterDemoMode() {
  if (DEMO_MODE) return;
  DEMO_MODE = true;
  stopStatusPolling();
  setBackendChip(false);
  if (!DEMO_TOAST_SHOWN) {
    DEMO_TOAST_SHOWN = true;
    showToast('后端未连接 · 已切换演示模式', 'warning');
  }
  // 演示模式不是终态：每 15s 静默探测一次，后端恢复后自动回到在线模式
  if (!demoReconnectTimer) {
    demoReconnectTimer = setInterval(probeBackendRecovery, 15000);
  }
}

async function probeBackendRecovery() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    const res = await fetch('/api/status', { signal: controller.signal });
    if (res.ok) {
      DEMO_MODE = false;
      clearInterval(demoReconnectTimer);
      demoReconnectTimer = null;
      setBackendChip(true);
      showToast('后端连接已恢复 · 已回到在线模式', 'success');
      startStatusPolling();
      await refreshRuntimeStatus();
    }
  } catch (err) {
    // 仍不可达：静默，下个周期继续探测
  } finally {
    clearTimeout(timer);
  }
}

function markOnline() {
  if (DEMO_MODE) return;
  setBackendChip(true);
  startStatusPolling();
}

// header 状态指示 chip：绿色「网关在线」/ 琥珀「演示模式」
function setBackendChip(online) {
  const chip = document.getElementById('backend-status-chip');
  const dot = document.getElementById('backend-status-dot');
  const text = document.getElementById('backend-status-text');
  if (!chip || !dot || !text) return;
  chip.className = online ? 'chip on' : 'chip off';
  dot.className = 'chip-dot';
  text.textContent = online ? '网关在线' : '演示模式';
}

// ---- 状态轮询：在线时每 5s 刷新运行态 ----
function startStatusPolling() {
  if (statusPollTimer || DEMO_MODE) return;
  statusPollTimer = setInterval(refreshRuntimeStatus, 5000);
}

function stopStatusPolling() {
  if (statusPollTimer) {
    clearInterval(statusPollTimer);
    statusPollTimer = null;
  }
}

async function refreshRuntimeStatus() {
  if (DEMO_MODE) return;
  try {
    const res = await apiFetch('/api/status');
    if (res.ok) {
      applyRuntimeStatus(await res.json().catch(() => null));
    }
  } catch (err) {
    // 网络失败：apiFetch 已进入演示模式并完成一次性提示
  }
}

// 将 /api/status 实况写入状态视图读数砖
function applyRuntimeStatus(data) {
  if (!data || DEMO_MODE) return;
  appState.runtime = {
    singboxRunning: !!data.singbox_running,
    proxyActive: !!data.proxy_active,
    version: data.version || '',
    // 容器内通常无 nmcli：SSID 感知在宿主 dispatcher 侧，此处可能恒为 null
    currentSsid: data.current_ssid || null
  };
  if (data.current_ssid) {
    appState.currentWifiSsid = data.current_ssid;
  }
  renderStatusReadouts();
  renderWhitelistTags();
}

// ---- 启动水合：GET /api/state + /api/status；任何失败均静默回退到演示初始化 ----
async function bootstrapFromBackend() {
  if (DEMO_MODE) return;
  try {
    const res = await apiFetch('/api/state');
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (mapApiStateToApp(data)) {
        fillNodeForm(appState.currentNode);
        fillNetworkForm();
        renderWhitelistTags();
        renderStatusReadouts();
      }
    }
  } catch (err) {
    // 网络失败：apiFetch 已进入演示模式，保持演示态即可（静默）
  }
  if (DEMO_MODE) return;
  await refreshRuntimeStatus();
}

// snake_case 后端 state -> camelCase appState；uninitialized / 无效数据返回 false（保留演示默认值）
function mapApiStateToApp(data) {
  if (!data || data.status === 'uninitialized' || !data.current_node) return false;

  if (Array.isArray(data.whitelist)) {
    appState.whitelist = data.whitelist;
  }

  const n = data.current_node;
  appState.currentNode = {
    tag: n.tag ?? 'hy2-out',
    server: n.server ?? '',
    port: n.port ?? 443,
    password: n.password ?? '',
    sni: n.sni ?? '',
    insecure: !!n.insecure,
    obfsType: n.obfs_type || '',
    obfsPassword: n.obfs_password || '',
    upMbps: n.up_mbps ?? 100,
    downMbps: n.down_mbps ?? 300
  };

  appState.network.rj45Dev = data.rj45_iface || appState.network.rj45Dev;
  appState.network.wifiDev = data.wifi_iface || appState.network.wifiDev;
  appState.network.vmnetDev = data.vmnet_iface || appState.network.vmnetDev;
  appState.network.tproxyPort = data.tproxy_port ?? appState.network.tproxyPort;
  appState.network.fwmark = (typeof data.fwmark === 'number')
    ? '0x' + data.fwmark.toString(16)   // API int 1 -> UI 显示 '0x1'
    : appState.network.fwmark;
  appState.network.table = data.table ?? appState.network.table;
  if (POLICY_LABELS[data.wifi_policy]) {
    appState.network.wifiPolicy = data.wifi_policy;
  }
  return true;
}

function fillNetworkForm() {
  ensureIfaceOption(document.getElementById('cfg-rj45-dev'), appState.network.rj45Dev);
  ensureIfaceOption(document.getElementById('cfg-wifi-dev'), appState.network.wifiDev);
  document.getElementById('cfg-rj45-dev').value = appState.network.rj45Dev;
  document.getElementById('cfg-wifi-dev').value = appState.network.wifiDev;
  document.getElementById('cfg-wifi-policy').value = appState.network.wifiPolicy;
  document.getElementById('cfg-tproxy-port').value = appState.network.tproxyPort;
  document.getElementById('cfg-fwmark').value = appState.network.fwmark;
  document.getElementById('cfg-table').value = appState.network.table;
}

// fwmark UI 字符串 ('0x1') -> API 整数 (1)；非 0x 前缀按十进制解析
function parseFwmarkToInt(val) {
  const s = String(val).trim();
  if (/^0x/i.test(s)) return parseInt(s, 16) || 0;
  return parseInt(s, 10) || 0;
}

// 组装 POST /api/apply 的完整 snake_case payload
function buildApplyPayload() {
  return {
    whitelist: appState.whitelist.slice(),
    current_node: {
      tag: appState.currentNode.tag,
      server: appState.currentNode.server,
      port: parseInt(appState.currentNode.port, 10) || 443,
      password: appState.currentNode.password,
      sni: appState.currentNode.sni,
      insecure: !!appState.currentNode.insecure,
      obfs_type: appState.currentNode.obfsType || '',
      obfs_password: appState.currentNode.obfsPassword || '',
      up_mbps: parseInt(appState.currentNode.upMbps, 10) || 0,
      down_mbps: parseInt(appState.currentNode.downMbps, 10) || 0
    },
    wifi_iface: appState.network.wifiDev,
    rj45_iface: appState.network.rj45Dev,
    vmnet_iface: appState.network.vmnetDev || 'vmnet8', // UI 无输入框, 保留后端状态值
    vmnet_subnet: '192.168.100.0/24',
    tproxy_port: parseInt(appState.network.tproxyPort, 10) || 12345,
    fwmark: parseFwmarkToInt(appState.network.fwmark),
    table: parseInt(appState.network.table, 10) || 100,
    wifi_policy: appState.network.wifiPolicy
  };
}

// 统一写操作同步：本地更新完成后，将完整 state 推送至后端；失败自动落入演示模式
async function syncToBackend(localMsg, msgType = 'success') {
  if (DEMO_MODE) {
    showToast(localMsg, msgType); // 演示兜底：保持原有模拟提示
    return;
  }
  try {
    const res = await apiFetch('/api/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildApplyPayload())
    }, API_LONG_TIMEOUT_MS);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const reason = err.message || (typeof err.detail === 'string' ? err.detail : '') || '字段校验未通过';
      showToast(`配置下发失败 (HTTP ${res.status}): ${reason}`, 'warning');
      return;
    }
    const data = await res.json().catch(() => ({}));
    showToast(data.message || localMsg, 'success');
    if (data.singbox_valid === false) {
      showToast('sing-box 配置校验未通过，请检查节点参数', 'warning');
    }
  } catch (err) {
    // 网络失败：apiFetch 已进入演示模式并提示；本地状态保持已更新，不回滚
  }
}

// 手动代理开关（状态页「手动干预」）
async function manualProxySwitch(action) {
  if (DEMO_MODE) {
    showToast(action === 'on'
      ? '模拟操作: TProxy 透明代理规则已手动启用 (iptables 已写入)'
      : '模拟操作: TProxy 规则已手动清空，恢复物理直连', 'info');
    return;
  }
  try {
    const res = await apiFetch('/api/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    }, API_LONG_TIMEOUT_MS);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || (data.status && data.status !== 'success')) {
      const reason = data.output
        || (typeof data.detail === 'string' ? data.detail : '')
        || data.message
        || ('HTTP ' + res.status);
      showToast(`代理切换失败: ${reason}`, 'warning');
      return;
    }
    const label = action === 'on' ? '手动代理已启用' : '已恢复物理直连';
    showToast(data.output ? `${label} | ${data.output}` : label, 'success');
    await refreshRuntimeStatus(); // 立即拉取 /api/status 刷新状态读数
  } catch (err) {
    // 网络失败：apiFetch 已进入演示模式
  }
}

// ===================================================================
// 状态视图读数
// ===================================================================
function renderStatusReadouts() {
  // sing-box
  const sbDot = document.getElementById('st-singbox-dot');
  const sbText = document.getElementById('st-singbox-text');
  const running = appState.runtime ? appState.runtime.singboxRunning : null;
  if (running !== null) {
    sbText.textContent = running ? 'RUNNING' : 'STOPPED';
    sbText.className = running ? 'tv big' : 'tv big v-bad';
    sbDot.className = running ? 'dot' : 'dot bad';
  } else {
    sbText.textContent = '未知';
    sbText.className = 'tv big v-muted';
    sbDot.className = 'dot warn';
  }

  // TProxy 规则 (在线时为 iptables 实况)
  const tp = document.getElementById('st-tproxy-text');
  if (appState.runtime) {
    tp.textContent = appState.runtime.proxyActive ? '已启用' : '未启用';
    tp.className = `tv big ${appState.runtime.proxyActive ? 'v-warn' : 'v-ok'}`;
  } else {
    tp.textContent = DEMO_MODE ? '未知 (演示模式)' : '未知';
    tp.className = 'tv big v-muted';
  }

  // 无线通道策略
  const pol = document.getElementById('st-policy-text');
  pol.textContent = POLICY_LABELS[appState.network.wifiPolicy] || appState.network.wifiPolicy;

  // Wi-Fi 通道 (读数只放 SSID/未感知, 网卡名在子行, 避免窄幅换行)
  const wf = document.getElementById('st-wifi-text');
  const wfSub = document.getElementById('st-wifi-sub');
  const ssid = appState.runtime ? appState.runtime.currentSsid : appState.currentWifiSsid;
  wf.textContent = ssid || '未感知';
  if (wfSub) wfSub.textContent = `${appState.network.wifiDev} · SSID 感知在宿主 dispatcher 侧`;
}

// ===================================================================
// 视图切换 + 砖块入场动效 (js 不可用时全量直接可见)
// ===================================================================
function animateView(viewEl) {
  if (!viewEl || viewEl.classList.contains('live')) return;
  const parts = viewEl.querySelectorAll('.tile');
  parts.forEach((el, i) => {
    el.style.transitionDelay = `${Math.min(i, 10) * 70}ms`;
  });
  requestAnimationFrame(() => requestAnimationFrame(() => viewEl.classList.add('live')));
}

function switchTab(tabId) {
  appState.activeTab = tabId;
  document.querySelectorAll('main > section.view').forEach(sec => sec.classList.remove('active'));
  const viewEl = document.getElementById('view-' + tabId);
  viewEl.classList.add('active');

  document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
  document.getElementById('nav-btn-' + tabId).classList.add('active');

  animateView(viewEl);
}

// ===================================================================
// 白名单管理
// ===================================================================
function renderWhitelistTags() {
  const container = document.getElementById('whitelist-tag-box');
  container.innerHTML = '';
  appState.whitelist.forEach((ssid, idx) => {
    const isCurrent = (ssid === appState.currentWifiSsid);
    const tag = document.createElement('div');
    tag.className = isCurrent ? 'wl-tag current' : 'wl-tag';

    // DOM API + textContent 构建，SSID 不拼入 innerHTML（消除自 XSS 面）
    const nameSpan = document.createElement('span');
    nameSpan.textContent = ssid;
    tag.appendChild(nameSpan);
    if (isCurrent) {
      const actBadge = document.createElement('span');
      actBadge.className = 'live';
      actBadge.textContent = '活跃';
      tag.appendChild(actBadge);
    }
    const removeBtn = document.createElement('button');
    removeBtn.className = 'wl-x';
    removeBtn.type = 'button';
    removeBtn.setAttribute('aria-label', `移除 ${ssid}`);
    removeBtn.textContent = '移除';
    removeBtn.onclick = () => removeWhitelistSsid(idx);
    tag.appendChild(removeBtn);
    container.appendChild(tag);
  });

  // 命中徽标: 在线时显示 TProxy 实况, 演示态显示占位
  const badge = document.getElementById('policy-match-badge');
  if (appState.runtime) {
    if (appState.runtime.proxyActive) {
      badge.textContent = '代理运行中 · 隧道出口';
      badge.className = 'badge badge-proxy';
    } else {
      badge.textContent = '直连模式 (策略/白名单判定为直连)';
      badge.className = 'badge badge-direct';
    }
  } else {
    badge.textContent = '状态待检测 (后端离线)';
    badge.className = 'badge badge-direct';
  }
}

function addWhitelistSsid() {
  const input = document.getElementById('input-add-ssid');
  const val = input.value.trim();
  if (!val) {
    showToast('请输入有效的 SSID', 'warning');
    return;
  }
  if (appState.whitelist.includes(val)) {
    showToast(`SSID [${val}] 已存在于白名单`, 'warning');
    return;
  }
  appState.whitelist.push(val);
  input.value = '';
  renderWhitelistTags();
  const localMsg = `已将 [${val}] 添加至 Wi-Fi 直连白名单`;
  if (DEMO_MODE) {
    showToast(localMsg, 'success');
    return;
  }
  syncToBackend(localMsg, 'success');
}

function removeWhitelistSsid(idx) {
  const removed = appState.whitelist.splice(idx, 1);
  renderWhitelistTags();
  const localMsg = `已从白名单移除: [${removed[0]}]`;
  if (DEMO_MODE) {
    showToast(localMsg, 'info');
    return;
  }
  syncToBackend(localMsg, 'info');
}

// ===================================================================
// v2rayN 链接 / JSON 解析
// ===================================================================
function parseHysteria2Raw(raw) {
  raw = raw.trim();
  if (!raw) throw new Error('输入不能为空');

  // 1. JSON
  if (raw.startsWith('{')) {
    try {
      const obj = JSON.parse(raw);
      const ob = obj.outbounds ? obj.outbounds.find(o => o.type === 'hysteria2') : obj;
      if (!ob) throw new Error('JSON 未包含 hysteria2 类型的 outbound 声明');
      return {
        tag: ob.tag || 'json-hy2-node',
        server: ob.server || '',
        port: ob.server_port || 443,
        password: ob.password || '',
        sni: ob.tls?.server_name || '',
        insecure: !!ob.tls?.insecure,
        obfsType: ob.obfs?.type || '',
        obfsPassword: ob.obfs?.password || '',
        upMbps: ob.up_mbps || 100,
        downMbps: ob.down_mbps || 300
      };
    } catch (e) {
      throw new Error('JSON 格式解析失败: ' + e.message);
    }
  }

  // 2. v2rayN 标准分享链接 (hy2:// / hysteria2://)
  if (raw.startsWith('hy2://') || raw.startsWith('hysteria2://')) {
    try {
      const norm = raw.replace(/^hy2:\/\//, 'hysteria2://');
      const url = new URL(norm);

      const params = url.searchParams;
      return {
        tag: url.hash ? decodeURIComponent(url.hash.substring(1)) : 'v2rayN-Node',
        server: url.hostname,
        port: url.port ? parseInt(url.port, 10) : 443,
        password: decodeURIComponent(url.username || ''),
        sni: params.get('sni') || '',
        insecure: params.get('insecure') === '1' || params.get('insecure') === 'true',
        obfsType: params.get('obfs') || '',
        obfsPassword: params.get('obfs-password') || '',
        upMbps: params.get('upmbps') ? parseInt(params.get('upmbps'), 10) : 100,
        downMbps: params.get('downmbps') ? parseInt(params.get('downmbps'), 10) : 300
      };
    } catch (e) {
      throw new Error('v2rayN URI 链接格式不符合标准: ' + e.message);
    }
  }

  throw new Error('未识别的协议格式。仅支持 hy2:// / hysteria2:// 分享链接或 sing-box JSON');
}

function parseLinkFromInput() {
  const input = document.getElementById('raw-link-input').value;
  const feedback = document.getElementById('parser-feedback');
  try {
    const parsed = parseHysteria2Raw(input);
    appState.currentNode = parsed;
    fillNodeForm(parsed);
    feedback.textContent = `解析成功: 命中节点 [${parsed.tag}] (${parsed.server}:${parsed.port})`;
    feedback.className = 'tdesc v-ok';
    showToast(`已成功识别 v2rayN 节点: ${parsed.tag}`, 'success');
  } catch (err) {
    feedback.textContent = `错误: ${err.message}`;
    feedback.className = 'tdesc v-bad';
    showToast(err.message, 'warning');
  }
}

function fillNodeForm(node) {
  document.getElementById('node-badge-tag').textContent = `#${node.tag}`;
  document.getElementById('node-server').value = node.server;
  document.getElementById('node-port').value = node.port;
  document.getElementById('node-password').value = node.password;
  document.getElementById('node-sni').value = node.sni;
  document.getElementById('node-insecure').value = node.insecure ? "true" : "false";
  document.getElementById('node-obfs-type').value = node.obfsType;
  document.getElementById('node-obfs-pass').value = node.obfsPassword;
  document.getElementById('node-up').value = node.upMbps;
  document.getElementById('node-down').value = node.downMbps;
}

function updateLivePreview() {
  appState.currentNode.server = document.getElementById('node-server').value;
  appState.currentNode.port = parseInt(document.getElementById('node-port').value, 10) || 443;
  appState.currentNode.password = document.getElementById('node-password').value;
  appState.currentNode.sni = document.getElementById('node-sni').value;
  appState.currentNode.insecure = document.getElementById('node-insecure').value === "true";
  appState.currentNode.obfsType = document.getElementById('node-obfs-type').value;
  appState.currentNode.obfsPassword = document.getElementById('node-obfs-pass').value;
  appState.currentNode.upMbps = parseInt(document.getElementById('node-up').value, 10) || 100;
  appState.currentNode.downMbps = parseInt(document.getElementById('node-down').value, 10) || 300;
}

// 样例为无口令演示形态; 真实分享链接由使用者粘贴, 凭据不经过源码
function loadSampleLink(type) {
  let sample = "";
  if (type === 1) {
    sample = "hy2://demo-token@us-silicon.edge-tunnel.org:443?sni=gateway.apple.com&insecure=0&upmbps=120&downmbps=500#US_West_HighSpeed";
  } else if (type === 2) {
    sample = "hysteria2://demo@hk-relay.quantum-node.net:8443?sni=hk.cloudflare.com&insecure=1&obfs=salamander&upmbps=80&downmbps=300#HK_Gaming_Obfs";
  } else {
    sample = JSON.stringify({
      "type": "hysteria2",
      "tag": "Tokyo_Direct_JSON",
      "server": "jp-hnd.edge-cloud.io",
      "server_port": 10443,
      "up_mbps": 150,
      "down_mbps": 600,
      "tls": {
        "enabled": true,
        "server_name": "jp.microsoft.com",
        "insecure": false
      }
    }, null, 2);
  }
  document.getElementById('raw-link-input').value = sample;
  parseLinkFromInput();
}

function saveAndDeployNode() {
  updateLivePreview(); // 先从表单同步最新节点参数至 appState
  const localMsg = '节点参数已写入 /data/singbox.json 并触发 sing-box 内核重载';
  if (DEMO_MODE) {
    showToast(localMsg, 'success');
    return;
  }
  syncToBackend(localMsg, 'success');
}

function saveNetworkCardSettings() {
  appState.network.rj45Dev = document.getElementById('cfg-rj45-dev').value;
  appState.network.wifiDev = document.getElementById('cfg-wifi-dev').value;
  appState.network.wifiPolicy = document.getElementById('cfg-wifi-policy').value;
  appState.network.tproxyPort = parseInt(document.getElementById('cfg-tproxy-port').value, 10);
  appState.network.fwmark = document.getElementById('cfg-fwmark').value.trim() || '0x1';
  appState.network.table = parseInt(document.getElementById('cfg-table').value, 10);
  renderStatusReadouts();
  const localMsg = '网卡配置已更新并下发';
  if (DEMO_MODE) {
    showToast(localMsg, 'success');
    return;
  }
  syncToBackend(localMsg, 'success');
}

// ===================================================================
// 网卡下拉选择: 后端枚举宿主真实接口, 演示模式回落常见名称
// ===================================================================
const IFACE_KIND_LABELS = {
  ethernet: '以太网', wifi: '无线', vmware: 'VMware', bridge: '虚拟网桥 (docker/libvirt)',
  tunnel: '隧道', loopback: '回环', other: '其他'
};
const IFACE_DEMO_LIST = [
  { name: 'enp3s0', kind: 'ethernet' }, { name: 'enp55s0', kind: 'ethernet' }, { name: 'eno1', kind: 'ethernet' },
  { name: 'wlp2s0', kind: 'wifi' }, { name: 'wlo1', kind: 'wifi' }, { name: 'wlan0', kind: 'wifi' },
  { name: 'vmnet1', kind: 'vmware' }, { name: 'vmnet8', kind: 'vmware' },
  { name: 'br0', kind: 'bridge' }, { name: 'virbr0', kind: 'bridge' },
  { name: 'tun0', kind: 'tunnel' }, { name: 'lo', kind: 'loopback' }
];

// 各网卡字段允许的接口类型 (下拉只列各自该选的, 不混入无关接口)
const IFACE_FIELD_KINDS = {
  'cfg-rj45-dev': ['ethernet'],   // 通道A · 有线: 物理以太网卡
  'cfg-wifi-dev': ['wifi']        // 通道B · 无线: 无线网卡
};

// select 中保证存在指定值的选项 (后端列表未含当前值时补一项, 不丢配置)
function ensureIfaceOption(sel, value) {
  if (!sel || !value) return;
  if (![...sel.options].some(o => o.value === value)) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = `${value} (当前配置)`;
    sel.insertBefore(opt, sel.firstChild);
  }
}

function populateInterfaceSelects(interfaces) {
  Object.entries(IFACE_FIELD_KINDS).forEach(([fieldId, kinds]) => {
    const sel = document.getElementById(fieldId);
    if (!sel) return;
    const pool = interfaces.filter(i => kinds.includes(i.kind));
    const usePool = pool.length ? pool : interfaces; // 无匹配类型时回落全列表

    const groups = {};
    usePool.forEach(i => {
      (groups[i.kind] = groups[i.kind] || []).push(i.name);
    });

    const current = sel.value;
    sel.innerHTML = '';
    Object.keys(IFACE_KIND_LABELS).forEach(kind => {
      const names = groups[kind];
      if (!names || !names.length) return;
      const og = document.createElement('optgroup');
      og.label = IFACE_KIND_LABELS[kind];
      names.forEach(n => {
        const opt = document.createElement('option');
        opt.value = n;
        opt.textContent = n;
        og.appendChild(opt);
      });
      sel.appendChild(og);
    });
    if (current) {
      ensureIfaceOption(sel, current);
      sel.value = current;
    }
  });
}

async function refreshInterfaces() {
  if (DEMO_MODE) {
    populateInterfaceSelects(IFACE_DEMO_LIST);
    showToast('演示模式: 已载入常见网卡名称列表', 'info');
    return;
  }
  try {
    const res = await apiFetch('/api/interfaces');
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.interfaces) && data.interfaces.length) {
        populateInterfaceSelects(data.interfaces);
        return;
      }
    }
    populateInterfaceSelects(IFACE_DEMO_LIST);
    showToast('后端网卡列表为空, 已回落常见名称', 'warning');
  } catch (err) {
    populateInterfaceSelects(IFACE_DEMO_LIST); // 进演示模式前的最后兜底
  }
}

// ===================================================================
// 网络连通性测试: 宿主机视角分段诊断 (DNS/直连 TCP/节点解析/节点 UDP)
// ===================================================================
async function runNetTest() {
  const panel = document.getElementById('nettest-panel');
  const target = (document.getElementById('nettest-target').value || 'www.google.com').trim();
  if (DEMO_MODE) {
    showToast(`演示模式: 真实连通性测试需后端在线 (将测试 ${target} 的 DNS/直连与节点可达性)`, 'warning');
    return;
  }
  panel.hidden = false;
  panel.innerHTML = '';
  const loading = document.createElement('p');
  loading.className = 'tdesc';
  loading.textContent = `正在从宿主机分段探测 ${target} ...`;
  panel.appendChild(loading);
  try {
    const res = await apiFetch('/api/nettest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    }, 15000);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.status !== 'success') {
      const reason = (typeof data.detail === 'string' ? data.detail : '') || ('HTTP ' + res.status);
      loading.textContent = `测试失败: ${reason}`;
      loading.className = 'tdesc v-bad';
      return;
    }
    renderNetTest(data);
  } catch (err) {
    loading.textContent = '测试失败: 后端不可达';
    loading.className = 'tdesc v-bad';
  }
}

function renderNetTest(data) {
  const panel = document.getElementById('nettest-panel');
  panel.hidden = false;
  panel.innerHTML = '';

  const sumText = { up: '链路正常', degraded: '链路部分可用', down: '直连不可用' }[data.overall] || data.overall;
  const sum = document.createElement('p');
  sum.className = `nettest-sum ${data.overall}`;
  sum.textContent = `${sumText} · 目标 ${data.target}`;
  panel.appendChild(sum);

  data.results.forEach(r => {
    const row = document.createElement('div');
    row.className = 'nettest-row';
    const dot = document.createElement('span');
    dot.className = r.ok === true ? 'dot' : (r.ok === false ? 'dot bad' : 'dot warn');
    const label = document.createElement('span');
    label.textContent = r.label;
    const detail = document.createElement('span');
    detail.className = 'n-detail';
    detail.textContent = r.detail || '';
    const ms = document.createElement('span');
    ms.className = 'n-ms';
    ms.textContent = r.ms != null ? `${r.ms} ms` : '';
    row.append(dot, label, detail, ms);
    panel.appendChild(row);
  });
}

function togglePass(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "隐藏";
  } else {
    input.type = "password";
    btn.textContent = "显示";
  }
}

// ===================================================================
// Toast 通知
// ===================================================================
function showToast(message, type = 'info') {
  const hub = document.getElementById('toast-hub');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.setAttribute('role', 'status');

  const dot = document.createElement('span');
  dot.className = 't-dot';
  const msg = document.createElement('span');
  msg.textContent = message;
  toast.append(dot, msg);
  hub.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ===================================================================
// 启动
// ===================================================================
window.addEventListener('load', async function () {
  // 0) 页头与页脚入场 (与砖块同一套 stagger 机制)
  document.querySelectorAll('.appbar-row > *, .foot > span').forEach((el, i) => {
    el.style.transitionDelay = `${i * 60}ms`;
  });
  requestAnimationFrame(() => requestAnimationFrame(() => document.body.classList.add('live')));

  // 1) 演示态初始化 (后端不可用时的完整兜底)
  fillNodeForm(appState.currentNode);
  renderWhitelistTags();
  renderStatusReadouts();
  populateInterfaceSelects(IFACE_DEMO_LIST); // 先给演示列表, 后端在线时立即被真实列表替换

  // 2) 状态视图入场 (默认落地页)
  animateView(document.getElementById('view-status'));

  // 3) 尝试接入真实后端; 失败静默保持演示态
  await bootstrapFromBackend();
  refreshInterfaces(); // 非阻塞: 后端在线则载入宿主真实网卡
});
