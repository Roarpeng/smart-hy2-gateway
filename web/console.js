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
  activeTab: 'node',
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
    upMbps: null,              // null = 不指定 -> BBR (v2rayN 语义)
    downMbps: null,
    portHopping: ''            // v2rayN mport/ports -> 端口跳跃
  },
  nodes: [],                  // /api/nodes 节点快照 (snake_case 原样保存)
  activeNodeId: '',           // 活跃节点 id
  nodeLatency: {},            // id -> { status: idle|testing|ok|fail, latency_ms, error }
  editingNodeId: null,        // 正在编辑的节点 id
  nodeSearch: ''              // 节点列表前端搜索关键词
};

const POLICY_LABELS = {
  whitelist: '走代理 · 白名单例外',
  always_proxy: '强制代理',
  always_direct: '强制直连'
};

const TAB_TITLES = {
  node: '节点管理',
  nics: '双通道',
  status: '运行状态'
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
      await fetchNodes();
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
  updateRouteStage();
}

// ---- 启动水合：GET /api/state + /api/status；任何失败均静默回退到演示初始化 ----
async function bootstrapFromBackend() {
  if (DEMO_MODE) {
    await fetchNodes();
    return;
  }
  let stateData = null;
  try {
    const res = await apiFetch('/api/state');
    if (res.ok) {
      stateData = await res.json().catch(() => null);
      if (mapApiStateToApp(stateData)) {
        fillNodeForm(appState.currentNode);
        fillNetworkForm();
        renderWhitelistTags();
        renderStatusReadouts();
      }
    }
  } catch (err) {
    // 网络失败：apiFetch 已进入演示模式，保持演示态即可（静默）
  }
  await fetchNodes(stateData); // /api/nodes 不可用时用 state 里的节点兜底
  if (DEMO_MODE) return;
  await refreshRuntimeStatus();
}

// snake_case 后端 state -> camelCase appState；uninitialized / 无数据返回 false（保留演示默认值）
function mapApiStateToApp(data) {
  if (!data || data.status === 'uninitialized') return false;

  if (Array.isArray(data.whitelist)) {
    appState.whitelist = data.whitelist;
  }

  if (typeof data.active_node_id === 'string') {
    appState.activeNodeId = data.active_node_id;
  }

  const n = data.current_node;
  if (n) {
    appState.currentNode = nodeToAppNode(n);
  }

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
  updateShellFacts();
}

// 侧栏/首屏的非节点事实: TProxy 端口、无线策略
function updateShellFacts() {
  const port = document.getElementById('route-port');
  if (port) port.textContent = ':' + (appState.network.tproxyPort || 12345);
  const policy = document.getElementById('stage-policy');
  if (policy) policy.textContent = POLICY_LABELS[appState.network.wifiPolicy] || appState.network.wifiPolicy;
}

// fwmark UI 字符串 ('0x1') -> API 整数 (1)；非 0x 前缀按十进制解析
function parseFwmarkToInt(val) {
  const s = String(val).trim();
  if (/^0x/i.test(s)) return parseInt(s, 16) || 0;
  return parseInt(s, 10) || 0;
}

// 组装 POST /api/apply 的完整 snake_case payload
function buildApplyPayload() {
  const num = (v) => Number.isFinite(parseInt(v, 10)) ? parseInt(v, 10) : null;
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
      up_mbps: num(appState.currentNode.upMbps),        // null = BBR
      down_mbps: num(appState.currentNode.downMbps),
      port_hopping: appState.currentNode.portHopping || ''
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
      const reason = extractApiError(err) || '字段校验未通过';
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
      const reason = data.output || extractApiError(data) || ('HTTP ' + res.status);
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
  updateRouteStage();
}

// ===================================================================
// 视图切换 + 砖块入场动效 (js 不可用时全量直接可见)
// ===================================================================
function animateView(viewEl) {
  if (!viewEl || viewEl.classList.contains('live')) return;
  const parts = viewEl.querySelectorAll('.tile, .stage');
  parts.forEach((el, i) => {
    el.style.transitionDelay = `${Math.min(i, 10) * 70}ms`;
  });
  requestAnimationFrame(() => requestAnimationFrame(() => viewEl.classList.add('live')));
}

function switchTab(tabId) {
  if (!TAB_TITLES[tabId]) tabId = 'node';
  appState.activeTab = tabId;
  document.querySelectorAll('main > section.view').forEach(sec => sec.classList.remove('active'));
  const viewEl = document.getElementById('view-' + tabId);
  viewEl.classList.add('active');

  document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
  document.getElementById('nav-btn-' + tabId).classList.add('active');

  const title = TAB_TITLES[tabId] || '控制台';
  const pageTitle = document.getElementById('page-title');
  if (pageTitle) pageTitle.textContent = title;
  document.title = `${title} · Smart Hy2 Gateway`;
  if (location.hash !== '#' + tabId) {
    history.replaceState(null, '', '#' + tabId);
  }

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

function fillNodeForm(node) {
  const n = node || {};
  const pick = (camel, snake, fallback) => (n[camel] !== undefined ? n[camel] : (n[snake] !== undefined ? n[snake] : fallback));
  const tag = n.tag ?? '未命名节点';
  document.getElementById('node-badge-tag').textContent = `#${tag}`;
  document.getElementById('node-tag').value = tag;
  document.getElementById('node-server').value = n.server ?? '';
  document.getElementById('node-port').value = n.port ?? 443;
  document.getElementById('node-password').value = n.password ?? '';
  document.getElementById('node-sni').value = n.sni ?? '';
  document.getElementById('node-insecure').value = (n.insecure ? "true" : "false");
  document.getElementById('node-obfs-type').value = pick('obfsType', 'obfs_type', '');
  document.getElementById('node-obfs-pass').value = pick('obfsPassword', 'obfs_password', '');
  document.getElementById('node-port-hopping').value = pick('portHopping', 'port_hopping', '');
  document.getElementById('node-up').value = pick('upMbps', 'up_mbps', null) ?? '';
  document.getElementById('node-down').value = pick('downMbps', 'down_mbps', null) ?? '';
}

function updateLivePreview() {
  const tagEl = document.getElementById('node-tag');
  if (!tagEl) return;
  const draft = {
    tag: tagEl.value.trim() || '未命名节点',
    server: document.getElementById('node-server').value.trim(),
    port: parseInt(document.getElementById('node-port').value, 10) || 443,
    password: document.getElementById('node-password').value,
    sni: document.getElementById('node-sni').value.trim(),
    insecure: document.getElementById('node-insecure').value === "true",
    obfsType: document.getElementById('node-obfs-type').value.trim(),
    obfsPassword: document.getElementById('node-obfs-pass').value,
    portHopping: document.getElementById('node-port-hopping').value.trim(),
    upMbps: null,
    downMbps: null
  };
  const upV = parseInt(document.getElementById('node-up').value, 10);
  const downV = parseInt(document.getElementById('node-down').value, 10);
  draft.upMbps = Number.isFinite(upV) ? upV : null;   // 空 = BBR
  draft.downMbps = Number.isFinite(downV) ? downV : null;

  document.getElementById('node-badge-tag').textContent = `#${draft.tag}`;
  // 编辑表单只是草稿: appState.currentNode 始终由活跃节点快照同步,
  // 避免未保存的草稿被网卡/白名单保存 (POST /api/apply) 一并下发。
}

// 样例为无口令演示形态; 真实分享链接由使用者粘贴, 凭据不经过源码
function loadSampleLink() {
  const sample = "hy2://demo-token@us-silicon.edge-tunnel.org:443?sni=gateway.apple.com&insecure=0&upmbps=120&downmbps=500#US_West_HighSpeed";
  document.getElementById('raw-link-input').value = sample;
  const feedback = document.getElementById('parser-feedback');
  if (feedback) {
    feedback.textContent = '已填入演示链接，点击「解析导入」体验完整流程';
    feedback.className = 'tdesc v-muted';
  }
  showToast('已填入演示节点链接', 'info');
}

// ===================================================================
// 节点链接管理: 导入 / 列表 / 启用 / 测试 / 编辑 / 删除
// 所有节点数据渲染均用 DOM API + textContent, 不拼接用户输入到 innerHTML
// ===================================================================

// 统一解析 API 错误: detail 字符串 / FastAPI 校验数组 / message
function extractApiError(data) {
  if (!data) return '未知错误';
  const detail = data.detail;
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map(item => {
      if (!item) return '';
      if (typeof item === 'string') return item;
      const loc = Array.isArray(item.loc)
        ? item.loc.filter(x => x !== 'body' && x !== 'query' && x !== 'path').join('.')
        : '';
      const msg = item.msg || item.error || item.message || '参数无效';
      return loc ? `${loc}: ${msg}` : msg;
    }).filter(Boolean);
    if (parts.length) return parts.join('; ');
  }
  if (detail && typeof detail === 'object') {
    return detail.message || detail.error || JSON.stringify(detail);
  }
  if (typeof data.error === 'string' && data.error) return data.error;
  if (typeof data.message === 'string' && data.message) return data.message;
  return '未知错误';
}

// snake_case API 节点 -> camelCase 表单节点
function nodeToAppNode(n) {
  if (!n) return { ...appState.currentNode };
  return {
    tag: n.tag ?? '未命名节点',
    server: n.server ?? '',
    port: n.port ?? 443,
    password: n.password ?? '',
    sni: n.sni ?? '',
    insecure: !!n.insecure,
    obfsType: n.obfs_type || '',
    obfsPassword: n.obfs_password || '',
    upMbps: n.up_mbps ?? null,
    downMbps: n.down_mbps ?? null,
    portHopping: n.port_hopping || ''
  };
}

// 节点字段兜底: 后端字段缺失时也能稳定渲染
function normalizeNode(n, index) {
  const raw = n || {};
  return {
    id: raw.id || `legacy-${index ?? 0}`,
    tag: raw.tag || '未命名节点',
    server: raw.server || '',
    port: Number.isFinite(parseInt(raw.port, 10)) ? parseInt(raw.port, 10) : 443,
    password: raw.password || '',
    sni: raw.sni || '',
    insecure: !!raw.insecure,
    obfs_type: raw.obfs_type || '',
    obfs_password: raw.obfs_password || '',
    up_mbps: raw.up_mbps ?? null,
    down_mbps: raw.down_mbps ?? null,
    port_hopping: raw.port_hopping || '',
    source: raw.source || '',
    created_at: raw.created_at || 0,
    latency_ms: (typeof raw.latency_ms === 'number') ? raw.latency_ms : null,
    latency_ok: (raw.latency_ok === true || raw.latency_ok === false) ? raw.latency_ok : null,
    latency_error: raw.latency_error || '',
    tested_at: raw.tested_at || 0,
    __demo: !!raw.__demo
  };
}

// 从节点快照重建延迟表; 正在测试的条目保留「测试中」状态
function syncLatencyFromNodes() {
  const prev = appState.nodeLatency || {};
  const next = {};
  appState.nodes.forEach(n => {
    const p = prev[n.id];
    if (p && p.status === 'testing') {
      next[n.id] = p;
    } else if (n.latency_ok === true) {
      next[n.id] = { status: 'ok', latency_ms: n.latency_ms, error: '' };
    } else if (n.latency_ok === false) {
      next[n.id] = { status: 'fail', latency_ms: n.latency_ms, error: n.latency_error || '' };
    } else {
      next[n.id] = { status: 'idle', latency_ms: null, error: '' };
    }
  });
  appState.nodeLatency = next;
}

// 活跃节点变化后同步 current_node, 保证网卡/白名单保存仍携带正确节点
function syncCurrentNodeFromActive() {
  const active = appState.nodes.find(n => n.id === appState.activeNodeId);
  if (active) {
    appState.currentNode = nodeToAppNode(active);
  }
  if (!appState.editingNodeId && active) {
    fillNodeForm(appState.currentNode);
  }
}

// 旧版后端兜底: 用 /api/state 的 nodes / current_node 构造列表
function applyLegacyStateNodes(stateData) {
  if (!stateData) {
    appState.nodes = [];
    appState.activeNodeId = '';
    appState.nodeLatency = {};
    renderNodeList();
    return;
  }
  const rawList = (Array.isArray(stateData.nodes) && stateData.nodes.length)
    ? stateData.nodes
    : (stateData.current_node ? [stateData.current_node] : []);
  appState.nodes = rawList.map((n, i) => normalizeNode(n, i));
  let activeId = typeof stateData.active_node_id === 'string' ? stateData.active_node_id : '';
  if (!activeId && stateData.current_node && appState.nodes.length) {
    const cur = stateData.current_node;
    const match = appState.nodes.find(n => n.tag === cur.tag && n.server === cur.server);
    activeId = match ? match.id : (appState.nodes.length === 1 ? appState.nodes[0].id : '');
  }
  appState.activeNodeId = activeId;
  syncLatencyFromNodes();
  syncCurrentNodeFromActive();
  renderNodeList();
}

function setDemoNodes() {
  const c = appState.currentNode || {};
  const demo = normalizeNode({
    id: 'demo-node',
    tag: (c.tag && c.tag !== '未命名节点') ? c.tag : '演示节点',
    server: c.server || 'demo.invalid',
    port: c.port || 443,
    password: '',
    sni: c.sni || '',
    insecure: !!c.insecure,
    obfs_type: c.obfsType || '',
    obfs_password: c.obfsPassword || '',
    up_mbps: c.upMbps ?? null,
    down_mbps: c.downMbps ?? null,
    port_hopping: c.portHopping || '',
    latency_ms: null,
    latency_ok: null,
    latency_error: '',
    __demo: true
  }, 0);
  appState.nodes = [demo];
  appState.activeNodeId = '';
  appState.nodeLatency = {};
  renderNodeList();
}

// GET /api/nodes; 404/旧版后端时回落到 /api/state 快照
async function fetchNodes(fallbackState) {
  if (DEMO_MODE) {
    setDemoNodes();
    return;
  }
  try {
    const res = await apiFetch('/api/nodes');
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.nodes)) {
        appState.nodes = data.nodes.map((n, i) => normalizeNode(n, i));
        appState.activeNodeId = typeof data.active_node_id === 'string' ? data.active_node_id : '';
        syncLatencyFromNodes();
        syncCurrentNodeFromActive();
        renderNodeList();
        return;
      }
    }
    applyLegacyStateNodes(fallbackState);
  } catch (err) {
    // 网络失败: apiFetch 已切演示模式, 下方展示演示节点
    setDemoNodes();
  }
}

// 节点列表头部搜索 (纯前端过滤 tag / server)
function onNodeSearchInput(value) {
  appState.nodeSearch = String(value || '').trim();
  renderNodeList();
}

function makeNodeButton(label, className, handler, disabled) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = className;
  btn.textContent = label;
  if (disabled) btn.disabled = true;
  btn.onclick = async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    try {
      await handler();
    } catch (err) {
      showToast(err && err.message ? err.message : '操作失败', 'warning');
    } finally {
      if (btn.isConnected) btn.disabled = false;
    }
  };
  return btn;
}

function buildNodeLatency(n) {
  const state = appState.nodeLatency[n.id] || { status: 'idle' };
  const el = document.createElement('div');
  el.className = 'node-latency';
  if (state.status === 'testing') {
    el.textContent = '测试中…';
    el.classList.add('node-lat-testing');
  } else if (state.status === 'ok') {
    const ms = state.latency_ms;
    if (typeof ms === 'number') {
      el.textContent = `${Math.round(ms)} ms`;
      el.title = `延迟 ${Math.round(ms)} ms`;
      el.classList.add(ms < 200 ? 'node-lat-ok' : (ms < 500 ? 'node-lat-warn' : 'node-lat-bad'));
    } else {
      el.textContent = '成功';
      el.classList.add('node-lat-ok');
    }
  } else if (state.status === 'fail') {
    el.textContent = '失败';
    el.classList.add('node-lat-bad');
    if (state.error) el.title = state.error;
  } else {
    el.textContent = '未测试';
    el.classList.add('node-lat-idle');
  }
  return el;
}

function buildNodeRow(n) {
  const isActive = n.id === appState.activeNodeId;
  const latState = appState.nodeLatency[n.id] || { status: 'idle' };

  const row = document.createElement('div');
  row.className = 'node-row' + (isActive ? ' active' : '');

  const main = document.createElement('div');
  main.className = 'node-main';

  const head = document.createElement('div');
  head.className = 'node-head';
  if (isActive) {
    const activeBadge = document.createElement('span');
    activeBadge.className = 'node-active-badge';
    activeBadge.textContent = '活跃';
    head.appendChild(activeBadge);
  }
  if (n.__demo) {
    const demoBadge = document.createElement('span');
    demoBadge.className = 'node-demo-badge';
    demoBadge.textContent = '演示';
    head.appendChild(demoBadge);
  }
  const tag = document.createElement('span');
  tag.className = 'node-tag';
  tag.textContent = n.tag;
  head.appendChild(tag);
  main.appendChild(head);

  const meta = document.createElement('div');
  meta.className = 'node-meta';
  const addr = document.createElement('span');
  addr.className = 'node-addr';
  addr.textContent = `出口 IP ${n.server || '未填写'} · 端口 ${n.port}`;
  const sni = document.createElement('span');
  sni.className = 'node-sni';
  sni.textContent = `SNI ${n.sni || '未填写'}`;
  meta.append(addr, sni);
  main.appendChild(meta);

  const flags = document.createElement('div');
  flags.className = 'node-flags';
  const proto = document.createElement('span');
  proto.className = 'node-flag';
  proto.textContent = 'Hysteria 2 · QUIC';
  flags.appendChild(proto);
  if (n.insecure) {
    const f = document.createElement('span');
    f.className = 'node-flag';
    f.textContent = 'insecure';
    flags.appendChild(f);
  }
  if (n.obfs_type) {
    const f = document.createElement('span');
    f.className = 'node-flag';
    f.textContent = `obfs=${n.obfs_type}`;
    flags.appendChild(f);
  }
  if (n.port_hopping) {
    const f = document.createElement('span');
    f.className = 'node-flag';
    f.textContent = `端口跳跃 ${n.port_hopping}`;
    flags.appendChild(f);
  }
  if (flags.childNodes.length) main.appendChild(flags);

  const latency = buildNodeLatency(n);

  const actions = document.createElement('div');
  actions.className = 'node-actions';
  const activateBtn = makeNodeButton('启用', 'btn btn-small btn-primary', () => activateNode(n.id), isActive);
  if (isActive) activateBtn.title = '当前活跃节点';
  const testBtn = makeNodeButton('测试', 'btn btn-small', () => testNode(n.id), latState.status === 'testing');
  const editBtn = makeNodeButton('编辑', 'btn btn-small', () => openNodeEditor(n.id));
  const delBtn = makeNodeButton('删除', 'btn btn-small btn-danger', () => deleteNode(n.id));
  actions.append(activateBtn, testBtn, editBtn, delBtn);

  row.append(main, latency, actions);
  return row;
}

function renderNodeList() {
  const container = document.getElementById('node-list');
  const countEl = document.getElementById('node-count');
  if (!container) return;
  updateRouteStage();

  const total = appState.nodes.length;
  const q = (appState.nodeSearch || '').toLowerCase();
  const filtered = q
    ? appState.nodes.filter(n => (n.tag || '').toLowerCase().includes(q) || (n.server || '').toLowerCase().includes(q))
    : appState.nodes;

  if (countEl) {
    countEl.textContent = q ? `${filtered.length} / ${total} 个节点` : `${total} 个节点`;
  }

  container.innerHTML = '';
  if (!total) {
    const empty = document.createElement('p');
    empty.className = 'node-empty';
    empty.textContent = '暂无节点，请在上方导入 v2rayN 分享链接或订阅';
    container.appendChild(empty);
    return;
  }
  if (!filtered.length) {
    const empty = document.createElement('p');
    empty.className = 'node-empty';
    empty.textContent = `未找到匹配「${appState.nodeSearch}」的节点`;
    container.appendChild(empty);
    return;
  }
  filtered.forEach(n => container.appendChild(buildNodeRow(n)));
}

// 首屏活动出口: 标题 / 地址 / 延迟 / 路径标签全部来自真实状态
function updateRouteStage() {
  const n = appState.nodes.find(item => item.id === appState.activeNodeId) || null;
  const proxy = appState.runtime ? appState.runtime.proxyActive : null;

  const title = document.getElementById('route-title');
  if (title) {
    title.textContent = !n ? '等待出口' : (proxy === false ? '直连中' : (proxy === true ? '出口正常' : '出口就绪'));
  }

  const sub = document.getElementById('route-sub');
  if (sub) {
    sub.textContent = n
      ? `${n.tag} · SNI ${n.sni || '未设置'}`
      : '在下方导入第一条 v2rayN 链接，或粘贴订阅地址。';
  }

  const ipEl = document.getElementById('route-ip');
  if (ipEl) ipEl.textContent = n ? (n.server || '未填写') : '未配置';

  const portEl = document.getElementById('route-port-out');
  if (portEl) portEl.textContent = n ? String(n.port || 443) : '未配置';

  const tag = document.getElementById('route-node-tag');
  if (tag) tag.textContent = n ? n.tag : '未配置';

  const shellRoute = document.getElementById('shell-route');
  if (shellRoute) shellRoute.textContent = n ? n.tag : '未配置';

  const topbarRoute = document.getElementById('topbar-route');
  if (topbarRoute) {
    topbarRoute.textContent = n
      ? `出口 IP ${n.server || '未填写'} · ${n.port || 443} · QUIC`
      : '尚未配置出口节点';
  }

  const latEl = document.getElementById('route-latency');
  const latState = n ? (appState.nodeLatency[n.id] || { status: 'idle' }) : null;
  if (latEl) {
    let text = '未测试';
    let cls = '';
    if (!n) {
      text = '未测试';
    } else if (!latState || latState.status === 'idle') {
      text = '未测试';
    } else if (latState.status === 'testing') {
      text = '测试中…';
      cls = 'is-warn';
    } else if (latState.status === 'ok') {
      const ms = typeof latState.latency_ms === 'number' ? latState.latency_ms : null;
      text = ms !== null ? `${Math.round(ms)} ms` : '成功';
      cls = ms === null ? 'is-ok' : (ms < 200 ? 'is-ok' : (ms < 500 ? 'is-warn' : 'is-bad'));
    } else {
      text = '失败';
      cls = 'is-bad';
    }
    latEl.textContent = text;
    latEl.className = cls;
    latEl.title = latState && latState.error ? latState.error : '';
  }

  const stateEl = document.getElementById('route-state');
  if (stateEl) {
    stateEl.textContent = !n ? '未配置' : (proxy === null ? '检测中' : (proxy ? '代理已接管' : '直连'));
    stateEl.className = !n ? 'is-off' : (proxy ? 'is-on' : 'is-off');
  }

  const stateDot = document.getElementById('route-state-dot');
  if (stateDot) {
    stateDot.className = (!n || proxy === false || proxy === null) ? 'dot warn' : 'dot';
  }

  const testBtn = document.getElementById('route-test-btn');
  if (testBtn) {
    const testing = latState && latState.status === 'testing';
    testBtn.disabled = !n || testing || DEMO_MODE;
    testBtn.textContent = testing ? '测试中…' : '测试延迟';
  }
}

async function testActiveNode() {
  const n = appState.nodes.find(item => item.id === appState.activeNodeId);
  if (!n) {
    showToast('请先导入并启用一个节点', 'warning');
    return;
  }
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法测试节点', 'warning');
    return;
  }
  await testNode(n.id);
  updateRouteStage();
}

function jumpToNodeList() {
  const target = document.getElementById('node-list-section');
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function jumpToChannels() {
  const target = document.querySelector('.channel-direct');
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// POST /api/nodes/{id}/activate
async function activateNode(id) {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法启用节点', 'warning');
    return false;
  }
  if (!id) return false;
  try {
    const res = await apiFetch(`/api/nodes/${encodeURIComponent(id)}/activate`, {
      method: 'POST'
    }, API_LONG_TIMEOUT_MS);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || (data.status && data.status !== 'success')) {
      showToast(`启用失败: ${extractApiError(data)}`, 'warning');
      await fetchNodes();
      return false;
    }
    showToast(data.message || '节点已启用', 'success');
    await fetchNodes();
    return true;
  } catch (err) {
    return false; // apiFetch 已进入演示模式并提示
  }
}

// POST /api/nodes/test (单节点 / 全部)
async function requestNodeTest(ids) {
  const res = await apiFetch('/api/nodes/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids: ids || [] })
  }, API_LONG_TIMEOUT_MS);
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.status !== 'success' || !Array.isArray(data.results)) {
    throw new Error(extractApiError(data));
  }
  return data.results;
}

function applyTestResults(results) {
  (results || []).forEach(r => {
    if (!r || !r.id) return;
    if (r.ok === true) {
      appState.nodeLatency[r.id] = {
        status: 'ok',
        latency_ms: (typeof r.latency_ms === 'number') ? r.latency_ms : null,
        error: ''
      };
    } else {
      appState.nodeLatency[r.id] = {
        status: 'fail',
        latency_ms: null,
        error: r.error || '测试失败'
      };
    }
  });
}

async function testNode(id) {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法测试节点', 'warning');
    return;
  }
  if (!id) return;
  appState.nodeLatency[id] = { status: 'testing', latency_ms: null, error: '' };
  renderNodeList();
  try {
    const results = await requestNodeTest([id]);
    await fetchNodes();
    applyTestResults(results);
  } catch (err) {
    if (!DEMO_MODE) {
      await fetchNodes();
      appState.nodeLatency[id] = { status: 'fail', latency_ms: null, error: err.message || '测试失败' };
      showToast(`测试失败: ${err.message || '后端不可达'}`, 'warning');
    }
  } finally {
    renderNodeList();
  }
}

async function testAllNodes(btn) {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法测试节点', 'warning');
    return;
  }
  if (!appState.nodes.length) {
    showToast('暂无可测试的节点', 'warning');
    return;
  }
  if (btn) btn.disabled = true;
  appState.nodes.forEach(n => {
    appState.nodeLatency[n.id] = { status: 'testing', latency_ms: null, error: '' };
  });
  renderNodeList();
  try {
    const results = await requestNodeTest([]);
    await fetchNodes();
    applyTestResults(results);
    const okCount = results.filter(r => r.ok === true).length;
    const failCount = results.length - okCount;
    showToast(`测试完成: 成功 ${okCount} · 失败 ${failCount}`, failCount ? 'warning' : 'success');
  } catch (err) {
    if (!DEMO_MODE) {
      await fetchNodes();
      appState.nodes.forEach(n => {
        appState.nodeLatency[n.id] = { status: 'fail', latency_ms: null, error: err.message || '测试失败' };
      });
      showToast(`全部测试失败: ${err.message || '后端不可达'}`, 'warning');
    }
  } finally {
    renderNodeList();
    if (btn) btn.disabled = false;
  }
}

// ---------------- 导入 ----------------
function maskSensitive(text) {
  if (text === null || text === undefined) return '';
  let s = String(text);
  s = s.replace(/([a-z][a-z0-9+.-]*:\/\/)([^@\s/]+)@/gi, '$1***@');
  s = s.replace(/("(?:password|passwd|pwd|obfs-password|auth)"\s*:\s*")[^"]*(")/gi, '$1***$2');
  s = s.replace(/([?&](?:password|passwd|pwd|obfs-password|auth)=)[^&\s]*/gi, '$1***');
  if (s.length > 180) s = s.slice(0, 180) + '…';
  return s;
}

function setImportBusy(busy) {
  const ids = ['btn-import-nodes', 'btn-import-clipboard', 'btn-import-clear', 'btn-import-sample'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = !!busy;
  });
  const main = document.getElementById('btn-import-nodes');
  if (!main) return;
  if (busy) {
    if (!main.dataset.idleText) main.dataset.idleText = main.textContent;
    main.textContent = '导入中…';
    main.setAttribute('aria-busy', 'true');
  } else {
    if (main.dataset.idleText) main.textContent = main.dataset.idleText;
    main.removeAttribute('aria-busy');
  }
}

function renderImportResult(data, ok) {
  const panel = document.getElementById('import-result-panel');
  if (!panel) return;
  panel.hidden = false;
  panel.innerHTML = '';

  const d = data || {};
  const summary = document.createElement('p');
  summary.className = `import-summary ${ok ? 'v-ok' : 'v-bad'}`;
  const imported = Number(d.imported) || 0;
  const updated = Number(d.updated) || 0;
  const skipped = Number(d.skipped) || 0;
  summary.textContent = ok
    ? `导入结果：新增 ${imported} · 更新 ${updated} · 跳过 ${skipped}`
    : `导入失败：${extractApiError(d)}`;
  panel.appendChild(summary);

  if (ok && d.active_node_id) {
    const meta = document.createElement('p');
    meta.className = 'import-meta';
    const active = (Array.isArray(d.nodes) ? d.nodes : []).find(n => n && n.id === d.active_node_id);
    meta.textContent = active ? `当前活跃节点：${active.tag}` : '当前活跃节点已更新';
    panel.appendChild(meta);
  }

  const errors = Array.isArray(d.errors) ? d.errors : [];
  if (errors.length) {
    const list = document.createElement('div');
    list.className = 'import-error-list';
    errors.forEach(item => {
      const box = document.createElement('div');
      box.className = 'import-error';
      const e = item || {};
      const line = document.createElement('p');
      line.className = 'import-error-line';
      line.textContent = `第 ${e.line ?? '?'} 行解析失败`;
      box.appendChild(line);
      if (e.input) {
        const input = document.createElement('p');
        input.className = 'import-error-input';
        input.textContent = maskSensitive(e.input);
        box.appendChild(input);
      }
      const reason = document.createElement('p');
      reason.className = 'import-error-msg';
      reason.textContent = e.error || '未知原因';
      box.appendChild(reason);
      list.appendChild(box);
    });
    panel.appendChild(list);
  } else if (ok) {
    const done = document.createElement('p');
    done.className = 'import-meta';
    done.textContent = '全部条目均已处理，无解析错误';
    panel.appendChild(done);
  }
}

async function importNodesFromInput() {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法导入节点', 'warning');
    return;
  }
  const input = document.getElementById('raw-link-input');
  const text = (input.value || '').trim();
  const feedback = document.getElementById('parser-feedback');
  if (!text) {
    showToast('请先粘贴 v2rayN 链接、订阅内容或 sing-box JSON', 'warning');
    if (feedback) {
      feedback.textContent = '输入不能为空';
      feedback.className = 'tdesc v-bad';
    }
    return;
  }

  setImportBusy(true);
  const hadActiveBefore = !!appState.activeNodeId;
  if (feedback) {
    feedback.textContent = '正在解析并导入…';
    feedback.className = 'tdesc v-muted';
  }
  try {
    const res = await apiFetch('/api/nodes/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, url: '' })
    }, API_LONG_TIMEOUT_MS);
    const data = await res.json().catch(() => ({}));
    const importOk = res.ok && (!data.status || data.status === 'success');
    renderImportResult(data, importOk);

    if (!importOk) {
      const reason = extractApiError(data);
      showToast(`导入失败: ${reason}`, 'warning');
      if (feedback) {
        feedback.textContent = `导入失败: ${reason}`;
        feedback.className = 'tdesc v-bad';
      }
      return;
    }

    const imported = Number(data.imported) || 0;
    const updated = Number(data.updated) || 0;
    const errors = Array.isArray(data.errors) ? data.errors : [];
    const msg = `导入完成: 新增 ${imported} · 更新 ${updated}${errors.length ? ` · ${errors.length} 条失败` : ''}`;
    showToast(msg, errors.length ? 'warning' : 'success');
    if (feedback) {
      feedback.textContent = msg;
      feedback.className = errors.length ? 'tdesc v-warn' : 'tdesc v-ok';
    }

    await fetchNodes();
    // 导入成功后清空输入框, 避免明文口令长期停留在页面上
    if ((imported + updated) > 0) input.value = '';
    // v2rayN 首次导入体验: 导入前无活跃节点时自动启用一个
    // (后端导入可能已自动选中首个节点但未重启 sing-box, 这里补一次 activate)
    if ((imported + updated) > 0 && !hadActiveBefore && appState.nodes.length) {
      const targetId = appState.activeNodeId || appState.nodes[0].id;
      showToast('首次导入 · 正在自动启用第一个节点…', 'info');
      await activateNode(targetId);
    }
  } catch (err) {
    showToast('导入失败: 后端不可达', 'warning');
    if (feedback) {
      feedback.textContent = '导入失败: 后端不可达';
      feedback.className = 'tdesc v-bad';
    }
  } finally {
    setImportBusy(false);
  }
}

async function importFromClipboard() {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法导入节点', 'warning');
    return;
  }
  if (!navigator.clipboard || typeof navigator.clipboard.readText !== 'function') {
    showToast('浏览器不支持读取剪贴板，请手动粘贴', 'warning');
    return;
  }
  try {
    const text = await navigator.clipboard.readText();
    if (!text || !text.trim()) {
      showToast('剪贴板为空', 'warning');
      return;
    }
    document.getElementById('raw-link-input').value = text;
    await importNodesFromInput();
  } catch (err) {
    showToast('读取剪贴板失败，请允许权限或手动粘贴', 'warning');
  }
}

function clearImportInput() {
  const input = document.getElementById('raw-link-input');
  if (input) {
    input.value = '';
    input.focus();
  }
  const panel = document.getElementById('import-result-panel');
  if (panel) {
    panel.hidden = true;
    panel.innerHTML = '';
  }
  const feedback = document.getElementById('parser-feedback');
  if (feedback) {
    feedback.textContent = '';
    feedback.className = 'tdesc';
  }
}

// ---------------- 编辑 ----------------
function openNodeEditor(id) {
  const node = appState.nodes.find(n => n.id === id);
  if (!node) {
    showToast('节点不存在，请刷新列表', 'warning');
    return;
  }
  appState.editingNodeId = id;
  fillNodeForm(nodeToAppNode(node));
  const tile = document.getElementById('node-edit-tile');
  if (tile) {
    tile.hidden = false;
    tile.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function cancelNodeEdit() {
  appState.editingNodeId = null;
  const tile = document.getElementById('node-edit-tile');
  if (tile) tile.hidden = true;
  const active = appState.nodes.find(n => n.id === appState.activeNodeId);
  if (active) fillNodeForm(nodeToAppNode(active));
  else fillNodeForm(appState.currentNode);
}

function setNodeEditorBusy(busy) {
  document.querySelectorAll('#node-edit-tile .btn').forEach(btn => {
    btn.disabled = !!busy;
  });
}

function buildNodePatchPayload() {
  const tag = document.getElementById('node-tag').value.trim();
  const server = document.getElementById('node-server').value.trim();
  const port = parseInt(document.getElementById('node-port').value, 10);
  if (!server) {
    showToast('服务器域名 / IP 不能为空', 'warning');
    return null;
  }
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    showToast('服务端口必须在 1-65535 之间', 'warning');
    return null;
  }
  const numOrNull = (id) => {
    const v = parseInt(document.getElementById(id).value, 10);
    return Number.isFinite(v) ? v : null;
  };
  return {
    tag: tag || server,
    server,
    port,
    password: document.getElementById('node-password').value,
    sni: document.getElementById('node-sni').value.trim(),
    insecure: document.getElementById('node-insecure').value === 'true',
    obfs_type: document.getElementById('node-obfs-type').value.trim(),
    obfs_password: document.getElementById('node-obfs-pass').value,
    up_mbps: numOrNull('node-up'),
    down_mbps: numOrNull('node-down'),
    port_hopping: document.getElementById('node-port-hopping').value.trim()
  };
}

async function saveNodeForm(activateAfter) {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法保存节点', 'warning');
    return;
  }
  const id = appState.editingNodeId;
  if (!id) {
    showToast('请先选择要编辑的节点', 'warning');
    return;
  }
  const payload = buildNodePatchPayload();
  if (!payload) return;

  setNodeEditorBusy(true);
  try {
    const res = await apiFetch(`/api/nodes/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, API_LONG_TIMEOUT_MS);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || (data.status && data.status !== 'success')) {
      showToast(`保存失败: ${extractApiError(data)}`, 'warning');
      return;
    }

    const wasActive = appState.activeNodeId === id || data.activated === true;
    appState.editingNodeId = null;
    const tile = document.getElementById('node-edit-tile');
    if (tile) tile.hidden = true;

    if (wasActive) {
      showToast('已保存并重新下发', 'success');
    } else {
      showToast('节点已保存', 'success');
    }

    await fetchNodes();
    if (activateAfter && !wasActive) {
      await activateNode(id);
    }
  } catch (err) {
    // apiFetch 已进入演示模式并提示
  } finally {
    setNodeEditorBusy(false);
  }
}

function saveNodeEdit(btn) {
  return saveNodeForm(false);
}

function saveAndActivateNode(btn) {
  return saveNodeForm(true);
}

// ---------------- 删除 ----------------
async function deleteNode(id) {
  if (DEMO_MODE) {
    showToast('演示模式需后端在线，无法删除节点', 'warning');
    return;
  }
  const node = appState.nodes.find(n => n.id === id);
  if (!node) return;
  if (id === appState.activeNodeId) {
    showToast('活跃节点不能删除，请先启用其他节点', 'warning');
    return;
  }
  if (!window.confirm(`确定删除节点 [${node.tag}] 吗？此操作不可撤销。`)) return;

  try {
    const res = await apiFetch(`/api/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' }, API_LONG_TIMEOUT_MS);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || (data.status && data.status !== 'success')) {
      showToast(`删除失败: ${extractApiError(data)}`, 'warning');
      await fetchNodes();
      return;
    }
    showToast('节点已删除', 'success');
    await fetchNodes();
  } catch (err) {
    // apiFetch 已进入演示模式并提示
  }
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
      const reason = extractApiError(data) || ('HTTP ' + res.status);
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
  document.querySelectorAll('.rail > *, .topbar > *, .foot > *').forEach((el, i) => {
    el.style.transitionDelay = `${Math.min(i, 8) * 55}ms`;
  });
  requestAnimationFrame(() => requestAnimationFrame(() => document.body.classList.add('live')));

  // 1) 演示态初始化 (后端不可用时的完整兜底)
  fillNodeForm(appState.currentNode);
  renderNodeList();
  renderWhitelistTags();
  renderStatusReadouts();
  populateInterfaceSelects(IFACE_DEMO_LIST); // 先给演示列表, 后端在线时立即被真实列表替换
  updateShellFacts();

  // 2) 节点管理为默认落地页; #status / #nics 可直达
  const initialTab = TAB_TITLES[location.hash.slice(1)] ? location.hash.slice(1) : 'node';
  switchTab(initialTab);

  // 3) 尝试接入真实后端; 失败静默保持演示态
  await bootstrapFromBackend();
  refreshInterfaces(); // 非阻塞: 后端在线则载入宿主真实网卡
});

window.addEventListener('hashchange', function () {
  const tabId = location.hash.slice(1);
  if (TAB_TITLES[tabId] && tabId !== appState.activeTab) {
    switchTab(tabId);
  }
});
