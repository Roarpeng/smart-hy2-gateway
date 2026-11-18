"""backend_app 核心契约与回归单元测试。

所有测试均在独立的 TemporaryDirectory 中运行，不触碰宿主 /data 或真实进程/iptables。
运行：
  python3 -m pytest tests/test_backend_app.py -v
  python3 -m unittest tests.test_backend_app -v
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import backend_app  # noqa: E402


class BackendAppTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="hy2-backend-test-")
        self.tmpdir = Path(self._tmpdir.name)
        self.state_file = self.tmpdir / "gateway_state.json"
        self.token_file = self.tmpdir / "api_token"
        self.singbox_config_file = self.tmpdir / "singbox.json"
        self.last_decision_file = self.tmpdir / "last_decision"
        self.current_ssid_file = self.tmpdir / "current_ssid"

        self.token = "test-gateway-token-secret-123456"
        self.token_file.write_text(self.token + "\n", encoding="utf-8")
        self.current_ssid_file.write_text("Test-WiFi\n", encoding="utf-8")

        self._patches = [
            patch.object(backend_app, "STATE_FILE", self.state_file),
            patch.object(backend_app, "TOKEN_FILE", self.token_file),
            patch.object(backend_app, "SINGBOX_CONFIG_FILE", self.singbox_config_file),
            patch.object(backend_app, "LAST_DECISION_FILE", self.last_decision_file),
            patch.object(backend_app, "CURRENT_SSID_FILE", self.current_ssid_file),
            patch.object(backend_app, "run_singbox_check", return_value=(True, "")),
            patch.object(backend_app.singbox_manager, "restart", return_value=True),
            patch.object(backend_app.singbox_manager, "start", return_value=True),
            patch.object(backend_app, "reapply_proxy_rules", return_value="mocked"),
            patch.object(backend_app, "sync_chnroute_ipset", return_value=True),
            patch.object(backend_app, "is_proxy_active", return_value=False),
            patch.dict(os.environ, {"GATEWAY_TOKEN": self.token}, clear=False),
        ]
        for p in self._patches:
            p.start()

        self.client = TestClient(backend_app.app)
        self.auth_headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self) -> None:
        for p in reversed(self._patches):
            p.stop()
        self._tmpdir.cleanup()

    # 1. API 鉴权与 Query Token 封堵测试
    def test_auth_and_query_token_blocked(self) -> None:
        # /api/health 免鉴权
        resp_health = self.client.get("/api/health")
        self.assertEqual(resp_health.status_code, 200)
        self.assertEqual(resp_health.json().get("status"), "ok")

        # 未带 Token 访问 /api/status 返回 401
        resp_no_auth = self.client.get("/api/status")
        self.assertEqual(resp_no_auth.status_code, 401)

        # 使用 ?token=<valid_token> query 参数访问必须返回 401
        resp_query_token = self.client.get(f"/api/status?token={self.token}")
        self.assertEqual(resp_query_token.status_code, 401)

        # Authorization: Bearer <valid_token> 返回 200
        resp_bearer = self.client.get("/api/status", headers=self.auth_headers)
        self.assertEqual(resp_bearer.status_code, 200)

        # X-Gateway-Token: <valid_token> 返回 200
        resp_x_token = self.client.get(
            "/api/status", headers={"X-Gateway-Token": self.token}
        )
        self.assertEqual(resp_x_token.status_code, 200)

    # 2. "***" 脱敏口令防覆写回归测试（P0 核心）
    def test_redacted_secrets_never_overwrite_real_passwords(self) -> None:
        link = (
            "hy2://my-real-secret-pw@hy2.example.com:8443"
            "?sni=hy2.example.com&obfs=salamander&obfs-password=my-real-obfs-pw#Main-Hy2"
        )
        imp = self.client.post(
            "/api/nodes/import", json={"text": link}, headers=self.auth_headers
        )
        self.assertEqual(imp.status_code, 200)
        node_id = imp.json()["nodes"][0]["id"]

        act = self.client.post(
            f"/api/nodes/{node_id}/activate", headers=self.auth_headers
        )
        self.assertEqual(act.status_code, 200)

        # GET /api/state (默认 reveal=False) 断言返回 "***"
        state_resp = self.client.get("/api/state", headers=self.auth_headers)
        self.assertEqual(state_resp.status_code, 200)
        redacted_state = state_resp.json()
        self.assertEqual(redacted_state["current_node"]["password"], "***")
        self.assertEqual(redacted_state["current_node"]["obfs_password"], "***")
        self.assertEqual(redacted_state["nodes"][0]["password"], "***")
        self.assertEqual(redacted_state["nodes"][0]["obfs_password"], "***")

        # 修改 whitelist 后将脱敏状态回传 POST /api/apply
        redacted_state["whitelist"] = ["New-Office-WiFi"]
        apply_resp = self.client.post(
            "/api/apply", json=redacted_state, headers=self.auth_headers
        )
        self.assertEqual(apply_resp.status_code, 200)

        disk_data = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(disk_data["whitelist"], ["New-Office-WiFi"])
        self.assertEqual(disk_data["nodes"][0]["password"], "my-real-secret-pw")
        self.assertEqual(disk_data["nodes"][0]["obfs_password"], "my-real-obfs-pw")
        self.assertEqual(disk_data["current_node"]["password"], "my-real-secret-pw")
        self.assertEqual(disk_data["current_node"]["obfs_password"], "my-real-obfs-pw")

        # PATCH /api/nodes/{id} 传入 "***" 断言不覆盖真实密码
        patch_resp = self.client.patch(
            f"/api/nodes/{node_id}",
            json={
                "tag": "Renamed-Hy2",
                "password": "***",
                "obfs_password": "***",
            },
            headers=self.auth_headers,
        )
        self.assertEqual(patch_resp.status_code, 200)
        disk_after_patch = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(disk_after_patch["nodes"][0]["tag"], "Renamed-Hy2")
        self.assertEqual(disk_after_patch["nodes"][0]["password"], "my-real-secret-pw")
        self.assertEqual(disk_after_patch["nodes"][0]["obfs_password"], "my-real-obfs-pw")

    # 3. PATCH /api/settings 轻量通道设置测试
    def test_patch_settings_preserves_nodes_and_passwords(self) -> None:
        link = "hy2://keep-this-pw@node.example.com:443#Keep-Node"
        imp = self.client.post(
            "/api/nodes/import", json={"text": link}, headers=self.auth_headers
        )
        self.assertEqual(imp.status_code, 200)

        resp = self.client.patch(
            "/api/settings",
            json={
                "whitelist": ["Corp-WiFi-5G"],
                "wifi_policy": "always_proxy",
                "rj45_iface": "eth0",
            },
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)
        disk_data = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(disk_data["whitelist"], ["Corp-WiFi-5G"])
        self.assertEqual(disk_data["wifi_policy"], "always_proxy")
        self.assertEqual(disk_data["rj45_iface"], "eth0")
        self.assertEqual(len(disk_data["nodes"]), 1)
        self.assertEqual(disk_data["nodes"][0]["password"], "keep-this-pw")

    # 4. Shadowsocks 节点迁移与编辑测试（P0 核心）
    def test_shadowsocks_migration_and_patch(self) -> None:
        # 旧格式 SS 节点自动迁移 method & 清空 obfs_type
        legacy_raw = {
            "nodes": [
                {
                    "id": "n_sslegacy",
                    "tag": "Legacy-SS",
                    "protocol": "shadowsocks",
                    "server": "ss.example.com",
                    "port": 8388,
                    "password": "ss-password",
                    "method": "",
                    "obfs_type": "aes-256-gcm",
                }
            ],
            "active_node_id": "n_sslegacy",
        }
        normalized = backend_app.normalize_state_dict(legacy_raw)
        ss_node = normalized["nodes"][0]
        self.assertEqual(ss_node["method"], "aes-256-gcm")
        self.assertEqual(ss_node["obfs_type"], "")

        # 通过 API 导入并 PATCH SS 节点
        user = (
            base64.urlsafe_b64encode(b"aes-256-gcm:ss-api-pw")
            .decode("ascii")
            .rstrip("=")
        )
        imp = self.client.post(
            "/api/nodes/import",
            json={"text": f"ss://{user}@ss.example.com:8388#SS-Node"},
            headers=self.auth_headers,
        )
        self.assertEqual(imp.status_code, 200)
        nid = imp.json()["nodes"][0]["id"]

        patch_resp = self.client.patch(
            f"/api/nodes/{nid}",
            json={"tag": "SS-Edited", "method": "chacha20-ietf-poly1305"},
            headers=self.auth_headers,
        )
        self.assertEqual(patch_resp.status_code, 200, patch_resp.text)
        disk_data = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(disk_data["nodes"][0]["tag"], "SS-Edited")
        self.assertEqual(disk_data["nodes"][0]["method"], "chacha20-ietf-poly1305")
        self.assertEqual(disk_data["nodes"][0]["obfs_type"], "")

    # 5. build_singbox_config 多协议、主备直连 DNS 与 diag-in 认证测试
    def test_build_singbox_config_primary_fallback_dns_and_diag_auth(self) -> None:
        raw_state = backend_app.normalize_state_dict(
            {
                "nodes": [
                    {
                        "id": "n_primary",
                        "tag": "primary-hy2",
                        "protocol": "hysteria2",
                        "server": "primary.example.com",
                        "port": 443,
                        "password": "primary-secret",
                    },
                    {
                        "id": "n_fallback",
                        "tag": "fallback-trojan",
                        "protocol": "trojan",
                        "server": "fallback.example.com",
                        "port": 443,
                        "password": "fallback-secret",
                    },
                ],
                "active_node_id": "n_primary",
                "fallback_node_id": "n_fallback",
            }
        )
        state = backend_app.StateModel.model_validate(raw_state)

        real_ruleset_dir = REPO_ROOT / "ruleset"
        with patch.object(backend_app, "RULE_SET_DIR", str(real_ruleset_dir)):
            cfg = backend_app.build_singbox_config(state)

        # dns.rules[0] 为主备节点域名直连 cn-dns，位于 google 关键字之前
        self.assertEqual(
            cfg["dns"]["rules"][0],
            {
                "domain": ["primary.example.com", "fallback.example.com"],
                "server": "cn-dns",
            },
        )
        self.assertEqual(
            cfg["dns"]["rules"][1],
            {"domain_keyword": ["google", "gstatic"], "server": "proxy-dns"},
        )

        # outbounds 含 auto-out (urltest)
        out_by_tag = {o["tag"]: o for o in cfg["outbounds"]}
        self.assertIn("auto-out", out_by_tag)
        self.assertEqual(out_by_tag["auto-out"]["type"], "urltest")
        self.assertEqual(
            out_by_tag["auto-out"]["outbounds"], ["primary-hy2", "fallback-trojan"]
        )

        # inbounds 中 diag-in 含非空 users 列表 (username & password)
        in_by_tag = {i["tag"]: i for i in cfg["inbounds"]}
        self.assertIn("diag-in", in_by_tag)
        diag_users = in_by_tag["diag-in"].get("users")
        self.assertIsInstance(diag_users, list)
        self.assertTrue(len(diag_users) >= 1)
        self.assertTrue(diag_users[0].get("username"))
        self.assertTrue(diag_users[0].get("password"))

        # 若 vendor/sing-box 存在且可执行，执行真实 sing-box check -c
        vendor_sb = REPO_ROOT / "vendor" / "sing-box"
        if vendor_sb.is_file() and os.access(vendor_sb, os.X_OK):
            cfg_file = self.tmpdir / "real_check_singbox.json"
            cfg_file.write_text(
                json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            proc = subprocess.run(
                [str(vendor_sb), "check", "-c", str(cfg_file)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"real sing-box check failed: {proc.stderr or proc.stdout}",
            )

    # 6. POST /api/reload 接口测试
    def test_reload_endpoint_with_and_without_active_node(self) -> None:
        # 无节点状态
        resp_empty = self.client.post("/api/reload", headers=self.auth_headers)
        self.assertEqual(resp_empty.status_code, 200)
        self.assertIs(resp_empty.json()["restarted"], False)

        # 导入节点后处于活跃状态
        imp = self.client.post(
            "/api/nodes/import",
            json={"text": "hy2://pw@reload.example.com:443#Reload-Node"},
            headers=self.auth_headers,
        )
        self.assertEqual(imp.status_code, 200)

        resp_active = self.client.post("/api/reload", headers=self.auth_headers)
        self.assertEqual(resp_active.status_code, 200)
        self.assertIs(resp_active.json()["restarted"], True)

    # 7. atomic_write_json 多线程并发写入测试
    def test_atomic_write_json_concurrent_threads(self) -> None:
        target_file = self.tmpdir / "concurrent_state.json"
        errors: list[Exception] = []
        errors_lock = threading.Lock()

        def worker(tid: int) -> None:
            for seq in range(50):
                try:
                    backend_app.atomic_write_json(
                        target_file,
                        {"thread": tid, "seq": seq, "payload": "x" * 128},
                        mode=0o600,
                    )
                except Exception as exc:
                    with errors_lock:
                        errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertTrue(target_file.exists())
        final_obj = json.loads(target_file.read_text(encoding="utf-8"))
        self.assertIn("thread", final_obj)
        self.assertIn("seq", final_obj)


if __name__ == "__main__":
    unittest.main()
