import json


def _login(client):
    client.post("/api/setup", json={"username": "admin", "password": "hunter2hunter2"})
    client.post("/api/login", json={"username": "admin", "password": "hunter2hunter2"})


def _seed(tmp_path, monkeypatch):
    pay_ex = tmp_path / "CTF-pay" / "config.paypal.example.json"
    reg_ex = tmp_path / "CTF-reg" / "config.paypal-proxy.example.json"
    pay_ex.parent.mkdir(parents=True)
    reg_ex.parent.mkdir(parents=True)
    pay_ex.write_text(json.dumps({"paypal": {"email": ""}, "captcha": {"api_url": "", "api_key": ""}}))
    reg_ex.write_text(json.dumps({"mail": {"catch_all_domain": ""}, "captcha": {"client_key": ""}}))

    import webui.backend.settings as s
    monkeypatch.setattr(s, "PAY_EXAMPLE_PATH", pay_ex)
    monkeypatch.setattr(s, "REG_EXAMPLE_PATH", reg_ex)
    monkeypatch.setattr(s, "PAY_CONFIG_PATH", tmp_path / "CTF-pay" / "config.paypal.json")
    monkeypatch.setattr(s, "REG_CONFIG_PATH", tmp_path / "CTF-reg" / "config.paypal-proxy.json")
    # 注：conftest 已经把 WEBUI_DATA_DIR 设到 tmp_path，secrets.json 会落
    # 到 tmp_path/secrets.json，下面断言要用这个路径。


def test_export_writes_two_files(client, tmp_path, monkeypatch):
    _login(client)
    _seed(tmp_path, monkeypatch)

    answers = {
        "paypal": {"email": "you@example.com"},
        "cloudflare": {"cf_token": "tok-abc", "zone_names": ["a.com", "b.com"]},
        # Note: forward_to 已被 fallback_to 取代（在 cloudflare_kv 里）；这里
        # 顺带保证 _write_secrets 不再要求 forward_to。
        "cloudflare_kv": {
            "account_id": "acct-123",
            "kv_namespace_id": "kv-456",
            "worker_name": "otp-relay",
        },
        "captcha": {"api_url": "https://x", "api_key": "k", "client_key": "k"},
    }
    r = client.post("/api/config/export", json={"answers": answers})
    assert r.status_code == 200

    pay = json.loads((tmp_path / "CTF-pay" / "config.paypal.json").read_text())
    reg = json.loads((tmp_path / "CTF-reg" / "config.paypal-proxy.json").read_text())
    assert pay["paypal"]["email"] == "you@example.com"
    assert pay["captcha"]["api_key"] == "k"
    # mail.catch_all_domain(s) 来自 cloudflare zone_names；不再有 imap 字段
    assert reg["mail"]["catch_all_domain"] == "a.com"
    assert reg["mail"]["catch_all_domains"] == ["a.com", "b.com"]
    assert "imap_server" not in reg["mail"]
    assert reg["captcha"]["client_key"] == "k"

    # secrets.json 应该带上 cloudflare 凭证（落在 conftest 设的 WEBUI_DATA_DIR）
    secrets = json.loads((tmp_path / "secrets.json").read_text())
    cf = secrets["cloudflare"]
    assert cf["api_token"] == "tok-abc"
    assert cf["zone_names"] == ["a.com", "b.com"]
    assert cf["account_id"] == "acct-123"
    assert cf["otp_kv_namespace_id"] == "kv-456"
    assert cf["otp_worker_name"] == "otp-relay"


def test_export_backs_up_existing(client, tmp_path, monkeypatch):
    _login(client)
    _seed(tmp_path, monkeypatch)

    pay_path = tmp_path / "CTF-pay" / "config.paypal.json"
    pay_path.parent.mkdir(parents=True, exist_ok=True)
    pay_path.write_text(json.dumps({"old": True}))

    client.post("/api/config/export", json={"answers": {}})

    backups = list((tmp_path / "CTF-pay").glob("config.paypal.json.bak.*"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text()) == {"old": True}


def test_export_requires_auth(client):
    r = client.post("/api/config/export", json={"answers": {}})
    assert r.status_code == 401
