from __future__ import annotations

import json
from types import SimpleNamespace

import register_ruyipage_v5 as v5


def _fake_session(captured):
    class Response:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    class Session:
        def __init__(self):
            self.headers = {}

        def post(self, url, **kwargs):
            captured.append((url, kwargs))
            if url.endswith("/createTask"):
                return Response({"errorId": 0, "taskId": "ez-task"})
            return Response(
                {
                    "errorId": 0,
                    "status": "ready",
                    "solution": {"token": "ez-token"},
                }
            )

    return Session


def _args(**overrides):
    values = {
        "protocol_user_agent": "Mozilla/5.0 test",
        "ezcaptcha_key": "key",
        "ezcaptcha_create_url": "https://api.ez-captcha.com/createTask",
        "ezcaptcha_result_url": "https://api.ez-captcha.com/getTaskResult",
        "ezcaptcha_timeout": 1,
        "ezcaptcha_poll_interval": 0,
        "capmonster_proxy_mode": "proxyless",
        "entry_url": "https://account.battle.net/creation/flow/creation-full",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_ezcaptcha_fun_captcha_contract(monkeypatch, tmp_path) -> None:
    captured = []
    monkeypatch.setattr(v5.requests, "Session", _fake_session(captured))

    result = v5.solve_with_ezcaptcha(
        {
            "blob": "blob-value",
            "siteKey": "site-key",
            "surl": "https://blizzard-api.arkoselabs.com",
            "websiteURL": "https://account.battle.net/creation/flow/creation-full",
        },
        _args(),
        tmp_path,
        v5.v4.ProxySettings(None, "direct"),
    )

    create_url, create_kwargs = captured[0]
    assert create_url.endswith("/createTask")
    task_payload = create_kwargs["json"]["task"]
    assert create_kwargs["json"]["clientKey"] == "key"
    assert task_payload["type"] == "FuncaptchaTaskProxyless"
    assert task_payload["websiteKey"] == "site-key"
    assert task_payload["funcaptchaApiJSSubdomain"] == "blizzard-api.arkoselabs.com"
    assert json.loads(task_payload["data"])["blob"] == "blob-value"
    assert result["provider"] == "ezcaptcha"
    assert result["token"] == "ez-token"
    assert "ez-token" not in (tmp_path / "ezcaptcha_result.json").read_text()


def test_ezcaptcha_uses_documented_proxy_string(monkeypatch, tmp_path) -> None:
    captured = []
    monkeypatch.setattr(v5.requests, "Session", _fake_session(captured))
    proxy = v5.v4.ProxySettings(
        "http://user:pass@127.0.0.1:8080",
        "proxy",
        "http",
        "127.0.0.1",
        8080,
        True,
    )

    v5.solve_with_ezcaptcha(
        {"siteKey": "site-key", "websiteURL": "https://example.test"},
        _args(capmonster_proxy_mode="proxy"),
        tmp_path,
        proxy,
    )

    task_payload = captured[0][1]["json"]["task"]
    assert task_payload["proxy"] == "http:127.0.0.1:8080:user:pass"
