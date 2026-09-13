# -*- coding: utf-8 -*-
"""Selectable V5 runner built on the V4 persistent HTTP registration flow."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import random
import re
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional
from urllib.parse import unquote, urlsplit

import requests

import register_ruyipage_v4 as v4
import v5_yescaptcha_solver
from battle_protocol_flow_v4 import BattleProtocolClient, PersistentFlowState
from proxy_traffic_meter import ProxyTrafficMeter
from v5_cloak_adapter import (
    CloakArkoseBlobCatcher,
    CloakArkoseImageCatcher,
    launch_cloak_page,
)
from v5_email_pool import EmailCredential, select_email_credential
from v5_email_verifier import EmailVerificationResult, verify_registered_email
from v5_resource_policy import should_block_tracking_resource


LOG = logging.getLogger("http_register_v5")
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "ruyipage_http_v5_register" / "runs"
DEFAULT_REGISTRATION_COUNTRY = "USA"
DEFAULT_YESCAPTCHA_API_URL = "https://api.yescaptcha.com/createTask"
DEFAULT_CAPMONSTER_CREATE_URL = "https://api.capmonster.cloud/createTask"
DEFAULT_CAPMONSTER_RESULT_URL = "https://api.capmonster.cloud/getTaskResult"
DEFAULT_CAPMONSTER_USER_AGENT_URL = "https://capmonster.cloud/api/useragent/actual"
DEFAULT_TWOCAPTCHA_CREATE_URL = "https://api.2captcha.com/createTask"
DEFAULT_TWOCAPTCHA_RESULT_URL = "https://api.2captcha.com/getTaskResult"
DEFAULT_SOLVECAPTCHA_CREATE_URL = "https://api.solvecaptcha.com/in.php"
DEFAULT_SOLVECAPTCHA_RESULT_URL = "https://api.solvecaptcha.com/res.php"
DEFAULT_EZCAPTCHA_CREATE_URL = "https://api.ez-captcha.com/createTask"
DEFAULT_EZCAPTCHA_RESULT_URL = "https://api.ez-captcha.com/getTaskResult"
DEFAULT_PROXY_DIRECT_HOSTS = (
    "blz-contentstack-assets.akamaized.net",
    "forge.akamaized.net",
)
_PROXY_ONLY_HOST_SUFFIXES = (
    "arkoselabs.com",
    "battle.net",
    "blizzard.com",
)
DEFAULT_WINDOWS_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)

# V5 keeps its historical exit code by default.  V6 installs a narrow,
# process-local override for deterministic submission outcomes so its workflow
# can distinguish them from retryable transport and solver failures.
DETERMINISTIC_FAILURE_EXIT_CODES: dict[str, int] = {}
_DIAGNOSTIC_SECRET_FIELDS = {
    "api_key",
    "blob",
    "client_key",
    "cookie",
    "cookies",
    "password",
    "proxy",
    "proxy_login",
    "proxy_password",
    "proxy_url",
    "token",
}


def _diagnostic_digest(value: Any, *, length: int = 16) -> str:
    """Return a short digest for correlating sensitive values without logging them."""

    raw = str(value or "")
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:length]


def _diagnostic_host(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    return str(parsed.hostname or "").lower()


def _diagnostic_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Defend the artifact against accidentally supplied raw secret fields."""

    result: dict[str, Any] = {}
    for key, value in fields.items():
        normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key)).casefold()
        result[str(key)] = (
            "<redacted>" if normalized in _DIAGNOSTIC_SECRET_FIELDS else value
        )
    return result


def _diagnostic_event(
    out: Path,
    phase: str,
    started: float,
    **fields: Any,
) -> None:
    """Append a safe phase event and mirror it to the console log.

    Callers pass only explicit diagnostic fields. Secrets are represented by
    lengths/digests so the trace remains useful when uploaded as an artifact.
    """

    safe_fields = _diagnostic_fields(fields)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "elapsedMs": round((time.perf_counter() - started) * 1000, 1),
        "phase": phase,
        **safe_fields,
    }
    path = out / "diagnostic_trace.jsonl"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception as exc:
        LOG.warning("诊断时间线写入失败：%s", type(exc).__name__)
    visible = " ".join(
        f"{key}={value}"
        for key, value in safe_fields.items()
        if value not in (None, "", [], {})
    )
    LOG.info("[诊断] %s%s", phase, f" | {visible}" if visible else "")


def _protocol_diagnostic_snapshot(client: Any) -> dict[str, Any]:
    state = getattr(getattr(client, "state", None), "data", {}) or {}
    response = state.get("response") if isinstance(state, Mapping) else {}
    if not isinstance(response, Mapping):
        response = {}
    form = getattr(client, "form", None)
    return {
        "stateStatus": str(state.get("status") or "") if isinstance(state, Mapping) else "",
        "formStep": str(getattr(form, "step", "") or "") if form else "",
        "responseLabel": str(response.get("label") or ""),
        "responseStatus": response.get("statusCode"),
        "responseLength": response.get("length"),
        "responseSha256": str(response.get("sha256") or "")[:16],
        "responseHost": _diagnostic_host(response.get("url")),
        "responsePath": str(response.get("path") or ""),
    }


def _protocol_history(client: Any) -> list[dict[str, Any]]:
    state = getattr(getattr(client, "state", None), "data", {}) or {}
    raw_history = state.get("history") if isinstance(state, Mapping) else []
    if not isinstance(raw_history, list):
        return []
    events: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_history, start=1):
        if not isinstance(raw, Mapping):
            continue
        events.append(
            {
                "transitionIndex": index,
                "stateEventAt": str(raw.get("at") or ""),
                "completed": str(raw.get("completed") or ""),
                "failed": str(raw.get("failed") or ""),
                "nextStep": str(raw.get("next") or ""),
                "returnedStep": str(raw.get("returned") or ""),
                "classification": str(raw.get("classification") or ""),
                "httpStatus": raw.get("httpStatus"),
                "responseSha256": str(raw.get("responseSha256") or "")[:16],
            }
        )
    return events


def _emit_protocol_history(out: Path, client: Any, started: float) -> None:
    for event in _protocol_history(client):
        _diagnostic_event(out, "protocol_transition", started, **event)


def _server_response_signals(outcome: Mapping[str, Any]) -> dict[str, Any]:
    """Classify a captcha-gate response without copying its visible text."""

    sample = str(outcome.get("sample") or "")
    errors = outcome.get("errors")
    if not isinstance(errors, list):
        errors = []
    text = " ".join([sample, *(str(value) for value in errors)]).casefold()
    labels: list[str] = []
    patterns = (
        ("humanity_only", ("detecting humanity", "only humans are allowed")),
        ("value_invalid", ("value is invalid", "value invalid")),
        ("captcha_related", ("arkose", "funcaptcha", "captcha")),
        ("session_or_csrf", ("csrf", "session expired", "session has expired")),
        ("rate_limited", ("rate limit", "too many", "try again later")),
        ("email_already_registered", ("already registered", "already exists")),
    )
    for label, needles in patterns:
        if any(needle in text for needle in needles):
            labels.append(label)
    if not labels:
        labels.append("no_known_server_signal")
    return {
        "labels": labels,
        "errorCount": len(errors),
        "sampleLength": len(sample),
        "sampleSha256": _diagnostic_digest(sample),
        "errorSha256": [_diagnostic_digest(value) for value in errors],
    }


def parse_proxy_direct_hosts(value: Any) -> tuple[str, ...]:
    hosts: list[str] = []
    for raw_host in str(value or "").split(","):
        host = raw_host.strip().strip(".").lower()
        if not host:
            continue
        if any(character in host for character in "/?#@:"):
            raise ValueError(f"直连分流项必须是纯域名，当前值为 {raw_host!r}")
        if any(
            host == suffix or host.endswith(f".{suffix}")
            for suffix in _PROXY_ONLY_HOST_SUFFIXES
        ):
            raise ValueError(f"身份或验证域名禁止直连分流: {host}")
        if host not in hosts:
            hosts.append(host)
    return tuple(hosts)


def force_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")


def run_id() -> str:
    return "run_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def setup_logging(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    formatter = logging.Formatter("%(asctime)s [HTTP-V5] %(message)s", "%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(stream)
    root.addHandler(file_handler)
    for name in ("urllib3", "PIL"):
        logging.getLogger(name).setLevel(logging.WARNING)


def write_json(path: Path, value: Any) -> None:
    v4.write_json(path, value)


def fetch_capmonster_user_agent(url: str = DEFAULT_CAPMONSTER_USER_AGENT_URL) -> str:
    """Fetch CapMonster's current UA as an unmodified plain-text value."""

    response = requests.get(
        str(url),
        headers={"Accept": "text/plain"},
        timeout=15,
    )
    response.raise_for_status()
    user_agent = str(response.text or "").strip()
    if not user_agent:
        raise ValueError("CapMonster User-Agent 接口返回为空")
    if "\r" in user_agent or "\n" in user_agent:
        raise ValueError("CapMonster User-Agent 接口返回了多行文本")
    if not user_agent.startswith("Mozilla/5.0"):
        raise ValueError("CapMonster User-Agent 接口返回格式异常")
    if len(user_agent) > 512:
        raise ValueError("CapMonster User-Agent 接口返回过长")
    return user_agent


def apply_capmonster_user_agent(
    args: argparse.Namespace,
    out: Path,
    url: str = DEFAULT_CAPMONSTER_USER_AGENT_URL,
) -> dict[str, Any]:
    """Apply one UA consistently to the V5 HTTP client and CapMonster task."""

    fallback = str(getattr(args, "protocol_user_agent", "") or "").strip()
    if str(getattr(args, "solver", "") or "").lower() != "capmonster":
        return {
            "source": "not-applicable",
            "length": len(fallback),
            "sha256": _diagnostic_digest(fallback),
        }
    try:
        user_agent = fetch_capmonster_user_agent(url)
    except Exception as exc:
        info = {
            "source": "configured-fallback",
            "length": len(fallback),
            "sha256": _diagnostic_digest(fallback),
            "errorType": type(exc).__name__,
        }
        write_json(out / "capmonster_user_agent.json", info)
        LOG.warning(
            "CapMonster 当前 UA 读取失败，回退已配置 UA：错误类型=%s",
            type(exc).__name__,
        )
        return info
    args.protocol_user_agent = user_agent
    info = {
        "source": "capmonster-api",
        "length": len(user_agent),
        "sha256": _diagnostic_digest(user_agent),
    }
    write_json(out / "capmonster_user_agent.json", {**info, "userAgent": user_agent})
    LOG.info(
        "CapMonster 当前 UA 已加载：来源=官方接口，长度=%s，sha256=%s",
        len(user_agent),
        _diagnostic_digest(user_agent),
    )
    return info


def build_parser() -> argparse.ArgumentParser:
    parser = v4.build_parser()
    parser.description = (
        "持久 HTTP 注册 + 可选浏览器 + 可选求解器"
    )
    parser.set_defaults(
        output_dir=str(DEFAULT_OUTPUT_ROOT),
        static_cache_dir=os.environ.get(
            "V5_STATIC_CACHE_DIR",
            str(PROJECT_ROOT / ".cache" / "v5_public_static"),
        ),
        protocol_user_agent=os.environ.get(
            "V5_USER_AGENT", DEFAULT_WINDOWS_USER_AGENT
        ),
    )
    parser.add_argument(
        "--solver",
        choices=(
            "v11",
            "yescaptcha",
            "capmonster",
            "twocaptcha",
            "solvecaptcha",
            "ezcaptcha",
        ),
        default=os.environ.get("V5_SOLVER", "v11").lower(),
    )
    parser.add_argument(
        "--browser",
        choices=("ruyipage", "cloakbrowser"),
        default=os.environ.get("V5_BROWSER", "ruyipage").lower(),
    )
    parser.add_argument(
        "--country",
        default=os.environ.get("V5_COUNTRY", DEFAULT_REGISTRATION_COUNTRY),
        help="ISO 3166-1 三字母注册国家代码（默认：USA）",
    )
    parser.add_argument(
        "--email-source",
        choices=("generated", "pool"),
        default=os.environ.get("V5_EMAIL_SOURCE", "generated").lower(),
        help="使用生成邮箱，或从 Email_registing.txt 确定性分配一行",
    )
    parser.add_argument(
        "--email-pool-file",
        default=os.environ.get("V5_EMAIL_POOL_FILE", "Email_registing.txt"),
    )
    parser.add_argument(
        "--email-pool-index",
        type=int,
        default=int(os.environ.get("V5_EMAIL_POOL_INDEX", "0") or 0),
    )
    parser.add_argument("--email-login-timeout", type=float, default=60.0)
    parser.add_argument("--email-mail-timeout", type=float, default=120.0)
    parser.add_argument("--email-verification-timeout", type=float, default=20.0)
    parser.add_argument(
        "--email-browser-cache-dir",
        default=os.environ.get(
            "V5_EMAIL_BROWSER_CACHE_DIR",
            str(PROJECT_ROOT / ".cache" / "v5_email_browser_profile"),
        ),
        help=(
            "用于指定邮箱验证的 RuyiPage Firefox 配置缓存；"
            "每次使用前后都会删除身份状态"
        ),
    )
    parser.add_argument(
        "--yescaptcha-key",
        default=os.environ.get("YESCAPTCHA_API_KEY", ""),
    )
    parser.add_argument(
        "--yescaptcha-api-url",
        default=DEFAULT_YESCAPTCHA_API_URL,
    )
    parser.add_argument("--yescaptcha-timeout", type=float, default=35.0)
    parser.add_argument("--click-interval-min-ms", type=int, default=250)
    parser.add_argument("--click-interval-max-ms", type=int, default=600)
    parser.add_argument(
        "--click-gap-min-ms",
        type=int,
        default=int(os.environ.get("V5_CLICK_GAP_MIN_MS", "180")),
        help="V11 balanced 模式相邻箭头点击的最短等待毫秒数",
    )
    parser.add_argument(
        "--click-gap-max-ms",
        type=int,
        default=int(os.environ.get("V5_CLICK_GAP_MAX_MS", "400")),
        help="V11 balanced 模式相邻箭头点击的最长等待毫秒数",
    )
    parser.add_argument(
        "--capmonster-key",
        default=os.environ.get("CAPMONSTER_API_KEY", ""),
    )
    parser.add_argument(
        "--capmonster-create-url",
        default=DEFAULT_CAPMONSTER_CREATE_URL,
    )
    parser.add_argument(
        "--capmonster-result-url",
        default=DEFAULT_CAPMONSTER_RESULT_URL,
    )
    parser.add_argument(
        "--capmonster-user-agent-url",
        default=os.environ.get(
            "V5_CAPMONSTER_USER_AGENT_URL",
            DEFAULT_CAPMONSTER_USER_AGENT_URL,
        ),
        help="读取 CapMonster 当前 User-Agent 的官方纯文本接口",
    )
    parser.add_argument(
        "--capmonster-proxy-mode",
        choices=("proxy", "proxyless"),
        default=os.environ.get("V5_CAPMONSTER_PROXY_MODE", "proxy").lower(),
        help=(
            "proxy 会把所选注册代理传给 CapMonster；"
            "proxyless 使用 CapMonster 自身网络"
        ),
    )
    parser.add_argument("--capmonster-timeout", type=float, default=300.0)
    parser.add_argument("--capmonster-poll-interval", type=float, default=2.5)
    parser.add_argument(
        "--twocaptcha-key", default=os.environ.get("TWOCAPTCHA_API_KEY", "")
    )
    parser.add_argument(
        "--twocaptcha-create-url", default=DEFAULT_TWOCAPTCHA_CREATE_URL
    )
    parser.add_argument(
        "--twocaptcha-result-url", default=DEFAULT_TWOCAPTCHA_RESULT_URL
    )
    parser.add_argument("--twocaptcha-timeout", type=float, default=300.0)
    parser.add_argument("--twocaptcha-poll-interval", type=float, default=2.5)
    parser.add_argument(
        "--solvecaptcha-key", default=os.environ.get("SOLVECAPTCHA_API_KEY", "")
    )
    parser.add_argument(
        "--solvecaptcha-create-url", default=DEFAULT_SOLVECAPTCHA_CREATE_URL
    )
    parser.add_argument(
        "--solvecaptcha-result-url", default=DEFAULT_SOLVECAPTCHA_RESULT_URL
    )
    parser.add_argument("--solvecaptcha-timeout", type=float, default=300.0)
    parser.add_argument("--solvecaptcha-poll-interval", type=float, default=5.0)
    parser.add_argument(
        "--ezcaptcha-key", default=os.environ.get("EZCAPTCHA_API_KEY", "")
    )
    parser.add_argument(
        "--ezcaptcha-create-url", default=DEFAULT_EZCAPTCHA_CREATE_URL
    )
    parser.add_argument(
        "--ezcaptcha-result-url", default=DEFAULT_EZCAPTCHA_RESULT_URL
    )
    parser.add_argument("--ezcaptcha-timeout", type=float, default=300.0)
    parser.add_argument("--ezcaptcha-poll-interval", type=float, default=5.0)
    parser.add_argument(
        "--proxy-direct-hosts",
        default=os.environ.get(
            "V5_PROXY_DIRECT_HOSTS",
            ",".join(DEFAULT_PROXY_DIRECT_HOSTS),
        ),
        help=(
            "用逗号分隔的公共静态资源直连域名；"
            "留空则禁用分流"
        ),
    )
    parser.add_argument("--cloak-locale", default="en-GB")
    return parser


def validate_configuration(args: argparse.Namespace) -> dict[str, Any]:
    registration_country = str(args.country or "").strip().upper()
    proxy_direct_hosts = parse_proxy_direct_hosts(args.proxy_direct_hosts)
    if len(registration_country) != 3 or not registration_country.isalpha():
        raise ValueError(
            "--country 必须是三字母 ISO 国家代码，"
            f"当前值为 {args.country!r}"
        )
    if args.solver == "yescaptcha" and not str(args.yescaptcha_key).strip():
        raise ValueError(
            "选择 YesCaptcha 求解时必须提供 YESCAPTCHA_API_KEY"
        )
    if args.solver == "capmonster" and not str(args.capmonster_key).strip():
        raise ValueError(
            "选择 CapMonster 求解时必须提供 CAPMONSTER_API_KEY"
        )
    if args.solver == "twocaptcha" and not str(args.twocaptcha_key).strip():
        raise ValueError(
            "选择 2Captcha 求解时必须提供 TWOCAPTCHA_API_KEY"
        )
    if args.solver == "solvecaptcha" and not str(args.solvecaptcha_key).strip():
        raise ValueError(
            "选择 SolveCaptcha 求解时必须提供 SOLVECAPTCHA_API_KEY"
        )
    if args.solver == "ezcaptcha" and not str(args.ezcaptcha_key).strip():
        raise ValueError(
            "选择 EzCaptcha 求解时必须提供 EZCAPTCHA_API_KEY"
        )
    if args.capmonster_poll_interval <= 0 or args.capmonster_timeout <= 0:
        raise ValueError("CapMonster 轮询间隔和超时时间必须为正数")
    if args.twocaptcha_poll_interval <= 0 or args.twocaptcha_timeout <= 0:
        raise ValueError("2Captcha 轮询间隔和超时时间必须为正数")
    if args.solvecaptcha_poll_interval <= 0 or args.solvecaptcha_timeout <= 0:
        raise ValueError("SolveCaptcha 轮询间隔和超时时间必须为正数")
    if args.ezcaptcha_poll_interval <= 0 or args.ezcaptcha_timeout <= 0:
        raise ValueError("EzCaptcha 轮询间隔和超时时间必须为正数")
    if args.yescaptcha_timeout <= 0:
        raise ValueError("YesCaptcha 超时时间必须为正数")
    if args.email_source == "pool" and int(args.email_pool_index) < 1:
        raise ValueError("邮箱池模式下 --email-pool-index 必须大于等于 1")
    if min(
        float(args.email_login_timeout),
        float(args.email_mail_timeout),
        float(args.email_verification_timeout),
    ) <= 0:
        raise ValueError("邮箱验证的各项超时时间必须为正数")
    return {
        "solver": args.solver,
        "browser": args.browser,
        "registrationCountry": registration_country,
        "emailSource": args.email_source,
        "emailPoolIndex": (
            int(args.email_pool_index) if args.email_source == "pool" else None
        ),
        "browserRequired": args.solver in {"v11", "yescaptcha"},
        "proxyDirectHosts": list(proxy_direct_hosts),
        "capmonsterProxyMode": (
            args.capmonster_proxy_mode
            if args.solver in {
                "capmonster",
                "twocaptcha",
                "solvecaptcha",
                "ezcaptcha",
            }
            else "not-applicable"
        ),
        "apiKeyConfigured": (
            True
            if args.solver == "v11"
            else bool(
                str(
                    args.yescaptcha_key
                    if args.solver == "yescaptcha"
                    else (
                        args.capmonster_key
                        if args.solver == "capmonster"
                        else (
                            args.twocaptcha_key
                            if args.solver == "twocaptcha"
                            else (
                                args.solvecaptcha_key
                                if args.solver == "solvecaptcha"
                                else args.ezcaptcha_key
                            )
                        )
                    )
                ).strip()
            )
        ),
    }


def _redacted_provider_response(value: Mapping[str, Any]) -> dict[str, Any]:
    clean = dict(value)
    solution = dict(clean.get("solution") or {})
    token = str(solution.pop("token", "") or "")
    if token:
        solution["tokenLength"] = len(token)
    if solution:
        clean["solution"] = solution
    elif "solution" in clean:
        clean["solution"] = {}
    return clean


def _capmonster_proxy_fields(proxy: v4.ProxySettings) -> dict[str, Any]:
    """Translate the selected V5 route into CapMonster FunCaptcha fields."""

    if not proxy.enabled:
        return {}
    parsed = urlsplit(str(proxy.url or ""))
    proxy_type = str(proxy.scheme or parsed.scheme or "http").lower()
    if proxy_type == "socks5h":
        proxy_type = "socks5"
    if proxy_type not in {"http", "https", "socks4", "socks5"}:
        raise ValueError(f"CapMonster 不支持此代理协议: {proxy_type}")
    address = str(proxy.host or parsed.hostname or "").strip()
    port = int(proxy.port or parsed.port or 0)
    if not address or not 1 <= port <= 65535:
        raise ValueError("所选代理没有有效的地址和端口")

    fields: dict[str, Any] = {
        "proxyType": proxy_type,
        "proxyAddress": address,
        "proxyPort": port,
    }
    if parsed.username is not None:
        fields["proxyLogin"] = unquote(parsed.username)
        fields["proxyPassword"] = unquote(parsed.password or "")
    return fields


def _twocaptcha_proxy_fields(proxy: v4.ProxySettings) -> dict[str, Any]:
    """Translate the selected route to the 2Captcha proxy task fields."""

    fields = _capmonster_proxy_fields(proxy)
    # 2Captcha documents http, socks4 and socks5 task proxy types.  Treat an
    # HTTPS proxy endpoint as an HTTP CONNECT proxy for this API field.
    if fields.get("proxyType") == "https":
        fields["proxyType"] = "http"
    return fields


def _solvecaptcha_proxy_fields(proxy: v4.ProxySettings) -> dict[str, Any]:
    """Translate the selected route to SolveCaptcha's proxy form fields."""

    if not proxy.enabled:
        return {}
    parsed = urlsplit(str(proxy.url or ""))
    proxy_type = str(proxy.scheme or parsed.scheme or "http").lower()
    if proxy_type == "socks5h":
        proxy_type = "socks5"
    if proxy_type not in {"http", "https", "socks4", "socks5"}:
        raise ValueError(f"SolveCaptcha 不支持此代理协议: {proxy_type}")
    address = str(proxy.host or parsed.hostname or "").strip()
    port = int(proxy.port or parsed.port or 0)
    if not address or not 1 <= port <= 65535:
        raise ValueError("所选代理没有有效的地址和端口")
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    username = unquote(parsed.username or "") if parsed.username is not None else ""
    password = unquote(parsed.password or "") if parsed.password is not None else ""
    proxy_value = f"{host}:{port}"
    if parsed.username is not None:
        proxy_value = f"{username}:{password}@{proxy_value}"
    return {"proxytype": proxy_type.upper(), "proxy": proxy_value}


def _parse_solvecaptcha_response(response: Any) -> dict[str, Any]:
    """Normalize SolveCaptcha's JSON and legacy ``OK|value`` responses."""

    try:
        payload = response.json()
    except Exception:
        raw = str(getattr(response, "text", "") or "").strip()
        if "|" in raw:
            status, request = raw.split("|", 1)
            return {
                "status": 1 if status.strip().upper() == "OK" else 0,
                "request": request,
            }
        return {"status": 0, "request": raw}
    if isinstance(payload, Mapping):
        return dict(payload)
    return {"status": 0, "request": str(payload or "")}


def _redacted_solvecaptcha_response(
    payload: Mapping[str, Any], *, token_response: bool = False
) -> dict[str, Any]:
    """Persist SolveCaptcha metadata without writing a returned token."""

    clean = dict(payload)
    if token_response and "request" in clean:
        request = str(clean.get("request") or "")
        clean["request"] = "<redacted>" if request else ""
        clean["requestLength"] = len(request)
        clean["requestSha256"] = _diagnostic_digest(request)
    return clean


def solve_with_solvecaptcha(
    context: Mapping[str, Any],
    args: argparse.Namespace,
    out: Path,
    proxy: v4.ProxySettings,
) -> dict[str, Any]:
    """Create and poll a SolveCaptcha Arkose Labs FunCaptcha task."""

    solver_started = time.perf_counter()
    blob = str(context.get("blob") or "")
    site_key = str(context.get("siteKey") or v4.DEFAULT_SITE_KEY)
    surl = str(context.get("surl") or v4.DEFAULT_SURL)
    website_url = str(context.get("websiteURL") or args.entry_url)
    user_agent = str(
        args.protocol_user_agent
        or context.get("userAgent")
        or DEFAULT_WINDOWS_USER_AGENT
    )
    requested_proxy = str(args.capmonster_proxy_mode).lower() == "proxy"
    use_proxy = requested_proxy and proxy.enabled
    form_data: dict[str, Any] = {
        "key": str(args.solvecaptcha_key).strip(),
        "method": "funcaptcha",
        "publickey": site_key,
        "surl": surl,
        "pageurl": website_url,
        "userAgent": user_agent,
        "json": 1,
    }
    if blob:
        form_data["data"] = json.dumps({"blob": blob}, separators=(",", ":"))
    if use_proxy:
        form_data.update(_solvecaptcha_proxy_fields(proxy))
    task_mode = "proxy" if use_proxy else "proxyless"
    LOG.info(
        "SolveCaptcha 任务：类型=funcaptcha，模式=%s，线路=%s",
        task_mode,
        proxy.display if use_proxy else "SolveCaptcha 自身网络",
    )
    _diagnostic_event(
        out,
        "solvecaptcha_create_start",
        solver_started,
        solver="solvecaptcha",
        method="funcaptcha",
        proxyMode=task_mode,
        proxyConfigured=bool(use_proxy),
        blobLength=len(blob),
        blobSha256=_diagnostic_digest(blob),
        siteKeySha256=_diagnostic_digest(site_key),
        surlHost=_diagnostic_host(surl),
        websiteHost=_diagnostic_host(website_url),
        userAgentSha256=_diagnostic_digest(user_agent),
    )

    session = requests.Session()
    try:
        create_response = session.post(
            args.solvecaptcha_create_url,
            data=form_data,
            timeout=20,
        )
        create_response.raise_for_status()
        created = _parse_solvecaptcha_response(create_response)
    except Exception as exc:
        _diagnostic_event(
            out,
            "solvecaptcha_create_error",
            solver_started,
            solver="solvecaptcha",
            errorType=type(exc).__name__,
        )
        raise
    write_json(
        out / "solvecaptcha_create_response.json",
        _redacted_solvecaptcha_response(created),
    )
    task_id = str(created.get("request") or "").strip()
    create_status = int(created.get("status") or 0)
    _diagnostic_event(
        out,
        "solvecaptcha_create_response",
        solver_started,
        solver="solvecaptcha",
        httpStatus=int(create_response.status_code),
        providerStatus=create_status,
        hasTaskId=bool(task_id and create_status == 1),
        responseKeys=sorted(str(key) for key in created.keys()),
    )
    if create_status != 1 or not task_id:
        _diagnostic_event(
            out,
            "solvecaptcha_create_failed",
            solver_started,
            solver="solvecaptcha",
            providerStatus=create_status,
            errorCodePresent=bool(task_id),
        )
        raise RuntimeError(f"SolveCaptcha 创建任务失败：{task_id or '未知错误'}")
    LOG.info("SolveCaptcha 任务已创建，blob 长度=%s", len(blob))

    deadline = time.monotonic() + float(args.solvecaptcha_timeout)
    polls = 0
    last: dict[str, Any] = {}
    last_status = ""
    while time.monotonic() < deadline:
        polls += 1
        try:
            result_response = session.post(
                args.solvecaptcha_result_url,
                data={
                    "key": str(args.solvecaptcha_key).strip(),
                    "action": "get",
                    "id": task_id,
                    "json": 1,
                },
                timeout=15,
            )
            result_response.raise_for_status()
            last = _parse_solvecaptcha_response(result_response)
        except Exception as exc:
            _diagnostic_event(
                out,
                "solvecaptcha_poll_error",
                solver_started,
                solver="solvecaptcha",
                poll=polls,
                errorType=type(exc).__name__,
            )
            raise
        status = int(last.get("status") or 0)
        request_value = str(last.get("request") or "").strip()
        status_text = str(status)
        if status_text != last_status or polls == 1 or polls % 10 == 0:
            _diagnostic_event(
                out,
                "solvecaptcha_poll",
                solver_started,
                solver="solvecaptcha",
                poll=polls,
                httpStatus=int(result_response.status_code),
                providerStatus=status,
                notReady=request_value.upper()
                in {"CAPCHA_NOT_READY", "CAPTCHA_NOT_READY"},
            )
            last_status = status_text
        if status == 1:
            token = request_value
            write_json(
                out / "solvecaptcha_result.json",
                _redacted_solvecaptcha_response(last, token_response=True),
            )
            if not token:
                _diagnostic_event(
                    out,
                    "solvecaptcha_ready_without_token",
                    solver_started,
                    solver="solvecaptcha",
                    poll=polls,
                )
                raise RuntimeError("SolveCaptcha 已返回成功，但缺少 token")
            _diagnostic_event(
                out,
                "solvecaptcha_ready",
                solver_started,
                solver="solvecaptcha",
                poll=polls,
                tokenPresent=True,
                tokenLength=len(token),
                tokenSha256=_diagnostic_digest(token),
            )
            return {
                "ok": True,
                "token": token,
                "actions": [],
                "provider": "solvecaptcha",
                "proxyMode": task_mode,
                "proxyModeRequested": args.capmonster_proxy_mode,
                "taskId": task_id,
                "polls": polls,
            }
        if request_value.upper() not in {
            "CAPCHA_NOT_READY",
            "CAPTCHA_NOT_READY",
            "",
        }:
            write_json(
                out / "solvecaptcha_result.json",
                _redacted_solvecaptcha_response(last),
            )
            _diagnostic_event(
                out,
                "solvecaptcha_failed",
                solver_started,
                solver="solvecaptcha",
                poll=polls,
                providerStatus=status,
                errorCodePresent=True,
            )
            raise RuntimeError(f"SolveCaptcha 任务失败：{request_value}")
        time.sleep(float(args.solvecaptcha_poll_interval))
    write_json(
        out / "solvecaptcha_result.json",
        _redacted_solvecaptcha_response(last),
    )
    _diagnostic_event(
        out,
        "solvecaptcha_timeout",
        solver_started,
        solver="solvecaptcha",
        poll=polls,
        lastProviderStatus=str(last.get("request") or ""),
    )
    raise TimeoutError(
        f"SolveCaptcha 任务 {task_id} 在 {args.solvecaptcha_timeout} 秒后超时"
    )


def _ezcaptcha_proxy_value(proxy: v4.ProxySettings) -> str:
    """Convert a route to EzCaptcha's ``scheme:host:port:user:password`` form."""

    if not proxy.enabled:
        return ""
    parsed = urlsplit(str(proxy.url or ""))
    proxy_type = str(proxy.scheme or parsed.scheme or "http").lower()
    if proxy_type == "socks5h":
        proxy_type = "socks5"
    if proxy_type not in {"http", "https", "socks4", "socks5"}:
        raise ValueError(f"EzCaptcha 不支持此代理协议: {proxy_type}")
    address = str(proxy.host or parsed.hostname or "").strip()
    port = int(proxy.port or parsed.port or 0)
    if not address or not 1 <= port <= 65535:
        raise ValueError("所选代理没有有效的地址和端口")
    value = f"{proxy_type}:{address}:{port}"
    if parsed.username is not None:
        value += f":{unquote(parsed.username)}:{unquote(parsed.password or '')}"
    return value


def solve_with_ezcaptcha(
    context: Mapping[str, Any],
    args: argparse.Namespace,
    out: Path,
    proxy: v4.ProxySettings,
) -> dict[str, Any]:
    """Create and poll an EzCaptcha Arkose Labs FunCaptcha task."""

    solver_started = time.perf_counter()
    blob = str(context.get("blob") or "")
    site_key = str(context.get("siteKey") or v4.DEFAULT_SITE_KEY)
    surl = str(context.get("surl") or v4.DEFAULT_SURL)
    website_url = str(context.get("websiteURL") or args.entry_url)
    requested_proxy = str(args.capmonster_proxy_mode).lower() == "proxy"
    use_proxy = requested_proxy and proxy.enabled
    surl_host = _diagnostic_host(surl)
    task: dict[str, Any] = {
        "type": "FuncaptchaTaskProxyless",
        "websiteURL": website_url,
        "websiteKey": site_key,
    }
    if blob:
        task["data"] = json.dumps({"blob": blob}, separators=(",", ":"))
    if surl_host and surl_host != "client-api.arkoselabs.com":
        task["funcaptchaApiJSSubdomain"] = surl_host
    task_mode = "proxy" if use_proxy else "proxyless"
    if use_proxy:
        task["proxy"] = _ezcaptcha_proxy_value(proxy)

    LOG.info(
        "EzCaptcha 任务：类型=%s，模式=%s，线路=%s",
        task["type"],
        task_mode,
        proxy.display if use_proxy else "EzCaptcha 自身网络",
    )
    _diagnostic_event(
        out,
        "ezcaptcha_create_start",
        solver_started,
        solver="ezcaptcha",
        taskType=task["type"],
        proxyMode=task_mode,
        proxyConfigured=bool(use_proxy),
        blobLength=len(blob),
        blobSha256=_diagnostic_digest(blob),
        siteKeySha256=_diagnostic_digest(site_key),
        surlHost=surl_host,
        websiteHost=_diagnostic_host(website_url),
    )

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    client_key = str(args.ezcaptcha_key).strip()
    try:
        create_response = session.post(
            args.ezcaptcha_create_url,
            json={"clientKey": client_key, "task": task},
            timeout=20,
        )
        create_response.raise_for_status()
        created = create_response.json()
    except Exception as exc:
        _diagnostic_event(
            out,
            "ezcaptcha_create_error",
            solver_started,
            solver="ezcaptcha",
            errorType=type(exc).__name__,
        )
        raise
    if not isinstance(created, Mapping):
        raise RuntimeError("EzCaptcha 创建任务返回了非对象 JSON")
    created = dict(created)
    write_json(
        out / "ezcaptcha_create_response.json",
        _redacted_provider_response(created),
    )
    error_id = int(created.get("errorId") or 0)
    task_id = str(created.get("taskId") or "").strip()
    _diagnostic_event(
        out,
        "ezcaptcha_create_response",
        solver_started,
        solver="ezcaptcha",
        httpStatus=int(create_response.status_code),
        providerErrorId=error_id,
        hasTaskId=bool(task_id),
        responseKeys=sorted(str(key) for key in created.keys()),
    )
    if error_id or not task_id:
        _diagnostic_event(
            out,
            "ezcaptcha_create_failed",
            solver_started,
            solver="ezcaptcha",
            providerErrorId=error_id,
            errorCodePresent=bool(created.get("errorCode")),
        )
        raise RuntimeError(
            f"EzCaptcha 创建任务失败：错误代码={created.get('errorCode')}，"
            f"错误说明={created.get('errorDescription')}"
        )
    LOG.info("EzCaptcha 任务已创建，blob 长度=%s", len(blob))

    deadline = time.monotonic() + float(args.ezcaptcha_timeout)
    polls = 0
    last: dict[str, Any] = {}
    last_status = ""
    while time.monotonic() < deadline:
        polls += 1
        try:
            result_response = session.post(
                args.ezcaptcha_result_url,
                json={"clientKey": client_key, "taskId": task_id},
                timeout=15,
            )
            result_response.raise_for_status()
            payload = result_response.json()
        except Exception as exc:
            _diagnostic_event(
                out,
                "ezcaptcha_poll_error",
                solver_started,
                solver="ezcaptcha",
                poll=polls,
                errorType=type(exc).__name__,
            )
            raise
        if not isinstance(payload, Mapping):
            raise RuntimeError("EzCaptcha 轮询返回了非对象 JSON")
        last = dict(payload)
        status = str(last.get("status") or "").lower()
        error_id = int(last.get("errorId") or 0)
        if status != last_status or polls == 1 or polls % 10 == 0:
            _diagnostic_event(
                out,
                "ezcaptcha_poll",
                solver_started,
                solver="ezcaptcha",
                poll=polls,
                httpStatus=int(result_response.status_code),
                providerStatus=status,
                providerErrorId=error_id,
            )
            last_status = status
        if error_id or status == "error":
            write_json(
                out / "ezcaptcha_result.json",
                _redacted_provider_response(last),
            )
            _diagnostic_event(
                out,
                "ezcaptcha_failed",
                solver_started,
                solver="ezcaptcha",
                poll=polls,
                providerStatus=status,
                providerErrorId=error_id,
                errorCodePresent=bool(last.get("errorCode")),
            )
            raise RuntimeError(
                f"EzCaptcha 任务失败：错误代码={last.get('errorCode')}，"
                f"错误说明={last.get('errorDescription')}"
            )
        if status == "ready":
            solution = last.get("solution")
            token = str(
                solution.get("token")
                if isinstance(solution, Mapping)
                else ""
            ).strip()
            write_json(
                out / "ezcaptcha_result.json",
                _redacted_provider_response(last),
            )
            if not token:
                _diagnostic_event(
                    out,
                    "ezcaptcha_ready_without_token",
                    solver_started,
                    solver="ezcaptcha",
                    poll=polls,
                )
                raise RuntimeError("EzCaptcha 已返回 ready，但缺少 solution.token")
            _diagnostic_event(
                out,
                "ezcaptcha_ready",
                solver_started,
                solver="ezcaptcha",
                poll=polls,
                tokenPresent=True,
                tokenLength=len(token),
                tokenSha256=_diagnostic_digest(token),
            )
            return {
                "ok": True,
                "token": token,
                "actions": [],
                "provider": "ezcaptcha",
                "taskType": task["type"],
                "proxyMode": task_mode,
                "proxyModeRequested": args.capmonster_proxy_mode,
                "taskId": task_id,
                "polls": polls,
            }
        if status not in {"", "processing"}:
            write_json(
                out / "ezcaptcha_result.json",
                _redacted_provider_response(last),
            )
            raise RuntimeError(f"EzCaptcha 返回未知状态：{status}")
        time.sleep(float(args.ezcaptcha_poll_interval))
    write_json(
        out / "ezcaptcha_result.json",
        _redacted_provider_response(last),
    )
    _diagnostic_event(
        out,
        "ezcaptcha_timeout",
        solver_started,
        solver="ezcaptcha",
        poll=polls,
        lastProviderStatus=str(last.get("status") or ""),
    )
    raise TimeoutError(
        f"EzCaptcha 任务 {task_id} 在 {args.ezcaptcha_timeout} 秒后超时"
    )


def solve_with_capmonster(
    context: Mapping[str, Any],
    args: argparse.Namespace,
    out: Path,
    proxy: v4.ProxySettings,
) -> dict[str, Any]:
    solver_started = time.perf_counter()
    blob = str(context.get("blob") or "")
    site_key = str(context.get("siteKey") or v4.DEFAULT_SITE_KEY)
    surl = str(context.get("surl") or v4.DEFAULT_SURL)
    website_url = str(context.get("websiteURL") or args.entry_url)
    user_agent = str(
        args.protocol_user_agent
        or context.get("userAgent")
        or DEFAULT_WINDOWS_USER_AGENT
    )
    requested_proxy = str(args.capmonster_proxy_mode).lower() == "proxy"
    use_proxy = requested_proxy and proxy.enabled
    task: dict[str, Any] = {
        "type": "FunCaptchaTask" if use_proxy else "FunCaptchaTaskProxyless",
        "websiteURL": website_url,
        "websitePublicKey": site_key,
        "userAgent": user_agent,
    }
    if blob:
        task["data"] = json.dumps({"blob": blob}, separators=(",", ":"))
    if surl and surl != "client-api.arkoselabs.com":
        task["funcaptchaApiJSSubdomain"] = surl
    if use_proxy:
        task.update(_capmonster_proxy_fields(proxy))
    task_mode = "proxy" if use_proxy else "proxyless"
    route_note = (
        proxy.display
        if use_proxy
        else (
            "CapMonster 无代理模式（注册线路为直连）"
            if requested_proxy
            else "CapMonster 无代理模式（已明确选择）"
        )
    )
    LOG.info(
        "CapMonster 任务：类型=%s，模式=%s，线路=%s",
        task["type"],
        task_mode,
        route_note,
    )
    _diagnostic_event(
        out,
        "capmonster_create_start",
        solver_started,
        solver="capmonster",
        taskType=task["type"],
        proxyMode=task_mode,
        proxyConfigured=bool(use_proxy),
        blobLength=len(blob),
        blobSha256=_diagnostic_digest(blob),
        siteKeySha256=_diagnostic_digest(site_key),
        surlHost=_diagnostic_host(surl),
        websiteHost=_diagnostic_host(website_url),
        userAgentSha256=_diagnostic_digest(user_agent),
    )

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    try:
        create_response = session.post(
            args.capmonster_create_url,
            json={"clientKey": str(args.capmonster_key).strip(), "task": task},
            timeout=20,
        )
    except Exception as exc:
        _diagnostic_event(
            out,
            "capmonster_create_error",
            solver_started,
            solver="capmonster",
            errorType=type(exc).__name__,
        )
        raise
    try:
        create_response.raise_for_status()
        created = create_response.json()
    except Exception as exc:
        _diagnostic_event(
            out,
            "capmonster_create_invalid_response",
            solver_started,
            solver="capmonster",
            httpStatus=int(create_response.status_code),
            errorType=type(exc).__name__,
        )
        raise
    write_json(out / "capmonster_create_response.json", _redacted_provider_response(created))
    task_id = created.get("taskId")
    _diagnostic_event(
        out,
        "capmonster_create_response",
        solver_started,
        solver="capmonster",
        httpStatus=int(create_response.status_code),
        providerErrorId=int(created.get("errorId") or 0),
        errorCodePresent=bool(created.get("errorCode")),
        hasTaskId=bool(task_id),
        responseKeys=sorted(str(key) for key in created.keys()),
    )
    if not task_id or int(created.get("errorId") or 0):
        _diagnostic_event(
            out,
            "capmonster_create_failed",
            solver_started,
            solver="capmonster",
            providerErrorId=int(created.get("errorId") or 0),
            errorCodePresent=bool(created.get("errorCode")),
        )
        raise RuntimeError(
            f"CapMonster 创建任务失败：错误代码={created.get('errorCode')}，"
            f"错误说明={created.get('errorDescription')}"
        )
    LOG.info("CapMonster 任务已创建：任务 ID=%s，blob 长度=%s", task_id, len(blob))

    deadline = time.monotonic() + float(args.capmonster_timeout)
    polls = 0
    last: dict[str, Any] = {}
    last_status = ""
    while time.monotonic() < deadline:
        polls += 1
        try:
            response = session.post(
                args.capmonster_result_url,
                json={"clientKey": str(args.capmonster_key).strip(), "taskId": task_id},
                timeout=15,
            )
        except Exception as exc:
            _diagnostic_event(
                out,
                "capmonster_poll_error",
                solver_started,
                solver="capmonster",
                poll=polls,
                errorType=type(exc).__name__,
            )
            raise
        try:
            response.raise_for_status()
            last = response.json()
        except Exception as exc:
            _diagnostic_event(
                out,
                "capmonster_poll_invalid_response",
                solver_started,
                solver="capmonster",
                poll=polls,
                httpStatus=int(response.status_code),
                errorType=type(exc).__name__,
            )
            raise
        status = str(last.get("status") or "")
        if status != last_status or polls == 1 or polls % 10 == 0:
            _diagnostic_event(
                out,
                "capmonster_poll",
                solver_started,
                solver="capmonster",
                poll=polls,
                httpStatus=int(response.status_code),
                providerStatus=status,
                providerErrorId=int(last.get("errorId") or 0),
                errorCodePresent=bool(last.get("errorCode")),
            )
            last_status = status
        if status == "ready":
            token = str((last.get("solution") or {}).get("token") or "")
            write_json(
                out / "capmonster_result.json",
                _redacted_provider_response(last),
            )
            if not token:
                _diagnostic_event(
                    out,
                    "capmonster_ready_without_token",
                    solver_started,
                    solver="capmonster",
                    poll=polls,
                )
                raise RuntimeError("CapMonster 已返回 ready，但缺少 solution.token")
            _diagnostic_event(
                out,
                "capmonster_ready",
                solver_started,
                solver="capmonster",
                poll=polls,
                tokenPresent=True,
                tokenLength=len(token),
                tokenSha256=_diagnostic_digest(token),
            )
            return {
                "ok": True,
                "token": token,
                "actions": [],
                "provider": "capmonster",
                "taskType": task["type"],
                "proxyMode": task_mode,
                "proxyModeRequested": args.capmonster_proxy_mode,
                "taskId": task_id,
                "polls": polls,
            }
        if int(last.get("errorId") or 0) or status in {"error", "failed"}:
            write_json(
                out / "capmonster_result.json",
                _redacted_provider_response(last),
            )
            _diagnostic_event(
                out,
                "capmonster_failed",
                solver_started,
                solver="capmonster",
                poll=polls,
                providerStatus=status,
                providerErrorId=int(last.get("errorId") or 0),
                errorCodePresent=bool(last.get("errorCode")),
            )
            raise RuntimeError(
                f"CapMonster 任务失败：错误代码={last.get('errorCode')}，"
                f"错误说明={last.get('errorDescription')}"
            )
        time.sleep(float(args.capmonster_poll_interval))
    write_json(out / "capmonster_result.json", _redacted_provider_response(last))
    _diagnostic_event(
        out,
        "capmonster_timeout",
        solver_started,
        solver="capmonster",
        poll=polls,
        lastProviderStatus=str(last.get("status") or ""),
    )
    raise TimeoutError(
        f"CapMonster 任务 {task_id} 在 {args.capmonster_timeout} 秒后超时"
    )


def solve_with_twocaptcha(
    context: Mapping[str, Any],
    args: argparse.Namespace,
    out: Path,
    proxy: v4.ProxySettings,
) -> dict[str, Any]:
    """Create and poll a 2Captcha Arkose Labs FunCaptcha task."""

    solver_started = time.perf_counter()
    blob = str(context.get("blob") or "")
    site_key = str(context.get("siteKey") or v4.DEFAULT_SITE_KEY)
    surl = str(context.get("surl") or v4.DEFAULT_SURL)
    website_url = str(context.get("websiteURL") or args.entry_url)
    user_agent = str(
        args.protocol_user_agent
        or context.get("userAgent")
        or DEFAULT_WINDOWS_USER_AGENT
    )
    requested_proxy = str(args.capmonster_proxy_mode).lower() == "proxy"
    use_proxy = requested_proxy and proxy.enabled
    task: dict[str, Any] = {
        "type": "FunCaptchaTask" if use_proxy else "FunCaptchaTaskProxyless",
        "websiteURL": website_url,
        "websitePublicKey": site_key,
        "userAgent": user_agent,
    }
    if blob:
        task["data"] = json.dumps({"blob": blob}, separators=(",", ":"))
    surl_host = _diagnostic_host(surl)
    if surl_host and surl_host != "client-api.arkoselabs.com":
        task["funcaptchaApiJSSubdomain"] = surl_host
    if use_proxy:
        task.update(_twocaptcha_proxy_fields(proxy))
    task_mode = "proxy" if use_proxy else "proxyless"
    LOG.info(
        "2Captcha 任务：类型=%s，模式=%s，线路=%s",
        task["type"],
        task_mode,
        proxy.display if use_proxy else "2Captcha 自身网络",
    )
    _diagnostic_event(
        out,
        "twocaptcha_create_start",
        solver_started,
        solver="twocaptcha",
        taskType=task["type"],
        proxyMode=task_mode,
        proxyConfigured=bool(use_proxy),
        blobLength=len(blob),
        blobSha256=_diagnostic_digest(blob),
        siteKeySha256=_diagnostic_digest(site_key),
        surlHost=surl_host,
        websiteHost=_diagnostic_host(website_url),
        userAgentSha256=_diagnostic_digest(user_agent),
    )

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    try:
        create_response = session.post(
            args.twocaptcha_create_url,
            json={"clientKey": str(args.twocaptcha_key).strip(), "task": task},
            timeout=20,
        )
        create_response.raise_for_status()
        created = create_response.json()
    except Exception as exc:
        _diagnostic_event(
            out,
            "twocaptcha_create_error",
            solver_started,
            solver="twocaptcha",
            errorType=type(exc).__name__,
        )
        raise
    if not isinstance(created, Mapping):
        raise RuntimeError("2Captcha 创建任务返回了非对象 JSON")
    write_json(
        out / "twocaptcha_create_response.json",
        _redacted_provider_response(created),
    )
    task_id = created.get("taskId")
    if not task_id or int(created.get("errorId") or 0):
        _diagnostic_event(
            out,
            "twocaptcha_create_failed",
            solver_started,
            solver="twocaptcha",
            providerErrorId=int(created.get("errorId") or 0),
            errorCodePresent=bool(created.get("errorCode")),
        )
        raise RuntimeError(
            f"2Captcha 创建任务失败：错误代码={created.get('errorCode')}，"
            f"错误说明={created.get('errorDescription')}"
        )
    _diagnostic_event(
        out,
        "twocaptcha_create_response",
        solver_started,
        solver="twocaptcha",
        httpStatus=int(create_response.status_code),
        providerErrorId=int(created.get("errorId") or 0),
        hasTaskId=True,
        responseKeys=sorted(str(key) for key in created.keys()),
    )

    deadline = time.monotonic() + float(args.twocaptcha_timeout)
    polls = 0
    last: dict[str, Any] = {}
    last_status = ""
    while time.monotonic() < deadline:
        polls += 1
        try:
            response = session.post(
                args.twocaptcha_result_url,
                json={
                    "clientKey": str(args.twocaptcha_key).strip(),
                    "taskId": task_id,
                },
                timeout=15,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            _diagnostic_event(
                out,
                "twocaptcha_poll_error",
                solver_started,
                solver="twocaptcha",
                poll=polls,
                errorType=type(exc).__name__,
            )
            raise
        if not isinstance(payload, Mapping):
            raise RuntimeError("2Captcha 轮询返回了非对象 JSON")
        last = dict(payload)
        status = str(last.get("status") or "")
        if status != last_status or polls == 1 or polls % 10 == 0:
            _diagnostic_event(
                out,
                "twocaptcha_poll",
                solver_started,
                solver="twocaptcha",
                poll=polls,
                httpStatus=int(response.status_code),
                providerStatus=status,
                providerErrorId=int(last.get("errorId") or 0),
                errorCodePresent=bool(last.get("errorCode")),
            )
            last_status = status
        if status == "ready":
            token = str((last.get("solution") or {}).get("token") or "")
            write_json(
                out / "twocaptcha_result.json",
                _redacted_provider_response(last),
            )
            if not token:
                _diagnostic_event(
                    out,
                    "twocaptcha_ready_without_token",
                    solver_started,
                    solver="twocaptcha",
                    poll=polls,
                )
                raise RuntimeError("2Captcha 已返回 ready，但缺少 solution.token")
            _diagnostic_event(
                out,
                "twocaptcha_ready",
                solver_started,
                solver="twocaptcha",
                poll=polls,
                tokenPresent=True,
                tokenLength=len(token),
                tokenSha256=_diagnostic_digest(token),
            )
            return {
                "ok": True,
                "token": token,
                "actions": [],
                "provider": "2captcha",
                "taskType": task["type"],
                "proxyMode": task_mode,
                "proxyModeRequested": args.capmonster_proxy_mode,
                "taskId": task_id,
                "polls": polls,
            }
        if int(last.get("errorId") or 0) or status in {"error", "failed"}:
            write_json(
                out / "twocaptcha_result.json",
                _redacted_provider_response(last),
            )
            _diagnostic_event(
                out,
                "twocaptcha_failed",
                solver_started,
                solver="twocaptcha",
                poll=polls,
                providerStatus=status,
                providerErrorId=int(last.get("errorId") or 0),
                errorCodePresent=bool(last.get("errorCode")),
            )
            raise RuntimeError(
                f"2Captcha 任务失败：错误代码={last.get('errorCode')}，"
                f"错误说明={last.get('errorDescription')}"
            )
        time.sleep(float(args.twocaptcha_poll_interval))
    write_json(
        out / "twocaptcha_result.json",
        _redacted_provider_response(last),
    )
    _diagnostic_event(
        out,
        "twocaptcha_timeout",
        solver_started,
        solver="twocaptcha",
        poll=polls,
        lastProviderStatus=str(last.get("status") or ""),
    )
    raise TimeoutError(
        f"2Captcha 任务 {task_id} 在 {args.twocaptcha_timeout} 秒后超时"
    )


def diagnose_captcha_submission_context(
    client: BattleProtocolClient,
    context: Mapping[str, Any],
    token: str,
) -> dict[str, Any]:
    """Validate local Arkose/token invariants without persisting secrets."""

    def host(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
        return str(parsed.hostname or "").lower()

    context_blob = str(context.get("blob") or "")
    site_key = str(context.get("siteKey") or "")
    surl = str(context.get("surl") or "")
    website_url = str(context.get("websiteURL") or "")
    token_value = str(token or "")
    entry_url = str(getattr(client, "entry_url", "") or "")
    entry_host = host(entry_url)
    form = getattr(client, "form", None)
    form_action = str(getattr(form, "action", "") or "") if form else ""
    form_step = str(getattr(form, "step", "") or "") if form else ""
    form_csrf = str(getattr(form, "csrf", "") or "") if form else ""

    state = getattr(getattr(client, "state", None), "data", {}) or {}
    state_arkose = state.get("arkose") if isinstance(state, Mapping) else {}
    if not isinstance(state_arkose, Mapping):
        state_arkose = {}
    state_blob = str(state_arkose.get("blob") or "")
    state_site_key = str(state_arkose.get("siteKey") or "")
    state_surl = str(state_arkose.get("surl") or "")
    state_website_url = str(state_arkose.get("websiteURL") or "")
    state_status = (
        str(state.get("status") or "") if isinstance(state, Mapping) else ""
    )

    checks = {
        "token_present": bool(token_value),
        "token_has_no_outer_whitespace": bool(token_value)
        and token_value == token_value.strip(),
        "blob_present": bool(context_blob),
        "blob_minimum_length": len(context_blob) >= 80,
        "site_key_present": bool(site_key),
        "surl_present": bool(surl),
        "website_url_host_matches_entry": bool(entry_host)
        and host(website_url) == entry_host,
        "form_present": form is not None,
        "form_step_is_captcha_gate": form_step == "captcha-gate",
        "form_action_host_matches_entry": bool(entry_host)
        and host(form_action) == entry_host,
        "csrf_present": bool(form_csrf),
        "state_status_compatible": state_status in {"captcha-gate", "token-ready"},
        "state_blob_matches": bool(state_blob) and state_blob == context_blob,
        "state_site_key_matches": bool(state_site_key)
        and state_site_key == site_key,
        "state_surl_matches": bool(state_surl) and state_surl == surl,
        "state_website_url_matches": bool(state_website_url)
        and state_website_url == website_url,
    }
    issues = [name for name, passed in checks.items() if not passed]
    fingerprint_material = "\x1f".join(
        (context_blob, site_key, surl, website_url, form_action, form_csrf)
    )
    return {
        "version": 1,
        "ok": not issues,
        "issues": issues,
        "checks": checks,
        "entryURLHost": entry_host,
        "websiteURLHost": host(website_url),
        "formAction": form_action,
        "formStep": form_step,
        "formControlNames": sorted(
            {
                str(control.name)
                for control in (getattr(form, "controls", ()) if form else ())
                if str(control.name or "")
            }
        ),
        "formControlCount": len(getattr(form, "controls", ()) if form else ()),
        "stateStatus": state_status,
        "siteKey": site_key,
        "surl": surl,
        "blobLength": len(context_blob),
        "blobSha256": hashlib.sha256(context_blob.encode("utf-8")).hexdigest()
        if context_blob
        else "",
        "tokenLength": len(token_value),
        "tokenSha256": hashlib.sha256(token_value.encode("utf-8")).hexdigest()
        if token_value
        else "",
        "contextFingerprint": hashlib.sha256(
            fingerprint_material.encode("utf-8")
        ).hexdigest(),
    }


def _install_cloak_resource_filter(page: Any, enabled: bool) -> None:
    if not enabled:
        return

    def route_handler(route: Any, request: Any) -> None:
        url = str(getattr(request, "url", "") or "")
        resource_type = str(getattr(request, "resource_type", "") or "")
        if (
            resource_type in {"font", "media"}
            or v4.should_block_resource(url)
            or should_block_tracking_resource(url)
        ):
            route.abort()
        else:
            route.continue_()

    page.context.route("**/*", route_handler)


class V5RuyiYesCaptchaImageCatcher(v4.v3.RuyiArkoseImageCatcher):
    """V4-compatible catcher that accepts compact Arkose RTIG strips."""

    def wait_new_challenge(
        self,
        seen: set[str],
        timeout: float,
        stop_page: Any = None,
    ) -> Optional[dict[str, Any]]:
        deadline = time.time() + max(0.0, float(timeout))
        while time.time() < deadline:
            if stop_page is not None:
                with contextlib.suppress(Exception):
                    if v4.base.captcha_state(stop_page) in ("success", "rejected"):
                        return None
            with self._lock:
                ready = [
                    dict(record)
                    for record in self.captured_images
                    if record.get("body_bytes")
                ]
            ready.sort(
                key=lambda record: (
                    0
                    if "/rtig/image" in str(record.get("url") or "").lower()
                    else 1,
                    record.get("timestamp") or 0,
                )
            )
            for record in ready:
                data = record.get("body_bytes") or b""
                sha = record.get("sha256") or hashlib.sha256(data).hexdigest()
                if sha in seen:
                    continue
                size = record.get("size") or v4.v3.image_size(data)
                if size:
                    width, height = size
                    is_rtig = "/rtig/image" in str(
                        record.get("url") or ""
                    ).lower()
                    valid_rtig = is_rtig and 300 <= height <= 650
                    valid_generic = width >= 800 and 300 <= height <= 650
                    if not valid_rtig and not valid_generic:
                        seen.add(sha)
                        LOG.info(
                            "[%s] 忽略非题目图片：尺寸=%sx%s，网址=%s",
                            self.label,
                            width,
                            height,
                            str(record.get("url") or "")[:120],
                        )
                        continue
                return record
            self._event.wait(0.5)
            self._event.clear()
        return None


def save_yescaptcha_image_record(
    record: dict[str, Any],
    out_dir: Path,
    wave: int,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = record.get("body_bytes") or b""
    sha = record.get("sha256") or hashlib.sha256(data).hexdigest()
    extension = v4.v3.image_ext(record.get("mime") or "", data)
    path = out_dir / f"yescaptcha_wave_{wave:02d}_{sha[:12]}{extension}"
    path.write_bytes(data)
    metadata = {
        key: value for key, value in record.items() if key != "body_bytes"
    }
    metadata.update({"file": str(path), "sha256": sha, "bytes": len(data)})
    write_json(
        out_dir / f"yescaptcha_wave_{wave:02d}_{sha[:12]}.json",
        metadata,
    )
    return path


_TERMINAL_SOLVER_STATUSES = frozenset(
    {
        "onFailed",
        "onError",
        "run-error",
        "setConfig-error",
        "script-error",
    }
)


def solver_terminal_reason(page: Any) -> str:
    state = v4.v3.solver_state(page)
    status = str(state.get("status") or "").strip()
    completed = state.get("completedPayload")
    rejection = v4.v3.completion_rejection_reason(completed)
    if rejection:
        return f"Arkose 完成结果被拒绝：{rejection}"
    if status in _TERMINAL_SOLVER_STATUSES:
        detail = str(state.get("error") or "").strip()
        suffix = f": {detail}" if detail else ""
        return f"Arkose 求解器已进入终止状态：{status}{suffix}"
    if v4.base.captcha_state(page) == "rejected":
        return "Arkose 验证页面已被拒绝"
    return ""


def wait_image_or_token_fast(
    catcher: Any,
    seen: set[str],
    timeout: float,
    solver_tab: Any,
) -> tuple[str, Any]:
    deadline = time.time() + max(0.0, float(timeout))
    while time.time() < deadline:
        token = v4.v3.wait_token_quick(solver_tab, 0.1)
        if token:
            return "token", token
        terminal = solver_terminal_reason(solver_tab)
        if terminal:
            return "terminal", terminal
        remaining = max(0.05, deadline - time.time())
        record = catcher.wait_new_challenge(
            seen,
            timeout=min(0.7, remaining),
            stop_page=solver_tab,
        )
        if record:
            return "image", record
    token = v4.v3.wait_token_quick(solver_tab, 0.2)
    if token:
        return "token", token
    terminal = solver_terminal_reason(solver_tab)
    if terminal:
        return "terminal", terminal
    return "timeout", None


def click_next_n_v4(page: Any, count: int, args: argparse.Namespace) -> bool:
    count = max(0, int(count))
    LOG.info("点击下一张箭头 %s 次", count)
    minimum = max(0, int(args.click_interval_min_ms))
    maximum = max(minimum, int(args.click_interval_max_ms))
    for index in range(count):
        delay = random.randint(minimum, maximum) / 1000.0
        LOG.info(
            "等待 %s 毫秒后点击第 %s/%s 张箭头",
            round(delay * 1000),
            index + 1,
            count,
        )
        time.sleep(delay)
        clicked = False
        for attempt in range(3):
            before = v4.v3.current_index(page)
            if not v4.v3.click_arrow(page, "right", timeout=4):
                return False
            after = v4.v3.wait_index_change(page, before)
            if before < 0 or after != before:
                LOG.info(
                    "第 %s/%s 次点击成功：点击前=%s，点击后=%s",
                    index + 1,
                    count,
                    before,
                    after,
                )
                clicked = True
                break
            LOG.warning(
                "第 %s/%s 次点击可能未生效：重试=%s，"
                "点击前=%s，点击后=%s",
                index + 1,
                count,
                attempt + 1,
                before,
                after,
            )
        if not clicked:
            return False
    return True


def auto_solve_yescaptcha_tab(
    solver_tab: Any,
    catcher: Any,
    args: argparse.Namespace,
    out: Path,
) -> dict[str, Any]:
    """Use the verified local V4 per-wave YesCaptcha state machine."""

    api_key = str(args.yescaptcha_key or "").strip()
    if not api_key:
        raise RuntimeError("YesCaptcha API 密钥为空")
    images_dir = out / "yescaptcha_images"
    actions: list[dict[str, Any]] = []
    seen: set[str] = set()

    token = v4.v3.wait_token_quick(solver_tab, 2.0, "initial ")
    if token:
        return v4.v3.build_token_result(solver_tab, token, actions)
    if not v4.v3.ensure_verify_or_image(
        solver_tab,
        catcher,
        args.verify_timeout,
    ):
        LOG.warning("点击验证后尚未确认题目图片，继续等待")

    for wave in range(args.max_waves):
        token = v4.v3.wait_token_quick(solver_tab, 1.0, f"wave{wave} pre ")
        if token:
            return v4.v3.build_token_result(solver_tab, token, actions)
        terminal = solver_terminal_reason(solver_tab)
        if terminal:
            return {"ok": False, "error": terminal, "actions": actions}

        kind, value = wait_image_or_token_fast(
            catcher,
            seen,
            args.first_image_timeout if wave == 0 else args.next_image_timeout,
            solver_tab,
        )
        if kind == "token":
            return v4.v3.build_token_result(solver_tab, str(value), actions)
        if kind == "terminal":
            return {"ok": False, "error": str(value), "actions": actions}
        record = value
        if not record:
            token = v4.v3.wait_token_quick(
                solver_tab,
                args.after_submit_token_wait,
                f"wave{wave} no-image ",
            )
            if token:
                return v4.v3.build_token_result(solver_tab, token, actions)
            state = v4.base.captcha_state(solver_tab)
            sample = v4.base.captcha_text(solver_tab).replace("\n", " ")[:260]
            return {
                "ok": False,
                "error": f"第 {wave} 轮没有新题图，状态={state}",
                "actions": actions,
                "sample": sample,
            }

        data = record.get("body_bytes") or b""
        sha = record.get("sha256") or hashlib.sha256(data).hexdigest()
        seen.add(sha)
        image_path = save_yescaptcha_image_record(record, images_dir, wave)
        if args.debug_screenshots:
            v4.base.screenshot(
                solver_tab,
                out / "solver_screenshots" / f"wave_{wave:02d}_before_answer.png",
            )

        question = v5_yescaptcha_solver.extract_dynamic_prompt(
            solver_tab,
            v4.base.all_contexts,
            timeout=min(5.0, max(0.5, float(args.yescaptcha_timeout))),
        )
        write_json(
            images_dir / f"yescaptcha_wave_{wave:02d}_question.json",
            question,
        )
        answer, api_result = v5_yescaptcha_solver.classify_image(
            image_path,
            question=question["prompt"],
            api_key=api_key,
            api_url=args.yescaptcha_api_url,
            timeout=args.yescaptcha_timeout,
            response_path=(
                images_dir / f"yescaptcha_wave_{wave:02d}_response.json"
            ),
        )
        retries = int(api_result.get("retries") or 0)
        if retries:
            reasons = ",".join(
                str(item) for item in (api_result.get("reasons") or [])
            ) or "unknown"
            LOG.info(
                "YesCaptcha 同图恢复：轮次=%s，重试=%s，"
                "原因=%s，重新编码=%s",
                wave,
                retries,
                reasons,
                bool(api_result.get("imageReencoded")),
            )
        LOG.info(
            "YesCaptcha 答案=%s，轮次=%s，题目=%r",
            answer,
            wave,
            question["prompt"],
        )
        if not click_next_n_v4(solver_tab, answer, args):
            return {
                "ok": False,
                "error": f"第 {wave} 轮无法点击下一张 {answer} 次",
                "actions": actions,
            }
        time.sleep(0.08 + random.random() * 0.08)
        submit_ok = v4.v3.click_submit(solver_tab)
        action = {
            "wave": wave,
            "image": str(image_path),
            "sha256": sha,
            "answer": answer,
            "clicks": answer,
            "submit": submit_ok,
            "question": question,
            "yescaptcha": api_result,
        }
        actions.append(action)
        write_json(out / "yescaptcha_actions_latest.json", actions)
        if args.debug_screenshots:
            v4.base.screenshot(
                solver_tab,
                out / "solver_screenshots" / f"wave_{wave:02d}_after_submit.png",
            )
        if not submit_ok:
            state = v4.base.captcha_state(solver_tab)
            return {
                "ok": False,
                "error": f"submit button failed at wave={wave}, state={state}",
                "actions": actions,
            }
        token = v4.v3.wait_token_quick(
            solver_tab,
            args.after_submit_token_wait,
            f"wave{wave} post ",
        )
        if token:
            return v4.v3.build_token_result(solver_tab, token, actions)

    token = v4.v3.wait_token_quick(solver_tab, args.token_timeout, "final ")
    if token:
        return v4.v3.build_token_result(solver_tab, token, actions)
    return {
        "ok": False,
        "error": f"max_waves exceeded ({args.max_waves}) without token",
        "actions": actions,
    }


def _launch_solver_browser(
    args: argparse.Namespace,
    proxy: v4.ProxySettings,
    runtime_proxy_url: Optional[str],
) -> tuple[Any, Any, Optional[Any]]:
    if args.browser == "ruyipage":
        page = v4.launch_ruyi_browser(args, proxy, runtime_proxy_url)
        catcher_type = (
            V5RuyiYesCaptchaImageCatcher
            if args.solver == "yescaptcha"
            else v4.v3.RuyiArkoseImageCatcher
        )
        catcher = catcher_type(page, label=f"v5-{args.solver}")
        optimizer = v4.BrowserResourceOptimizer(
            page,
            Path(args.static_cache_dir),
            proxy_enabled=proxy.enabled,
            direct_public_static=(proxy.enabled and not args.no_direct_public_static),
            direct_challenge_images=(proxy.enabled and args.direct_challenge_images),
            block_nonessential=not args.no_resource_blocking,
            fetch_timeout=args.static_fetch_timeout,
            max_entry_bytes=max(1, int(args.static_cache_max_entry_mib * v4.MIB)),
            should_block=lambda url: (
                v4.should_block_resource(url)
                or should_block_tracking_resource(url)
            ),
        )
        optimizer.start()
        return page, catcher, optimizer

    page = launch_cloak_page(
        headless=bool(args.headless),
        proxy=runtime_proxy_url,
        locale=args.cloak_locale,
    )
    _install_cloak_resource_filter(page, not args.no_resource_blocking)
    catcher = CloakArkoseImageCatcher(page, label=f"v5-{args.solver}")
    return page, catcher, None


def _recover_missing_blob(
    client: BattleProtocolClient,
    args: argparse.Namespace,
    proxy: v4.ProxySettings,
    out: Path,
    runtime_proxy_url: Optional[str],
) -> dict[str, Any]:
    if args.browser == "ruyipage":
        recovery_page = v4.launch_ruyi_browser(args, proxy, runtime_proxy_url)
        try:
            return v4.recover_blob_with_ruyi(recovery_page, client, args, out)
        finally:
            with contextlib.suppress(Exception):
                recovery_page.quit()

    recovery_page = launch_cloak_page(
        headless=bool(args.headless),
        proxy=runtime_proxy_url,
        locale=args.cloak_locale,
    )
    catcher = CloakArkoseBlobCatcher(recovery_page)
    try:
        cookies = client.playwright_cookies()
        recovery_page.set_cookies(cookies)
        write_json(
            out / "solver" / "cookie_import_summary.json",
            {"count": len(cookies), "names": sorted({item["name"] for item in cookies})},
        )
        catcher.start()
        recovery_page.get(args.entry_url, wait="interactive", timeout=45)
        recovery_page.stop_loading()
        blob = catcher.wait_for_blob(timeout=min(12.0, args.blob_timeout))
        if not blob:
            v4.base.click_arkose_verify(recovery_page, timeout=12)
            blob = catcher.wait_for_blob(timeout=args.blob_timeout)
        if not blob:
            raise RuntimeError("CloakBrowser 恢复流程未取得 Arkose blob")
        detected = v4.base.detect_arkose_context(recovery_page, catcher)
        return {
            "blob": blob,
            "siteKey": detected.get("siteKey") or v4.DEFAULT_SITE_KEY,
            "surl": detected.get("surl") or v4.DEFAULT_SURL,
            "websiteURL": args.entry_url,
            "userAgent": detected.get("userAgent"),
            "source": "cloakbrowser-cookie-import-playwright",
        }
    finally:
        with contextlib.suppress(Exception):
            catcher.stop()
        with contextlib.suppress(Exception):
            recovery_page.quit()


def solve_with_browser(
    client: BattleProtocolClient,
    context: Mapping[str, Any],
    args: argparse.Namespace,
    proxy: v4.ProxySettings,
    out: Path,
    runtime_proxy_url: Optional[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    current = dict(context)
    if not current.get("blob"):
        LOG.info("HTTP 响应没有 blob，启用 V4 Cookie 导入恢复流程")
        current = _recover_missing_blob(
            client, args, proxy, out, runtime_proxy_url
        )
    current["siteKey"] = str(current.get("siteKey") or v4.DEFAULT_SITE_KEY)
    current["surl"] = str(current.get("surl") or v4.DEFAULT_SURL)
    current["websiteURL"] = str(current.get("websiteURL") or args.entry_url)
    write_json(out / "arkose_context.json", v4.public_arkose_context(current))

    page = None
    catcher = None
    optimizer = None
    try:
        page, catcher, optimizer = _launch_solver_browser(
            args, proxy, runtime_proxy_url
        )
        catcher.start()
        harness = v4.base.build_solver_harness(
            current["siteKey"], str(current["blob"]), current["surl"]
        )
        origin = v4.replace_document_low_traffic(
            page, current["websiteURL"], harness
        )
        write_json(out / "solver" / "origin.json", origin)
        if args.debug_screenshots:
            v4.base.screenshot(
                page, out / "solver_screenshots" / "harness_loaded.png"
            )

        if args.browser == "cloakbrowser":
            # The shared V2/V3 helpers use JS fallback clicks on Playwright.
            v4.v3.CLICK_STYLE = "js"
        if args.solver == "v11":
            result = v4.run_v4_solver_tab(page, catcher, args, out)
            result_file = out / "local_v11_solver_result.json"
        else:
            result = auto_solve_yescaptcha_tab(page, catcher, args, out)
            result_file = out / "yescaptcha_solver_result.json"
        write_json(
            result_file,
            {key: value for key, value in result.items() if key != "token"},
        )
        if not result.get("ok") or not result.get("token"):
            raise RuntimeError(
                str(result.get("error") or f"{args.solver} 未返回 token")
            )
        with contextlib.suppress(Exception):
            catcher.stop()
        catcher = None
        if optimizer is not None:
            result["browserTraffic"] = v4.stop_browser_optimizer(optimizer, out)
            optimizer = None
        else:
            result["browserTraffic"] = {
                "enabled": True,
                "adapter": "cloakbrowser-playwright",
            }
        return result, current
    finally:
        with contextlib.suppress(Exception):
            if catcher:
                catcher.stop()
        with contextlib.suppress(Exception):
            if optimizer:
                v4.stop_browser_optimizer(optimizer, out)
        if args.keep_open and page is not None:
            with contextlib.suppress(EOFError):
                input("Solver browser is open. Press Enter to close...")
        with contextlib.suppress(Exception):
            if page:
                page.quit()


def resolve_resume_path(value: str) -> Path:
    return v4.resolve_resume_path(value)


def main() -> int:
    force_utf8_stdio()
    args = build_parser().parse_args()
    email_credential: Optional[EmailCredential] = None
    if args.email_source == "pool":
        email_credential = select_email_credential(
            args.email_pool_file, args.email_pool_index
        )
        if args.email and str(args.email).strip().casefold() != email_credential.email.casefold():
            raise ValueError("--email 与邮箱池分配结果不一致")
        args.email = email_credential.email
    v4.configure_v3_clicks(args)
    config = validate_configuration(args)
    registration_country = str(config["registrationCountry"])
    resume_path = resolve_resume_path(args.resume) if args.resume else None
    out = (
        resume_path.parent
        if resume_path is not None
        else Path(args.output_dir).expanduser().resolve() / run_id()
    )
    out.mkdir(parents=True, exist_ok=True)
    args.output_dir = str(out)
    setup_logging(out / "run.log")

    state: Optional[PersistentFlowState] = None
    client: Optional[BattleProtocolClient] = None
    identity: dict[str, str] = {}
    proxy = v4.ProxySettings(None, "direct")
    traffic_meter: Optional[ProxyTrafficMeter] = None
    traffic_snapshots: dict[str, dict[str, Any]] = {}
    runtime_proxy_url: Optional[str] = None
    submission_diagnosis: Optional[dict[str, Any]] = None
    registration_started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    diagnostic_phase = "initialization"
    capmonster_user_agent_info: dict[str, Any] = {
        "source": "not-applicable",
        "length": 0,
        "sha256": "",
    }
    try:
        proxy = v4.parse_proxy(args.proxy)
        if resume_path is not None:
            state = PersistentFlowState.load(resume_path)
            saved_profile = dict(state.data.get("profile") or {})
            saved_country = str(
                saved_profile.get("registrationCountry") or ""
            ).strip().upper()
            if saved_country:
                registration_country = saved_country
                config["registrationCountry"] = saved_country
            identity = {
                key: str(value)
                for key, value in dict(state.data.get("identity") or {}).items()
            }
            if not all(identity.get(key) for key in ("email", "password", "battle_tag")):
                raise RuntimeError("恢复状态中没有完整账号信息")
            if (
                email_credential is not None
                and identity.get("email", "").casefold()
                != email_credential.email.casefold()
            ):
                raise RuntimeError("恢复状态中的邮箱与邮箱池分配结果不一致")
            LOG.info(
                "恢复持久状态：%s，状态=%s",
                resume_path,
                state.data.get("status"),
            )
        else:
            identity = v4.configured_identity(args)
            state = PersistentFlowState.create(
                out / "persistent_state.json",
                identity=identity,
                profile={
                    "mode": "persistent-http-v5",
                    "solver": args.solver,
                    "browser": args.browser,
                    "registrationCountry": registration_country,
                    "emailSource": args.email_source,
                    "emailCredential": (
                        email_credential.public_summary()
                        if email_credential is not None
                        else None
                    ),
                    "countryProbe": bool(args.country_probe),
                    "proxy": proxy.summary(),
                    "proxyTrafficMeter": bool(proxy.enabled),
                    "proxyDirectHosts": list(config["proxyDirectHosts"]),
                    "publicStaticDirect": bool(
                        proxy.enabled and not args.no_direct_public_static
                    ),
                    "challengeImageDirect": bool(
                        proxy.enabled and args.direct_challenge_images
                    ),
                    "protocolImpersonate": args.protocol_impersonate,
                },
            )
        capmonster_user_agent_info = apply_capmonster_user_agent(
            args,
            out,
            args.capmonster_user_agent_url,
        )
        config["capmonsterUserAgent"] = dict(capmonster_user_agent_info)
        write_json(out / "account_generated.json", identity)
        write_json(out / "v5_configuration.json", config)
        LOG.info("输出目录：%s", out)
        LOG.info(
            "诊断时间线：%s",
            (out / "diagnostic_trace.jsonl").resolve(),
        )
        LOG.info(
            "流程：持久 HTTP -> %s/%s -> HTTP captcha-gate",
            args.browser,
            args.solver,
        )
        LOG.info("注册国家：%s", registration_country)
        LOG.info("代理线路：%s，身份验证=%s", proxy.display, proxy.has_auth)
        LOG.info(
            "静态资源分流：%s",
            (
                ", ".join(config["proxyDirectHosts"])
                if config["proxyDirectHosts"]
                else "关闭"
            )
            if proxy.enabled
            else "无需分流（注册网络为直连）",
        )
        LOG.info("账号：%s", identity["email"])
        LOG.info("战网昵称：%s", identity["battle_tag"])
        diagnostic_phase = "configured"
        _diagnostic_event(
            out,
            "run_configured",
            started,
            solver=args.solver,
            browser=args.browser,
            registrationCountry=registration_country,
            emailSource=args.email_source,
            proxyEnabled=bool(proxy.enabled),
            proxyHasAuth=bool(proxy.has_auth),
            resumed=bool(resume_path is not None),
            capmonsterUserAgentSource=capmonster_user_agent_info["source"],
            capmonsterUserAgentLength=capmonster_user_agent_info["length"],
            capmonsterUserAgentSha256=capmonster_user_agent_info["sha256"],
        )

        if state.data.get("status") == "complete":
            LOG.info("持久状态已经完成")
            _diagnostic_event(
                out,
                "already_complete",
                started,
                stateStatus=str(state.data.get("status") or ""),
            )
            print(f"账号：{identity['email']}")
            print(f"密码：{identity['password']}")
            print(f"战网昵称：{identity.get('battle_tag', '')}")
            return 0

        runtime_proxy_url = proxy.url
        if proxy.enabled and proxy.url:
            diagnostic_phase = "proxy_meter"
            _diagnostic_event(
                out,
                "proxy_meter_start",
                started,
                proxyEnabled=True,
                directHosts=list(config["proxyDirectHosts"]),
            )
            traffic_meter = ProxyTrafficMeter(
                proxy.url,
                direct_hosts=config["proxyDirectHosts"],
            )
            runtime_proxy_url = traffic_meter.start()
            LOG.info(
                "代理流量计已启动：本地=%s，上游=%s",
                runtime_proxy_url,
                proxy.display,
            )
            traffic_snapshots["start"] = v4.capture_proxy_traffic_snapshot(
                traffic_meter
            )
            _diagnostic_event(
                out,
                "proxy_meter_ready",
                started,
                localProxyConfigured=bool(runtime_proxy_url),
            )

        diagnostic_phase = "protocol_flow"
        client = BattleProtocolClient(
            state,
            out,
            entry_url=args.entry_url,
            proxy=runtime_proxy_url,
            impersonate=args.protocol_impersonate,
            user_agent=args.protocol_user_agent or None,
            accept_language="en-GB,en;q=0.9",
            timeout=args.protocol_timeout,
        )
        _diagnostic_event(
            out,
            "protocol_start",
            started,
            entryHost=_diagnostic_host(args.entry_url),
            stateStatus=str(state.data.get("status") or ""),
            formStep=str(getattr(client.form, "step", "") or "") if client.form else "",
            timeoutSeconds=float(args.protocol_timeout),
        )
        if state.data.get("status") not in {"captcha-gate", "token-ready"}:
            try:
                client.run_to_captcha(
                    country=registration_country,
                    opt_in=False,
                    country_probe=bool(args.country_probe),
                )
            except BaseException as exc:
                _emit_protocol_history(out, client, started)
                _diagnostic_event(
                    out,
                    "protocol_error",
                    started,
                    errorType=type(exc).__name__,
                    **_protocol_diagnostic_snapshot(client),
                )
                raise
        _emit_protocol_history(out, client, started)
        _diagnostic_event(
            out,
            "protocol_ready",
            started,
            **_protocol_diagnostic_snapshot(client),
        )
        LOG.info("持久 HTTP 流程已到达 captcha-gate")
        arkose = dict(state.data.get("arkose") or {})
        if not arkose.get("blob"):
            arkose = client.recover_arkose_from_last_response()
        arkose["siteKey"] = str(arkose.get("siteKey") or v4.DEFAULT_SITE_KEY)
        arkose["surl"] = str(arkose.get("surl") or v4.DEFAULT_SURL)
        arkose["websiteURL"] = str(
            arkose.get("websiteURL") or args.entry_url
        )
        traffic_snapshots["captchaGate"] = v4.capture_proxy_traffic_snapshot(
            traffic_meter
        )
        LOG.info(
            "Arkose 上下文：来源=%s，站点密钥=%s，blob 长度=%s",
            arkose.get("source"),
            arkose.get("siteKey"),
            len(str(arkose.get("blob") or "")),
        )
        _diagnostic_event(
            out,
            "captcha_context_ready",
            started,
            source=str(arkose.get("source") or ""),
            blobLength=len(str(arkose.get("blob") or "")),
            blobSha256=_diagnostic_digest(arkose.get("blob")),
            siteKeySha256=_diagnostic_digest(arkose.get("siteKey")),
            surlHost=_diagnostic_host(arkose.get("surl")),
            websiteHost=_diagnostic_host(arkose.get("websiteURL")),
            **_protocol_diagnostic_snapshot(client),
        )

        token = (
            str(arkose.get("token") or "")
            if state.data.get("status") == "token-ready"
            else ""
        )
        health: dict[str, Any]
        diagnostic_phase = "captcha_solver"
        solver_started = time.perf_counter()
        _diagnostic_event(
            out,
            "solver_start",
            started,
            solver=args.solver,
            browser=args.browser,
            resumedToken=bool(token),
            capmonsterProxyMode=(
                args.capmonster_proxy_mode
                if args.solver in {
                    "capmonster",
                    "twocaptcha",
                    "solvecaptcha",
                    "ezcaptcha",
                }
                else "not-applicable"
            ),
        )
        try:
            if token:
                health = {"ok": True, "status": "not-required-resumed-token"}
                solve_result = {
                    "ok": True,
                    "token": token,
                    "actions": [],
                    "resumedToken": True,
                }
            elif args.solver == "capmonster":
                health = {"ok": True, "status": "external-provider"}
                solve_result = solve_with_capmonster(arkose, args, out, proxy)
                token = str(solve_result["token"])
            elif args.solver == "twocaptcha":
                health = {"ok": True, "status": "external-provider"}
                solve_result = solve_with_twocaptcha(arkose, args, out, proxy)
                token = str(solve_result["token"])
            elif args.solver == "solvecaptcha":
                health = {"ok": True, "status": "external-provider"}
                solve_result = solve_with_solvecaptcha(arkose, args, out, proxy)
                token = str(solve_result["token"])
            elif args.solver == "ezcaptcha":
                health = {"ok": True, "status": "external-provider"}
                solve_result = solve_with_ezcaptcha(arkose, args, out, proxy)
                token = str(solve_result["token"])
            else:
                if args.solver == "v11":
                    health = v4.wait_rank_v11_service(
                        args.rank_v11_url, args.rank_v11_timeout
                    )
                    write_json(out / "rank_v11_health.json", health)
                    LOG.info(
                        "本地 V11 已就绪：设备=%s，加载=%.3f 秒，预热=%.3f 秒",
                        health.get("device"),
                        float(health.get("model_load_seconds") or 0.0),
                        float(health.get("warmup_seconds") or 0.0),
                    )
                else:
                    health = {"ok": True, "status": "external-classifier"}
                solve_result, arkose = solve_with_browser(
                    client,
                    arkose,
                    args,
                    proxy,
                    out,
                    runtime_proxy_url,
                )
                token = str(solve_result["token"])
        except BaseException as exc:
            _diagnostic_event(
                out,
                "solver_error",
                started,
                solver=args.solver,
                errorType=type(exc).__name__,
                solverElapsedMs=round((time.perf_counter() - solver_started) * 1000, 1),
            )
            raise
        _diagnostic_event(
            out,
            "solver_ready",
            started,
            solver=args.solver,
            provider=str(solve_result.get("provider") or args.solver),
            tokenPresent=bool(token),
            tokenLength=len(token),
            tokenSha256=_diagnostic_digest(token),
            solverElapsedMs=round((time.perf_counter() - solver_started) * 1000, 1),
            providerStatus=str(solve_result.get("status") or ""),
            polls=solve_result.get("polls"),
        )

        arkose["token"] = token
        state.checkpoint(
            "token-ready",
            arkose=arkose,
            event={
                "completed": f"{args.browser}-{args.solver}",
                "tokenLength": len(token),
            },
        )
        LOG.info("求解器已返回 Arkose 令牌，长度=%s", len(token))
        traffic_snapshots["tokenReady"] = v4.capture_proxy_traffic_snapshot(
            traffic_meter
        )

        submission_diagnosis = diagnose_captcha_submission_context(
            client,
            arkose,
            token,
        )
        write_json(
            out / "captcha_submission_diagnosis.json",
            submission_diagnosis,
        )
        LOG.info(
            "提交前上下文诊断：ok=%s，blob_sha256=%s，token_sha256=%s，问题=%s",
            submission_diagnosis["ok"],
            submission_diagnosis["blobSha256"][:12],
            submission_diagnosis["tokenSha256"][:12],
            ",".join(submission_diagnosis["issues"]) or "无",
        )
        _diagnostic_event(
            out,
            "captcha_precheck",
            started,
            ok=bool(submission_diagnosis["ok"]),
            issueCount=len(submission_diagnosis["issues"]),
            issues=list(submission_diagnosis["issues"]),
            formStep=str(submission_diagnosis.get("formStep") or ""),
            formControlCount=submission_diagnosis.get("formControlCount"),
            stateStatus=str(submission_diagnosis.get("stateStatus") or ""),
            blobLength=submission_diagnosis.get("blobLength"),
            blobSha256=str(submission_diagnosis.get("blobSha256") or "")[:16],
            tokenLength=submission_diagnosis.get("tokenLength"),
            tokenSha256=str(submission_diagnosis.get("tokenSha256") or "")[:16],
        )
        if not submission_diagnosis["ok"]:
            raise RuntimeError(
                "Arkose 提交上下文诊断失败："
                + ",".join(submission_diagnosis["issues"])
            )

        diagnostic_phase = "captcha_submit"
        submit_started = time.perf_counter()
        _diagnostic_event(
            out,
            "captcha_submit_start",
            started,
            formStep=str(getattr(client.form, "step", "") or "") if client.form else "",
            formActionHost=_diagnostic_host(getattr(client.form, "action", "") if client.form else ""),
        )
        try:
            outcome = client.submit_captcha(token)
        except BaseException as exc:
            _diagnostic_event(
                out,
                "captcha_submit_error",
                started,
                errorType=type(exc).__name__,
                submitElapsedMs=round((time.perf_counter() - submit_started) * 1000, 1),
                **_protocol_diagnostic_snapshot(client),
            )
            raise
        success = outcome.get("status") == "success" and bool(outcome.get("success"))
        submission_diagnosis["outcome"] = {
            key: outcome.get(key)
            for key in (
                "status",
                "success",
                "httpStatus",
                "stepId",
                "hasExpectedEmail",
                "hasSuccessIcon",
                "hasAllSet",
                "hasCreated",
                "hasDownloadApp",
            )
            if key in outcome
        }
        submission_diagnosis["assessment"] = (
            "accepted"
            if success
            else (
                "server_rejected_after_local_context_pass"
                if outcome.get("status") == "rejected"
                else "submission_not_confirmed"
            )
        )
        submission_diagnosis["serverResponseSignals"] = _server_response_signals(
            outcome
        )
        write_json(
            out / "captcha_submission_diagnosis.json",
            submission_diagnosis,
        )
        LOG.info(
            "提交后上下文诊断：assessment=%s，服务端状态=%s，HTTP=%s",
            submission_diagnosis["assessment"],
            outcome.get("status"),
            outcome.get("httpStatus"),
        )
        _diagnostic_event(
            out,
            "captcha_submit_result",
            started,
            success=bool(success),
            assessment=str(submission_diagnosis["assessment"]),
            serverStatus=str(outcome.get("status") or ""),
            httpStatus=outcome.get("httpStatus"),
            stepId=str(outcome.get("stepId") or ""),
            hasExpectedEmail=bool(outcome.get("hasExpectedEmail")),
            hasSuccessIcon=bool(outcome.get("hasSuccessIcon")),
            hasAllSet=bool(outcome.get("hasAllSet")),
            hasCreated=bool(outcome.get("hasCreated")),
            hasDownloadApp=bool(outcome.get("hasDownloadApp")),
            serverSignals=list(
                submission_diagnosis["serverResponseSignals"].get("labels") or []
            ),
            serverErrorCount=submission_diagnosis["serverResponseSignals"].get(
                "errorCount"
            ),
            serverSampleSha256=str(
                submission_diagnosis["serverResponseSignals"].get("sampleSha256")
                or ""
            ),
            submitElapsedMs=round((time.perf_counter() - submit_started) * 1000, 1),
            **_protocol_diagnostic_snapshot(client),
        )
        email_verification = EmailVerificationResult(
            ok=False,
            status="not_requested",
            note="",
        )
        if success and email_credential is not None:
            email_verification = verify_registered_email(
                email_credential,
                identity["password"],
                args=args,
                proxy=proxy,
                runtime_proxy_url=runtime_proxy_url,
                output_dir=out,
                not_before=registration_started_at,
            )
            write_json(out / "email_verification.json", email_verification.to_dict())
            if email_verification.ok:
                LOG.info("注册邮箱验证完成: %s", identity["email"])
            else:
                LOG.warning(
                    "注册邮箱验证未完成: %s；%s",
                    identity["email"],
                    email_verification.note,
                )
        registration = {
            "ok": success,
            "email": identity["email"],
            "battleTag": identity["battle_tag"],
            "emailSource": args.email_source,
            "emailVerification": email_verification.to_dict(),
            "successSource": "persistent-http-captcha-gate" if success else None,
            "outcome": outcome,
            "captchaSubmissionDiagnosis": submission_diagnosis,
        }
        write_json(out / "registration_result.json", registration)
        write_json(
            out / "summary.json",
            {
                "ok": success,
                "outputDir": str(out),
                "mode": "persistent-http-v5",
                "solver": args.solver,
                "browser": args.browser,
                "capmonsterProxyMode": (
                    str(
                        solve_result.get("proxyMode")
                        or args.capmonster_proxy_mode
                    )
                    if args.solver in {
                        "capmonster",
                        "twocaptcha",
                        "solvecaptcha",
                        "ezcaptcha",
                    }
                    else "not-applicable"
                ),
                "capmonsterProxyModeRequested": (
                    args.capmonster_proxy_mode
                    if args.solver in {
                        "capmonster",
                        "twocaptcha",
                        "solvecaptcha",
                        "ezcaptcha",
                    }
                    else "not-applicable"
                ),
                "capmonsterUserAgent": capmonster_user_agent_info,
                "registrationCountry": registration_country,
                "emailSource": args.email_source,
                "countryProbe": bool(args.country_probe),
                "proxy": proxy.summary(),
                "arkose": v4.public_arkose_context(arkose),
                "solverHealth": health,
                "solverActions": solve_result.get("actions") or [],
                "browserTraffic": solve_result.get("browserTraffic") or {},
                "registration": registration,
                "captchaSubmissionDiagnosis": submission_diagnosis,
                "diagnosticTrace": str((out / "diagnostic_trace.jsonl").resolve()),
                "elapsedSeconds": time.perf_counter() - started,
            },
        )
        if not success:
            assessment = str(
                (submission_diagnosis or {}).get("assessment") or ""
            )
            exit_code = DETERMINISTIC_FAILURE_EXIT_CODES.get(assessment, 1)
            _diagnostic_event(
                out,
                "terminal_failure",
                started,
                assessment=assessment,
                exitCode=exit_code,
                serverStatus=str(outcome.get("status") or ""),
                httpStatus=outcome.get("httpStatus"),
            )
            LOG.error(
                "captcha-gate 未确认注册成功：状态=%s，样例=%r",
                outcome.get("status"),
                outcome.get("sample"),
            )
            return exit_code

        _diagnostic_event(
            out,
            "registration_accepted",
            started,
            assessment=str(submission_diagnosis.get("assessment") or ""),
            serverStatus=str(outcome.get("status") or ""),
            emailVerificationRequested=bool(email_credential is not None),
        )
        LOG.info("已通过持久 HTTP 会话完成注册")
        print(f"账号：{identity['email']}")
        print(f"密码：{identity['password']}")
        print(f"战网昵称：{identity['battle_tag']}")
        if email_credential is not None and email_verification.note:
            print(f"说明：{email_verification.note}")
        return 0
    except KeyboardInterrupt:
        LOG.warning("运行已中断")
        _diagnostic_event(
            out,
            "run_interrupted",
            started,
            currentPhase=diagnostic_phase,
            errorType="KeyboardInterrupt",
            **_protocol_diagnostic_snapshot(client),
        )
        write_json(
            out / "summary.json",
            {
                "ok": False,
                "error": "KeyboardInterrupt",
                "outputDir": str(out),
                "diagnosticTrace": str((out / "diagnostic_trace.jsonl").resolve()),
            },
        )
        return 130
    except Exception as exc:
        error_text = v4.redact_proxy_text(
            f"{type(exc).__name__}: {exc}", proxy, args.proxy
        )
        safe_traceback = v4.redact_proxy_text(
            traceback.format_exc(), proxy, args.proxy
        )
        LOG.error("运行失败：%s\n%s", error_text, safe_traceback)
        with contextlib.suppress(Exception):
            _diagnostic_event(
                out,
                "run_error",
                started,
                currentPhase=diagnostic_phase,
                errorType=type(exc).__name__,
                **_protocol_diagnostic_snapshot(client),
            )
        if state is not None:
            with contextlib.suppress(Exception):
                state.checkpoint(
                    str(state.data.get("status") or "failed"),
                    error=error_text,
                    event={"failed": "runner", "errorType": type(exc).__name__},
                )
        failure = {
            "ok": False,
            "error": error_text,
            "outputDir": str(out),
            "solver": args.solver,
            "browser": args.browser,
            "registrationCountry": registration_country,
            "emailSource": args.email_source,
            "countryProbe": bool(args.country_probe),
            "proxy": proxy.summary(),
            "diagnosticTrace": str((out / "diagnostic_trace.jsonl").resolve()),
            "elapsedSeconds": time.perf_counter() - started,
        }
        if isinstance(exc, v4.v3.UnsupportedCaptchaQuestion):
            failure["unsupportedCaptcha"] = True
            failure["challenge"] = exc.details
        browser_traffic = v4.read_json_object(out / "browser_traffic.json")
        if browser_traffic:
            failure["browserTraffic"] = browser_traffic
        if submission_diagnosis is not None:
            failure["captchaSubmissionDiagnosis"] = submission_diagnosis
        write_json(out / "summary.json", failure)
        return (
            v4.v3.UNSUPPORTED_CAPTCHA_EXIT_CODE
            if isinstance(exc, v4.v3.UnsupportedCaptchaQuestion)
            else 1
        )
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.session.close()
        if traffic_meter is not None:
            with contextlib.suppress(Exception):
                report = traffic_meter.stop()
                v4.write_proxy_traffic_report(out, report)
                phase_report = v4.build_proxy_traffic_phase_report(
                    traffic_snapshots, report
                )
                v4.write_proxy_traffic_phase_report(out, phase_report)
                v4.log_proxy_traffic_phases(phase_report)
                v4.log_proxy_traffic_targets(report)
                LOG.info(
                    "代理总流量：上传=%.4f MiB，下载=%.4f MiB，"
                    "总计=%.4f MiB，字节=%s，连接=%s，失败=%s",
                    float(report.get("uploadMiB") or 0.0),
                    float(report.get("downloadMiB") or 0.0),
                    float(report.get("totalMiB") or 0.0),
                    int(report.get("totalBytes") or 0),
                    int(report.get("connections") or 0),
                    int(report.get("failures") or 0),
                )
                direct = dict(report.get("directBypass") or {})
                if int(direct.get("totalBytes") or 0):
                    LOG.info(
                        "直连分流流量：上传=%.4f MiB，下载=%.4f MiB，"
                        "总计=%.4f MiB，字节=%s，连接=%s，失败=%s",
                        float(direct.get("uploadMiB") or 0.0),
                        float(direct.get("downloadMiB") or 0.0),
                        float(direct.get("totalMiB") or 0.0),
                        int(direct.get("totalBytes") or 0),
                        int(direct.get("connections") or 0),
                        int(direct.get("failures") or 0),
                    )
        with contextlib.suppress(Exception):
            _diagnostic_event(
                out,
                "run_finished",
                started,
                currentPhase=diagnostic_phase,
                stateStatus=(
                    str(state.data.get("status") or "")
                    if state is not None
                    else ""
                ),
                trafficReportPresent=(out / "proxy_traffic.json").is_file(),
                diagnosticTrace=str((out / "diagnostic_trace.jsonl").resolve()),
            )


if __name__ == "__main__":
    raise SystemExit(main())
