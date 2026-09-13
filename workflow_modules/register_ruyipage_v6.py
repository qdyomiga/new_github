# -*- coding: utf-8 -*-
"""V6 entrypoint: V5 registration logic with the V6 email-pool contract."""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

import register_ruyipage_v5 as v5
import v6_email_pool
import v6_email_verifier


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "ruyipage_http_v6_register" / "runs"
_V5_BUILD_PARSER = v5.build_parser
_V5_VERIFY_REGISTERED_EMAIL = v6_email_verifier.verify_registered_email
_V5_RUN_TO_CAPTCHA = v5.BattleProtocolClient.run_to_captcha
EXIT_EMAIL_ALREADY_REGISTERED = 43
EXIT_CAPTCHA_SERVER_REJECTED = 44


def _map_v6_environment() -> None:
    """Expose V6 settings to the unchanged V5 parser implementation."""
    for suffix in (
        "SOLVER",
        "BROWSER",
        "COUNTRY",
        "EMAIL_SOURCE",
        "EMAIL_POOL_FILE",
        "EMAIL_POOL_INDEX",
        "EMAIL_BROWSER_CACHE_DIR",
        "VERIFY_EMAIL",
        "CAPMONSTER_PROXY_MODE",
        "CAPMONSTER_USER_AGENT_URL",
        "PROXY_DIRECT_HOSTS",
        "STATIC_CACHE_DIR",
        "USER_AGENT",
    ):
        source = f"V6_{suffix}"
        target = f"V5_{suffix}"
        if source in os.environ:
            os.environ[target] = os.environ[source]
    if "V6_TWOCAPTCHA_API_KEY" in os.environ:
        os.environ["TWOCAPTCHA_API_KEY"] = os.environ["V6_TWOCAPTCHA_API_KEY"]
    if "V6_SOLVECAPTCHA_API_KEY" in os.environ:
        os.environ["SOLVECAPTCHA_API_KEY"] = os.environ["V6_SOLVECAPTCHA_API_KEY"]
    if "V6_EZCAPTCHA_API_KEY" in os.environ:
        os.environ["EZCAPTCHA_API_KEY"] = os.environ["V6_EZCAPTCHA_API_KEY"]


def _setup_v6_logging(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    formatter = logging.Formatter("%(asctime)s [HTTP-V6] %(message)s", "%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(stream)
    root.addHandler(file_handler)
    for name in ("urllib3", "PIL"):
        logging.getLogger(name).setLevel(logging.WARNING)


def _build_parser_v6():
    parser = _V5_BUILD_PARSER()
    parser.description = "V5 持久 HTTP 注册逻辑 + V6 指定邮箱输入"
    for action in parser._actions:
        if action.dest == "email_source":
            action.help = (
                "generated or one deterministic row from "
                "Email_registing_v6.txt"
            )
            break
    verify_email_default = os.environ.get(
        "V6_VERIFY_EMAIL",
        os.environ.get("V5_VERIFY_EMAIL", "yes"),
    ).strip().lower()
    if verify_email_default not in {"yes", "no"}:
        verify_email_default = "yes"
    parser.add_argument(
        "--verify-email",
        choices=("yes", "no"),
        default=verify_email_default,
        help="注册后验证指定邮箱（默认：是）",
    )
    return parser


def _verify_registered_email_v6(
    credential: v6_email_pool.EmailCredential,
    account_password: str,
    **kwargs,
):
    """Feed the V6 source fields to the unchanged V5 mailbox verifier."""
    args = kwargs.get("args")
    if str(getattr(args, "verify_email", "yes")).strip().lower() == "no":
        v5.LOG.info("V6 已按工作流设置跳过注册邮箱验证")
        return v5.EmailVerificationResult(
            ok=True,
            status="skipped",
            note="",
        )
    return _V5_VERIFY_REGISTERED_EMAIL(
        credential.to_v5(),
        account_password,
        **kwargs,
    )


def _is_already_registered_bootstrap_error(exc: BaseException) -> bool:
    """Recognize localized bootstrap login-form responses for a supplied address."""
    message = str(exc)
    return bool(
        re.search(
            r"(?:bootstrap ended on unexpected form|引导流程结束在意外表单)"
            r"\s+['\"]login['\"]",
            message,
            flags=re.IGNORECASE,
        )
    )


def _run_to_captcha_v6(self, *args, **kwargs):
    """Give an already-registered mailbox a terminal, non-retryable exit code."""
    try:
        return _V5_RUN_TO_CAPTCHA(self, *args, **kwargs)
    except RuntimeError as exc:
        if not _is_already_registered_bootstrap_error(exc):
            raise
        identity = getattr(getattr(self, "state", None), "data", {}).get(
            "identity", {}
        )
        email = str(identity.get("email") or "")
        v5.LOG.warning(
            "bootstrap 返回 login 表单，判定邮箱已注册%s；停止当前 Job 的后续重试",
            f": {email}" if email else "",
        )
        raise SystemExit(EXIT_EMAIL_ALREADY_REGISTERED) from None


def _install_v6_contract() -> None:
    # V5's default behavior remains unchanged. Runtime globals are replaced only
    # inside this V6 process, so registration, solver and verification logic are
    # exactly the V5 implementation while credential parsing and V6 retry
    # classification use V6 semantics.
    v5.DEFAULT_OUTPUT_ROOT = DEFAULT_OUTPUT_ROOT
    v5.build_parser = _build_parser_v6
    v5.EmailCredential = v6_email_pool.EmailCredential
    v5.select_email_credential = v6_email_pool.select_email_credential
    v5.verify_registered_email = _verify_registered_email_v6
    v5.BattleProtocolClient.run_to_captcha = _run_to_captcha_v6
    v5.setup_logging = _setup_v6_logging
    v5.DETERMINISTIC_FAILURE_EXIT_CODES = {
        "server_rejected_after_local_context_pass": EXIT_CAPTCHA_SERVER_REJECTED,
    }


def _selected_api_line() -> str:
    args = v5.build_parser().parse_args()
    if args.email_source != "pool":
        return ""
    return v6_email_pool.select_email_credential(
        args.email_pool_file, args.email_pool_index
    ).raw_line


def main() -> int:
    _map_v6_environment()
    _install_v6_contract()
    api_line = _selected_api_line()
    exit_code = v5.main()
    if exit_code == 0 and api_line:
        print(f"API：{api_line}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
