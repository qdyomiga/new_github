from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "register-ruyipage-v6.yml"
V5_WORKFLOW = ROOT / ".github" / "workflows" / "register-ruyipage-v5.yml"


@pytest.mark.parametrize("workflow_path", [V5_WORKFLOW, WORKFLOW])
def test_registration_workflows_default_to_yescaptcha_direct(
    workflow_path: Path,
) -> None:
    workflow = yaml.load(
        workflow_path.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]

    assert inputs["solver"]["default"] == "YesCaptcha"
    assert inputs["network"]["default"] == "直连"


def test_v6_workflow_uses_v6_pool_runner_and_output_contract() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert 'EMAIL_POOL_FILE: "Email_registing_v6.txt"' in text
    assert "from v6_email_pool import validate_pool_capacity" in text
    assert "workflow_runner.py register-v6" in text
    assert "V6_EMAIL_POOL_FILE: Email_registing_v6.txt" in text
    assert "from v6_email_pool import remove_consumed_emails" in text
    assert 'Path("Email_registing_v6.txt")' in text
    assert "git add Email_registing_v6.txt" in text
    assert 'f"API：{api_line}"' in text
    assert 'lines.append(f"说明：{note}")' not in text
    assert "V5_EMAIL_POOL_FILE: Email_registing.txt" not in text


def test_v6_workflow_exposes_twocaptcha_secret_and_solver_choice() -> None:
    workflow = yaml.load(
        WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]

    assert "twocaptcha_key" in inputs
    assert "2Captcha" in inputs["solver"]["options"]
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "TWOCAPTCHA_API_KEY" in text
    assert '"2Captcha": "twocaptcha"' in text


def test_v6_workflow_exposes_solvecaptcha_secret_and_solver_choice() -> None:
    workflow = yaml.load(
        WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]

    assert "solvecaptcha_key" in inputs
    assert "SolveCaptcha" in inputs["solver"]["options"]
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "SOLVECAPTCHA_API_KEY" in text
    assert '"SolveCaptcha": "solvecaptcha"' in text


def test_v6_workflow_exposes_ezcaptcha_secret_and_solver_choice() -> None:
    workflow = yaml.load(
        WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]

    assert "ezcaptcha_key" in inputs
    assert "EzCaptcha" in inputs["solver"]["options"]
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "EZCAPTCHA_API_KEY" in text
    assert '"EzCaptcha": "ezcaptcha"' in text


def test_v6_workflow_retains_unique_matrix_allocation_and_serial_pool_runs() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "list(range(1, count + 1))" in text
    assert "V6_EMAIL_POOL_INDEX: ${{ matrix.index }}" in text
    assert "cancel-in-progress: false" in text
    assert "format('V6-待注册邮箱-{0}-{1}'" in text


def test_v6_workflow_supports_optional_email_verification() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "verify_email:" in text
    assert 'default: "是"' in text
    assert 'verify_email_map = {"是": "yes", "否": "no"}' in text
    assert "V6_VERIFY_EMAIL: ${{ needs.prepare.outputs.verify_email }}" in text
    assert '--verify-email "$V6_VERIFY_EMAIL"' in text
    assert "needs.prepare.outputs.verify_email == 'yes'" in text


def test_v6_workflow_repairs_or_rebuilds_invalid_venv_cache() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    deps_steps = workflow["jobs"]["deps-cache"]["steps"]
    build_step = next(
        step for step in deps_steps if step.get("name") == "构建 V6 虚拟环境"
    )
    cache_step = next(
        step for step in deps_steps if step.get("name") == "缓存 V6 虚拟环境"
    )

    assert "v6-" in cache_step["with"]["key"]
    check_step = next(
        step
        for step in deps_steps
        if step.get("name") == "校验 V6 虚拟环境缓存"
    )
    assert check_step["continue-on-error"] is True
    assert "if [ ! -x .venv/bin/python ]" in check_step["run"]
    assert "importlib.util.find_spec" in check_step["run"]
    assert "steps.venv-check.outcome != 'success'" in build_step["if"]
    assert "requirements-ruyipage-v5.txt" in build_step["run"]

    register_steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][
        "register"
    ]["steps"]
    register_check = next(
        step for step in register_steps if step.get("name") == "校验 V6 虚拟环境"
    )
    repair_step = next(
        step for step in register_steps if step.get("name") == "修复缺失的缓存依赖"
    )
    assert register_check["continue-on-error"] is True
    assert "importlib.util.find_spec" in register_check["run"]
    assert "steps.venv-check.outcome != 'success'" in repair_step["if"]
    assert repair_step["env"]["V6_VENV_CHECK"] == "${{ steps.venv-check.outcome }}"
    assert 'rm -rf .venv' in repair_step["run"]


def test_v6_workflow_quarantines_login_form_without_retrying() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert 'if [ "$last_rc" -eq 43 ]; then' in text
    assert "already_registered_email.txt" in text
    assert "already_registered_emails.txt" in text
    assert "pool_removal_emails.txt" in text
    assert 'success_path = Path("pool_removal_emails.txt")' in text


def test_v6_workflow_stops_deterministic_server_rejection_without_retrying() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert 'if [ "$last_rc" -eq 44 ]; then' in text
    assert "服务端已明确拒绝当前提交" in text


def test_v6_workflow_uses_short_solver_arrow_wait() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "--click-gap-min-ms 400" in text
    assert "--click-gap-max-ms 800" in text
    assert "--click-interval-min-ms 400" in text
    assert "--click-interval-max-ms 800" in text


def test_v6_workflow_uploads_pending_email_accounts_only_when_present() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    register_steps = workflow["jobs"]["register"]["steps"]
    export_step = next(
        step for step in register_steps if step.get("name") == "导出成功账号"
    )
    account_upload = next(
        step for step in register_steps if step.get("name") == "上传 V6 账号数据"
    )
    assert "is_email_verification_pending" in export_step["run"]
    assert 'Path("email_pending_account.txt")' in export_step["run"]
    assert "email_pending_account.txt" in account_upload["with"]["path"]

    collect_steps = workflow["jobs"]["collect"]["steps"]
    collect_step = next(
        step for step in collect_steps if step.get("name") == "汇总账号与邮箱状态"
    )
    pending_upload = next(
        step for step in collect_steps if step.get("name") == "上传邮箱待验证账号"
    )
    original_upload = next(
        step for step in collect_steps if step.get("name") == "上传 V6 汇总结果"
    )
    assert "email_pending_account.txt" in collect_step["run"]
    assert 'Path("email_pending_accounts.txt")' in collect_step["run"]
    assert pending_upload["if"] == "${{ hashFiles('email_pending_accounts.txt') != '' }}"
    assert pending_upload["with"]["name"] == "ALL-邮箱待验证"
    assert pending_upload["with"]["path"] == "email_pending_accounts.txt"
    assert "email_pending_accounts.txt" not in original_upload["with"]["path"]


def test_v6_registration_shell_block_has_valid_bash_syntax() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["register"]["steps"]
    script = next(
        step["run"] for step in steps if step.get("name") == "执行 HTTP V6 注册"
    )

    # The exit-43 branch must not use an indented heredoc: Bash parses the whole
    # function before executing it and would reject every job before Python starts.
    exit_43_branch = script.split('if [ "$last_rc" -eq 43 ]; then', 1)[1]
    exit_43_branch = exit_43_branch.split(
        'if [ "$last_rc" -eq 42 ]; then', 1
    )[0]
    assert "<<'PY'" not in exit_43_branch

    candidates = [Path(value) for value in [shutil.which("bash")] if value]
    git = shutil.which("git")
    if git:
        candidates.append(Path(git).resolve().parents[1] / "bin" / "bash.exe")
    bash = None
    for candidate in candidates:
        if not candidate.is_file():
            continue
        probe = subprocess.run(
            [str(candidate), "--version"],
            capture_output=True,
            check=False,
        )
        if probe.returncode == 0 and b"GNU bash" in probe.stdout:
            bash = str(candidate)
            break
    if bash is None:
        pytest.skip("a usable GNU Bash is unavailable on this platform")
    result = subprocess.run(
        [bash, "-n"],
        input=script.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_v6_registration_shell_stops_retry_after_runner_signal() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "trap 'handle_runner_signal" in text
    assert "interrupted_by_runner.txt" in text
    assert 'if [ "$last_rc" -eq 130 ] || [ "$last_rc" -eq 143 ]; then' in text
