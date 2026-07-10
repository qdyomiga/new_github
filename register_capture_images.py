# -*- coding: utf-8 -*-
"""Battle.net FunCaptcha image capture runner.

This is a data-collection variant. It does NOT solve captcha and does NOT use
CapMonster. It drives the registration flow until Arkose appears, clicks Verify,
then repeatedly clicks the captcha Submit button with random/current answers so
that Arkose loads more images. CDPImageCatcher saves every browser-loaded image.
"""

import logging
import os
import time

from captcha_image_collector import CDPImageCatcher, collect_captcha_images, zip_capture_dir
from register import (
    REGISTER_URL,
    COUNTRY,
    CDP_DEBUG_PORT,
    create_cloak_browser,
    generate_identity,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("captcha_capture")

CAPTCHA_RANDOM_SUBMITS = int(os.environ.get("CAPTCHA_RANDOM_SUBMITS", "12"))
CAPTCHA_OUTPUT_DIR = os.environ.get("CAPTCHA_OUTPUT_DIR", "captcha_images")


def wait_or_refresh(page, selector: str, desc: str, timeout: int = 25):
    try:
        page.wait_for_selector(selector, timeout=timeout * 1000)
        logger.info("ready: %s", desc)
        return page.locator(selector).first
    except Exception:
        logger.warning("timeout waiting for %s, reload and retry", desc)
        page.reload()
        time.sleep(5)
        page.wait_for_selector(selector, timeout=timeout * 1000)
        return page.locator(selector).first


def fill_birthday(page, acc):
    page.locator('[name="dob-plain"]').click()
    time.sleep(0.8)
    page.evaluate(
        """
        ([year, month, day]) => {
            var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
            var c = document.querySelector('#dob-field-active');
            if (!c) return;
            c.querySelectorAll('input').forEach(function(inp){
                var cls = inp.className || '';
                if (cls.indexOf('--yyyy') !== -1) setter.call(inp, year);
                else if (cls.indexOf('--mm') !== -1) setter.call(inp, month);
                else if (cls.indexOf('--dd') !== -1) setter.call(inp, day);
                inp.dispatchEvent(new Event('input', {bubbles:true}));
                inp.dispatchEvent(new Event('change', {bubbles:true}));
            });
        }
        """,
        [acc["birth_year"], acc["birth_month"], acc["birth_day"]],
    )


def close_cookie_banner(page):
    try:
        cookie_btn = page.locator('button#onetrust-reject-all-handler, button.ot-reject-all, button[id*="reject"]')
        if cookie_btn.count() > 0 and cookie_btn.first.is_visible():
            cookie_btn.first.click(timeout=3000)
            time.sleep(0.3)
    except Exception:
        pass


def run_capture(acc) -> bool:
    browser = None
    image_catcher = None
    try:
        browser, context, page = create_cloak_browser()
        logger.info("open: %s", REGISTER_URL)
        page.goto(REGISTER_URL, wait_until="domcontentloaded")
        time.sleep(2)
        close_cookie_banner(page)

        logger.info("step email: %s", acc["email"])
        page.locator("#accountName").fill(acc["email"])
        page.locator("#submit").click()
        time.sleep(2)

        wait_or_refresh(page, "#capture-country", "country selector")
        page.reload()
        time.sleep(3)
        wait_or_refresh(page, "#capture-country", "country selector after reload")
        page.select_option("#capture-country", COUNTRY)
        time.sleep(1.5)

        close_cookie_banner(page)
        logger.info("step birthday: %s-%s-%s", acc["birth_year"], acc["birth_month"], acc["birth_day"])
        fill_birthday(page, acc)
        time.sleep(0.5)
        page.locator("#flow-form-submit-btn").click()
        time.sleep(2)

        logger.info("step name: %s %s", acc["first_name"], acc["last_name"])
        try:
            page.wait_for_selector("#capture-first-name", timeout=8000)
        except Exception:
            page.reload()
            time.sleep(5)
            page.wait_for_selector("#capture-first-name", timeout=10000)
        page.locator("#capture-first-name").fill(acc["first_name"])
        page.locator("#capture-last-name").fill(acc["last_name"])
        time.sleep(0.5)
        page.locator("#flow-form-submit-btn").click()
        time.sleep(2)

        actual_email = page.locator("#capture-email").input_value()
        if actual_email != acc["email"]:
            logger.error("email mismatch: %s", actual_email)
            page.screenshot(path="error_email.png")
            return False
        page.locator("#flow-form-submit-btn").click()
        time.sleep(2)

        logger.info("step legal checkboxes")
        page.evaluate(
            """() => {
                ['#capture-opt-in-blizzard-news-special-offers','#legal-checkboxes > label > input.step__checkbox'].forEach(function(sel){
                    var el = document.querySelector(sel);
                    if (el && !el.checked) {
                        var s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'checked').set;
                        s.call(el, true);
                        el.dispatchEvent(new Event('change', {bubbles:true}));
                        el.dispatchEvent(new Event('input', {bubbles:true}));
                    }
                });
            }"""
        )
        time.sleep(0.5)
        page.locator("#flow-form-submit-btn").click()
        time.sleep(2)

        logger.info("step password")
        wait_or_refresh(page, "#capture-password", "password input")
        page.locator("#capture-password").fill(acc["password"])
        time.sleep(0.5)
        page.locator("#flow-form-submit-btn").click()
        time.sleep(2)

        logger.info("step battletag: %s", acc["battle_tag"])
        wait_or_refresh(page, "#capture-battletag", "BattleTag input")
        page.evaluate(
            """
            ([elId, val]) => {
                var el = document.querySelector(elId);
                var s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                s.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
            }
            """,
            ["#capture-battletag", acc["battle_tag"]],
        )
        time.sleep(0.5)
        try:
            page.wait_for_function(
                '() => { const btn = document.querySelector("#flow-form-submit-btn"); return btn && !btn.disabled; }',
                timeout=5000,
            )
        except Exception:
            logger.warning("submit button enable wait timeout")

        image_catcher = CDPImageCatcher(debug_port=CDP_DEBUG_PORT, label=str(os.environ.get("MATRIX_INDEX", "1")))
        image_catcher.start()

        logger.info("submit BattleTag to trigger FunCaptcha")
        page.locator("#flow-form-submit-btn").click()
        time.sleep(2)

        summary = collect_captcha_images(
            page,
            image_catcher,
            out_dir=CAPTCHA_OUTPUT_DIR,
            max_submits=CAPTCHA_RANDOM_SUBMITS,
        )
        logger.info("capture summary: %s", summary)
        try:
            page.screenshot(path=os.path.join(CAPTCHA_OUTPUT_DIR, "final_page.png"))
        except Exception:
            pass
        zip_capture_dir(CAPTCHA_OUTPUT_DIR, "captcha_images.zip")
        return True

    except Exception as e:
        logger.error("capture exception: %s: %s", type(e).__name__, e, exc_info=True)
        try:
            if browser and browser.contexts:
                for p in browser.contexts[0].pages:
                    p.screenshot(path="error_exception.png")
        except Exception:
            pass
        return False
    finally:
        if image_catcher:
            try:
                image_catcher.stop()
            except Exception:
                pass
        if browser:
            try:
                browser.close()
            except Exception:
                pass


def main():
    acc = generate_identity()
    logger.info("=" * 60)
    logger.info("FunCaptcha image capture mode")
    logger.info("email=%s", acc["email"])
    logger.info("battle_tag=%s", acc["battle_tag"])
    logger.info("max_submits=%s output=%s", CAPTCHA_RANDOM_SUBMITS, CAPTCHA_OUTPUT_DIR)
    logger.info("=" * 60)
    ok = run_capture(acc)
    logger.info("capture finished: %s", "ok" if ok else "failed")


if __name__ == "__main__":
    main()
