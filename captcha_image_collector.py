# -*- coding: utf-8 -*-
"""CDP FunCaptcha image collector for training data."""

import base64
import hashlib
import json
import logging
import random
import threading
import time
import zipfile
from pathlib import Path

import requests
import websocket

logger = logging.getLogger("captcha_collector")


class CDPImageCatcher:
    def __init__(self, debug_port: int = 9222, ws_url: str = None, label: str = ""):
        self.debug_port = debug_port
        self._ws_url_override = ws_url
        self._label = label
        self.ws = None
        self.msg_id = 0
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._requests_log = {}
        self.captured_images = []
        self.image_event = threading.Event()
        self._image_rid_index = {}
        self._image_body_pending = {}

    def _send(self, method, params=None, session_id=None):
        with self._lock:
            self.msg_id += 1
            mid = self.msg_id
            payload = {"id": mid, "method": method, "params": params or {}}
            if session_id:
                payload["sessionId"] = session_id
            try:
                self.ws.send(json.dumps(payload))
            except Exception as e:
                logger.debug("CDP send failed: %s", e)
            return mid

    def _get_browser_ws_url(self) -> str:
        if self._ws_url_override:
            return self._ws_url_override
        return requests.get(f"http://localhost:{self.debug_port}/json/version", timeout=5).json()["webSocketDebuggerUrl"]

    def start(self):
        ws_url = self._get_browser_ws_url()
        try:
            self.ws = websocket.create_connection(ws_url, max_size=None, suppress_origin=True)
        except TypeError:
            self.ws = websocket.create_connection(ws_url, max_size=None, origin="chrome://devtools")
        self._send("Network.enable", {"maxPostDataSize": 131072})
        self._send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("[%s] CDP image catcher started", self._label)

    def _loop(self):
        while self._running:
            try:
                raw = self.ws.recv()
                if not raw:
                    continue
                msg = json.loads(raw)
                msg_id = msg.get("id")
                if msg_id is not None and msg_id in self._image_body_pending:
                    idx = self._image_body_pending.pop(msg_id)
                    if "error" in msg:
                        if 0 <= idx < len(self.captured_images):
                            self.captured_images[idx]["body_error"] = msg.get("error")
                        continue
                    result = msg.get("result", {})
                    body = result.get("body", "")
                    data = b""
                    if body:
                        data = base64.b64decode(body) if result.get("base64Encoded") else body.encode("utf-8", "replace")
                    if data and 0 <= idx < len(self.captured_images):
                        rec = self.captured_images[idx]
                        rec["body_bytes"] = data
                        rec["bytes"] = len(data)
                        rec["sha256"] = hashlib.sha256(data).hexdigest()
                        self.image_event.set()
                        logger.info("[%s] captured image body idx=%s bytes=%s sha256=%s", self._label, idx, len(data), rec["sha256"][:12])
                    continue

                method = msg.get("method")
                params = msg.get("params", {})
                session_id = msg.get("sessionId")
                if method == "Network.requestWillBeSent":
                    req = params.get("request", {})
                    rid = params.get("requestId")
                    if rid:
                        self._requests_log[rid] = {
                            "url": req.get("url", ""),
                            "type": params.get("type", "Other"),
                            "method": req.get("method", "GET"),
                            "session_id": session_id,
                        }
                    continue
                if method == "Network.responseReceived":
                    rid = params.get("requestId")
                    resp = params.get("response", {})
                    url = resp.get("url", "") or self._requests_log.get(rid, {}).get("url", "")
                    mime = (resp.get("mimeType", "") or "").lower()
                    rtype = params.get("type", "")
                    if rid and rid in self._requests_log:
                        self._requests_log[rid]["status"] = resp.get("status", 0)
                        self._requests_log[rid]["mime"] = mime
                    u = url.lower()
                    is_challenge_image = (
                        "/rtig/image" in u
                        or ("arkoselabs.com" in u and rtype == "Image" and "/fc/assets/" not in u and mime.startswith("image/"))
                    )
                    if rid and is_challenge_image and rid not in self._image_rid_index:
                        idx = len(self.captured_images)
                        self._image_rid_index[rid] = idx
                        self.captured_images.append({
                            "url": url,
                            "mime": mime,
                            "status": resp.get("status", 0),
                            "requestId": rid,
                            "session_id": session_id or self._requests_log.get(rid, {}).get("session_id"),
                            "resource_type": rtype,
                            "timestamp": time.time(),
                            "body_bytes": None,
                        })
                        logger.info("[%s] saw image idx=%s status=%s mime=%s url=%s", self._label, idx, resp.get("status", 0), mime, url[:160])
                    continue
                if method == "Network.loadingFinished":
                    rid = params.get("requestId")
                    if rid and rid in self._image_rid_index:
                        idx = self._image_rid_index[rid]
                        sess = session_id
                        if 0 <= idx < len(self.captured_images):
                            sess = self.captured_images[idx].get("session_id") or sess
                        mid = self._send("Network.getResponseBody", {"requestId": rid}, session_id=sess)
                        self._image_body_pending[mid] = idx
                    continue
                if method == "Target.attachedToTarget":
                    new_session = params.get("sessionId")
                    waiting = params.get("waitingForDebugger", False)
                    self._send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True}, session_id=new_session)
                    self._send("Network.enable", {"maxPostDataSize": 131072}, session_id=new_session)
                    if waiting:
                        self._send("Runtime.runIfWaitingForDebugger", {}, session_id=new_session)
                    continue
            except Exception:
                if self._running:
                    time.sleep(0.05)

    def wait_for_image(self, min_count: int = 1, timeout: float = 30.0) -> list:
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready = [r for r in self.captured_images if r.get("body_bytes")]
            if len(ready) >= min_count:
                time.sleep(0.2)
                return list(ready)
            self.image_event.wait(timeout=1.0)
            self.image_event.clear()
        return [r for r in self.captured_images if r.get("body_bytes")]

    def stop(self):
        self._running = False
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass


def _click_in_frames(page, selectors, max_depth=4) -> bool:
    def try_page(p):
        for sel in selectors:
            try:
                loc = p.locator(sel)
                count = min(loc.count(), 8)
                for i in range(count):
                    btn = loc.nth(i)
                    try:
                        if btn.is_visible():
                            btn.click(force=True, timeout=2500)
                            return True
                    except Exception:
                        pass
            except Exception:
                pass
        return False

    def recurse(p, depth):
        if try_page(p):
            return True
        if depth >= max_depth:
            return False
        for frame in p.frames:
            if frame == p.main_frame and depth > 0:
                continue
            try:
                if recurse(frame, depth + 1):
                    return True
            except Exception:
                pass
        return False

    return recurse(page, 0)


def click_verify_button(page) -> bool:
    return _click_in_frames(page, [
        'button[data-theme="home.verifyButton"]',
        'button[aria-label="Verify"]',
        'button[aria-label="验证"]',
        'button:has-text("Verify")',
        'button:has-text("验证")',
    ])


def click_submit_button(page) -> bool:
    return _click_in_frames(page, [
        'button.sc-nkuzb1-0.yuVdl.button',
        'button.sc-nkuzb1-0.yuVdl',
        'button:has-text("提交")',
        'button:has-text("Submit")',
        'button:has-text("submit")',
    ])


def save_cdp_images(catcher: CDPImageCatcher, out_dir: str, prefix: str = "captcha") -> list:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    saved = []
    seen = set()
    index = []
    for i, rec in enumerate(catcher.captured_images):
        data = rec.get("body_bytes")
        meta = {k: v for k, v in rec.items() if k != "body_bytes"}
        if not data:
            index.append(meta)
            continue
        sha = rec.get("sha256") or hashlib.sha256(data).hexdigest()
        if sha in seen:
            continue
        seen.add(sha)
        mime = (rec.get("mime") or "").lower()
        ext = ".jpg" if "jpeg" in mime or "jpg" in mime else ".png" if "png" in mime else ".webp" if "webp" in mime else ".bin"
        path = out / f"{prefix}_{i:03d}_{sha[:12]}{ext}"
        if not path.exists():
            path.write_bytes(data)
        meta.update({"file": str(path), "sha256": sha, "bytes": len(data)})
        saved.append(str(path))
        index.append(meta)
    (out / "images_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return saved


def collect_captcha_images(page, catcher: CDPImageCatcher, out_dir: str = "captcha_images", max_submits: int = 12) -> dict:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    logger.info("waiting/clicking Arkose Verify button")
    deadline = time.time() + 45
    clicked_verify = False
    while time.time() < deadline:
        if click_verify_button(page):
            clicked_verify = True
            logger.info("clicked Arkose Verify")
            break
        time.sleep(1)

    catcher.wait_for_image(min_count=1, timeout=30)
    saved = save_cdp_images(catcher, out_dir)
    logger.info("initial captured images=%s saved=%s", len(catcher.captured_images), len(saved))

    submit_count = 0
    last_ready = len([r for r in catcher.captured_images if r.get("body_bytes")])
    for n in range(max_submits):
        if not click_submit_button(page):
            logger.info("submit button not found at loop=%s", n)
            break
        submit_count += 1
        logger.info("random submit clicked %s/%s", submit_count, max_submits)
        time.sleep(0.8 + random.random() * 0.9)
        catcher.wait_for_image(min_count=last_ready + 1, timeout=12)
        ready = len([r for r in catcher.captured_images if r.get("body_bytes")])
        save_cdp_images(catcher, out_dir)
        if ready <= last_ready:
            logger.info("no new image after submit=%s, stopping", submit_count)
            break
        last_ready = ready

    saved = save_cdp_images(catcher, out_dir)
    summary = {
        "clicked_verify": clicked_verify,
        "submit_count": submit_count,
        "captured_records": len(catcher.captured_images),
        "saved_images": len(saved),
        "out_dir": str(Path(out_dir).resolve()),
        "timestamp": time.time(),
    }
    Path(out_dir, "capture_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def zip_capture_dir(src_dir: str = "captcha_images", zip_path: str = "captcha_images.zip") -> str:
    src = Path(src_dir)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if src.exists():
            for path in src.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(src.parent))
    logger.info("zip saved: %s", zip_path)
    return zip_path
