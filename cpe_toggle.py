#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPE cell-lock automation for PinSu R200C.

Used standalone:
  python cpe_toggle.py --lock
  python cpe_toggle.py --unlock
  python cpe_toggle.py --status

Used from CPEMonitor.exe tray:
  CPEMonitor.exe --lock-cell
  CPEMonitor.exe --unlock-cell
"""

import argparse
import asyncio
import ctypes
import hashlib
import hmac
import http.cookiejar
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime

# 配置：所有参数可通过环境变量覆盖（默认值为品速R200C出厂设置）
DEVICE_BASE = os.environ.get("CPE_DEVICE_BASE", "http://192.168.10.1")
LOGIN_URL = DEVICE_BASE + "/common/login.html"
SETTINGS_URL = DEVICE_BASE + "/html/settings.html"
USER = os.environ.get("CPE_USER", "admin")
PASS = os.environ.get("CPE_PASS", "admin")
TARGET_PCI = int(os.environ.get("CPE_TARGET_PCI", "990"))
TARGET_EARFCN = int(os.environ.get("CPE_TARGET_EARFCN", "504990"))
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.environ.get("CPE_MONITOR_APP_DIR") or os.getcwd()
STATE_CACHE_PATH = os.path.join(APP_DIR, "cell_lock_state.json")
LOGIN_HMAC_KEY = os.environ.get("CPE_HMAC_KEY", "0123456789").encode("utf-8")

g_choice = None
g_choice_evt = threading.Event()


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(message):
    print(f"  [{ts()}] {message}", flush=True)


def ok(message):
    print(f"  [OK] {message}", flush=True)


def fail(message):
    print(f"  [ERR] {message}", flush=True)


def info(message):
    print(f"  [INFO] {message}", flush=True)


def sep(message):
    print(f"\n{'=' * 18} {message} {'=' * 18}", flush=True)


def write_state_cache(state):
    try:
        import json
        payload = {
            "locked": bool(state.get("locked")),
            "pci": int(state.get("pci") or 0),
            "earfcn": int(state.get("earfcn") or 0),
            "updated_at": datetime.now().isoformat(),
        }
        with open(STATE_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        info(f"状态缓存写入失败: {exc}")


def read_state_cache(max_age_seconds=300):
    try:
        import json
        with open(STATE_CACHE_PATH, "r", encoding="utf-8") as f:
            state = json.load(f)
        updated = datetime.fromisoformat(state.get("updated_at", ""))
        if (datetime.now() - updated).total_seconds() > max_age_seconds:
            return None
        return state
    except Exception:
        return None


def _hmac_login_value(value):
    return hmac.new(LOGIN_HMAC_KEY, value.encode("utf-8"), hashlib.md5).hexdigest()


class CpeApi:
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def post_json(self, path, payload):
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            DEVICE_BASE + path,
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        with self.opener.open(req, timeout=self.timeout) as resp:
            text = resp.read().decode("utf-8", "ignore")
        try:
            return json.loads(text)
        except Exception:
            return {"retcode": -1, "raw": text}

    def login(self):
        payload = {
            "username": _hmac_login_value(USER),
            "password": _hmac_login_value(PASS),
        }
        obj = self.post_json("/goform/login", payload)
        return obj.get("retcode") == 0

    def get_raw_lock_info(self):
        obj = self.post_json("/action/get_mgdb_params", {"keys": ["mnet_cell_lock_info"]})
        if obj.get("retcode") != 0:
            return None
        return (obj.get("data") or {}).get("mnet_cell_lock_info")

    def read_state(self):
        if not self.login():
            return None
        raw = self.get_raw_lock_info()
        state = parse_lock_info(raw)
        if state:
            write_state_cache(state)
        return state

    def set_lock(self):
        if not self.login():
            return False
        payload = {
            "mnet_cell_lock_rat": "4",
            "mnet_cell_lock_arfcn": str(TARGET_EARFCN),
            "mnet_cell_lock_scs": "30",
            "mnet_cell_lock_pci": str(TARGET_PCI),
            "mnet_cell_lock_band": str(band_level(TARGET_EARFCN)),
            "mnet_cell_lock_type": "1",
        }
        obj = self.post_json("/action/mnet_set_celllock_switch", payload)
        if obj.get("retcode") == 0:
            write_state_cache({"locked": True, "pci": TARGET_PCI, "earfcn": TARGET_EARFCN})
            return True
        fail(f"直连锁定接口返回: {obj}")
        return False

    def set_unlock(self):
        if not self.login():
            return False
        payload = {
            "mnet_cell_lock_rat": "14",
            "mnet_cell_lock_type": "1",
        }
        obj = self.post_json("/action/mnet_set_celllock_switch", payload)
        if obj.get("retcode") == 0:
            write_state_cache({"locked": False, "pci": 0, "earfcn": 0})
            return True
        fail(f"直连解锁接口返回: {obj}")
        return False


def band_level(arfcn):
    arfcn = int(arfcn)
    if 499200 < arfcn < 538000:
        return 41
    if 620000 < arfcn < 653333:
        return 78
    if 693333 < arfcn < 733333:
        return 79
    return 41


def parse_lock_info(raw):
    if not raw:
        return {"locked": False, "pci": 0, "earfcn": 0, "raw": raw}
    result = {"locked": False, "pci": 0, "earfcn": 0, "raw": raw}
    for row in str(raw).split(";"):
        parts = row.split(",")
        if len(parts) < 5:
            continue
        rat, enabled = parts[0].lower(), parts[1]
        if enabled != "1":
            continue
        earfcn = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
        pci = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
        result.update({"locked": True, "pci": pci, "earfcn": earfcn, "rat": rat})
        break
    return result


def run_api_action(action):
    api = CpeApi(timeout=3)
    started = datetime.now()
    if action == "status":
        state = api.read_state()
        elapsed = (datetime.now() - started).total_seconds()
        if state is None:
            fail("直连读取锁频状态失败")
            return False
        info(f"当前状态: locked={state['locked']}, PCI={state['pci']}, EARFCN={state['earfcn']}, 耗时={elapsed:.3f}s")
        return True
    if action == "lock":
        ok_flag = api.set_lock()
    elif action == "unlock":
        ok_flag = api.set_unlock()
    else:
        return False
    elapsed = (datetime.now() - started).total_seconds()
    info(f"直连{action}耗时={elapsed:.3f}s")
    return ok_flag


class CpeToggle:
    def __init__(self, action=None, debug=False, headless=False, keep_open=False):
        self.action = action
        self.debug = debug
        self.headless = headless
        self.keep_open = keep_open
        self.page = None
        self.context = None
        self.screenshot_dir = os.path.join(APP_DIR, "debug_screenshots")

    async def screenshot(self, name):
        if not self.debug or not self.page:
            return
        try:
            os.makedirs(self.screenshot_dir, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            path = os.path.join(self.screenshot_dir, f"{stamp}_{name}.png")
            await self.page.screenshot(path=path, full_page=True)
            info(f"截图已保存: {path}")
        except Exception as exc:
            info(f"截图失败: {exc}")

    async def _dismiss_translate(self):
        try:
            await self.page.keyboard.press("Escape")
        except Exception:
            pass

    async def _try_fill(self, selectors, value):
        for sel in selectors:
            try:
                el = await self.page.query_selector(sel)
                if el and await el.is_visible(timeout=1000):
                    await el.fill(str(value))
                    log(f"填写 {sel} = {value}")
                    return True
            except Exception:
                continue
        return False

    async def _js_fill_login_field(self, field_type, value):
        return await self.page.evaluate(
            """([fieldType, value]) => {
                const userWords = ['user', 'account', 'admin', '用户名', '账号'];
                const passWords = ['pass', 'pwd', 'password', '密码'];
                for (const el of document.querySelectorAll('input')) {
                    const text = [
                        el.type || '', el.id || '', el.name || '', el.placeholder || '',
                        el.className || '', el.getAttribute('aria-label') || ''
                    ].join(' ').toLowerCase();
                    const words = fieldType === 'user' ? userWords : passWords;
                    let match = words.some((w) => text.includes(w.toLowerCase()));
                    if (fieldType === 'user' && (el.type || '').toLowerCase() === 'text') match = true;
                    if (fieldType === 'pass' && (el.type || '').toLowerCase() === 'password') match = true;
                    if (!match) continue;
                    el.value = value;
                    el.dispatchEvent(new Event('input', {bubbles:true}));
                    el.dispatchEvent(new Event('change', {bubbles:true}));
                    return true;
                }
                return false;
            }""",
            [field_type, str(value)],
        )

    async def _try_click(self, selectors, timeout=1000):
        for sel in selectors:
            try:
                el = await self.page.query_selector(sel)
                if el and await el.is_visible(timeout=timeout):
                    await el.click()
                    log(f"点击 {sel}")
                    return True
            except Exception:
                continue
        return False

    async def _click_by_text(self, keywords, scope_selector=None):
        return await self.page.evaluate(
            """([keywords, scopeSelector]) => {
                const root = scopeSelector ? document.querySelector(scopeSelector) : document;
                if (!root) return false;
                const nodes = root.querySelectorAll('button,a,input[type="button"],input[type="submit"],span,div,li');
                for (const el of nodes) {
                    const text = ((el.innerText || el.value || '') + '').trim();
                    if (!keywords.some((k) => text.includes(k))) continue;
                    const rect = el.getBoundingClientRect();
                    if (rect.width <= 0 || rect.height <= 0) continue;
                    el.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, clientX: rect.left + 5, clientY: rect.top + 5}));
                    el.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, clientX: rect.left + 5, clientY: rect.top + 5}));
                    el.dispatchEvent(new MouseEvent('click', {bubbles:true, cancelable:true, clientX: rect.left + 5, clientY: rect.top + 5}));
                    return true;
                }
                return false;
            }""",
            [keywords, scope_selector],
        )

    async def login(self):
        sep("登录 CPE")
        try:
            await self.page.goto(LOGIN_URL, timeout=12000, wait_until="domcontentloaded")
        except Exception:
            pass
        await asyncio.sleep(0.05)
        await self._dismiss_translate()
        await self.screenshot("01_login_page")

        filled_user = await self._try_fill(["#username", "input[name='username']", "input[type='text']"], USER)
        filled_pass = await self._try_fill(["#password", "input[name='password']", "input[type='password']"], PASS)
        if not filled_user:
            filled_user = await self._js_fill_login_field("user", USER)
        if not filled_pass:
            filled_pass = await self._js_fill_login_field("pass", PASS)

        clicked = await self._try_click(["#loginBtn", "#login", "button[type='submit']", ".login-btn"])
        if not clicked:
            clicked = await self._click_by_text(["登录", "Login", "登陆"])
        if not clicked:
            await self.page.keyboard.press("Enter")

        for _ in range(20):
            await asyncio.sleep(0.1)
            if "login" not in self.page.url.lower():
                break

        await self.screenshot("02_after_login")
        if "login" in self.page.url.lower():
            fail("登录后仍停留在登录页，请检查账号密码或 CPE 页面状态")
            return False
        ok("登录成功")
        return True

    async def open_settings_fast(self):
        sep("打开设置页")
        if "settings" not in self.page.url.lower():
            try:
                await self.page.goto(SETTINGS_URL, timeout=10000, wait_until="domcontentloaded")
            except Exception:
                pass
        await asyncio.sleep(0.15)
        await self.screenshot("03_settings_page")
        if "login" in self.page.url.lower():
            return False
        try:
            body_text = await self.page.evaluate("() => document.body.innerText || ''")
            if "登录" in body_text and "密码" in body_text and "settings" not in self.page.url.lower():
                return False
        except Exception:
            pass
        return True

    async def open_lock_dialog(self):
        sep("打开锁小区设置")

        if await self._has_lock_form():
            ok("锁小区表单已就绪")
            return True

        clicked = await self._try_click([
            "#lockCell", "#lock_cell", "#lockcell", "[data-title*='锁小区']",
            "button:has-text('锁小区')", "a:has-text('锁小区')"
        ], timeout=800)
        if not clicked:
            clicked = await self._click_by_text(["锁小区", "小区锁定", "锁频", "锁定小区"])

        if not clicked:
            fail("找不到锁小区入口")
            await self.screenshot("04_no_lock_button")
            return False

        for _ in range(25):
            await asyncio.sleep(0.08)
            if await self._has_lock_form() or await self._has_layer():
                await self.screenshot("04_lock_dialog")
                ok("锁小区界面已出现")
                return True

        fail("点击后未检测到锁小区弹窗/表单")
        await self.screenshot("04_no_dialog")
        return False

    async def _has_layer(self):
        return await self.page.evaluate("""() => !!document.querySelector('.layui-layer, .modal, .dialog')""")

    async def _has_lock_form(self):
        return await self.page.evaluate(
            """() => {
                const text = document.body.innerText || '';
                return !!(
                    document.querySelector('#cek_sts') ||
                    document.querySelector('.layui-form-switch') ||
                    document.querySelector('input[name*="pci" i]') ||
                    document.querySelector('input[id*="pci" i]') ||
                    (text.includes('PCI') && (text.includes('EARFCN') || text.includes('频点')))
                );
            }"""
        )

    async def read_state(self):
        return await self.page.evaluate(
            """() => {
                const root = document.querySelector('.layui-layer, .modal, .dialog') || document.body;
                const result = {locked:false, pci:0, earfcn:0};
                const checkbox = root.querySelector('#cek_sts, input[type="checkbox"]');
                if (checkbox) result.locked = !!checkbox.checked;
                const sw = root.querySelector('.layui-form-switch, .switch, [role="switch"]');
                if (sw) {
                    const cls = sw.className || '';
                    const aria = sw.getAttribute('aria-checked');
                    result.locked = cls.includes('layui-form-onswitch') || cls.includes('on') || aria === 'true';
                }
                const inputs = Array.from(root.querySelectorAll('input'));
                for (const inp of inputs) {
                    const id = inp.id || '';
                    const name = inp.name || '';
                    const ph = inp.placeholder || '';
                    const item = inp.closest('.layui-form-item, .form-item, .row, label, div');
                    const nearby = item ? item.innerText || '' : '';
                    const key = `${id} ${name} ${ph} ${nearby}`.toLowerCase();
                    const val = parseInt(inp.value, 10) || 0;
                    if (!val) continue;
                    if (key.includes('pci') || key.includes('小区') || key.includes('cell')) result.pci = val;
                    if (key.includes('earfcn') || key.includes('频点') || key.includes('freq')) result.earfcn = val;
                }
                return result;
            }"""
        )

    async def set_switch(self, turn_on):
        await self.page.evaluate(
            """(turnOn) => {
                const root = document.querySelector('.layui-layer, .modal, .dialog') || document.body;
                const checkbox = root.querySelector('#cek_sts, input[type="checkbox"]');
                const sw = root.querySelector('.layui-form-switch, .switch, [role="switch"]');
                const isOn = checkbox ? !!checkbox.checked : !!(sw && ((sw.className || '').includes('on') || sw.getAttribute('aria-checked') === 'true'));
                if (isOn === turnOn) return true;
                if (sw) sw.click();
                else if (checkbox) checkbox.click();
                return true;
            }""",
            bool(turn_on),
        )

    async def fill_lock_inputs(self):
        success = await self.page.evaluate(
            """([pci, earfcn]) => {
                const root = document.querySelector('.layui-layer, .modal, .dialog') || document.body;
                let pciSet = false;
                let earfcnSet = false;
                const inputs = Array.from(root.querySelectorAll('input[type="text"], input[type="number"], input:not([type])'));
                for (const inp of inputs) {
                    const id = inp.id || '';
                    const name = inp.name || '';
                    const ph = inp.placeholder || '';
                    const item = inp.closest('.layui-form-item, .form-item, .row, label, div');
                    const nearby = item ? item.innerText || '' : '';
                    const key = `${id} ${name} ${ph} ${nearby}`.toLowerCase();
                    let value = null;
                    if (key.includes('earfcn') || key.includes('频点') || key.includes('freq')) {
                        value = String(earfcn);
                        earfcnSet = true;
                    } else if (key.includes('pci') || key.includes('小区') || key.includes('cell')) {
                        value = String(pci);
                        pciSet = true;
                    }
                    if (value === null) continue;
                    inp.focus();
                    inp.value = value;
                    inp.dispatchEvent(new Event('input', {bubbles:true}));
                    inp.dispatchEvent(new Event('change', {bubbles:true}));
                    inp.blur();
                }
                return {pciSet, earfcnSet};
            }""",
            [TARGET_PCI, TARGET_EARFCN],
        )
        if not success.get("pciSet") or not success.get("earfcnSet"):
            info(f"输入框匹配结果: {success}")
        return bool(success.get("pciSet") and success.get("earfcnSet"))

    async def click_confirm(self):
        clicked = await self._try_click([".layui-layer-btn0", ".layui-btn-normal", "button[type='submit']"], timeout=1000)
        if not clicked:
            clicked = await self._click_by_text(["确认操作", "确定", "保存", "提交", "确认"], ".layui-layer")
        if not clicked:
            clicked = await self._click_by_text(["确认操作", "确定", "保存", "提交", "确认"])
        await asyncio.sleep(1.0)
        await self.screenshot("06_after_confirm")
        return clicked

    async def show_confirm_page(self, state):
        global g_choice, g_choice_evt
        g_choice = None
        g_choice_evt.clear()
        confirm_page = await self.context.new_page()

        async def on_choice(action):
            global g_choice, g_choice_evt
            g_choice = action
            g_choice_evt.set()

        await confirm_page.expose_function("onConfirmChoice", on_choice)
        if state["locked"]:
            title = f"当前已锁定：PCI={state['pci'] or '-'}，EARFCN={state['earfcn'] or '-'}"
            primary = "解锁"
            action = "unlock"
            secondary = "保持当前状态"
        else:
            title = "当前未锁定小区"
            primary = f"锁定 PCI {TARGET_PCI}"
            action = "lock"
            secondary = "取消"

        html = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>CPE 锁小区确认</title>
<style>
body{{font-family:'Microsoft YaHei',Segoe UI,sans-serif;margin:0;background:#f5f6fa;display:flex;align-items:center;justify-content:center;height:100vh;color:#222}}
.card{{background:white;border:1px solid #dde1e7;border-radius:8px;padding:34px 42px;box-shadow:0 12px 32px rgba(0,0,0,.12);text-align:center;min-width:360px}}
h2{{margin:0 0 12px;font-size:22px}} .state{{color:#555;margin-bottom:26px}}
button{{font-size:16px;padding:11px 28px;margin:7px;border-radius:6px;border:0;cursor:pointer;font-weight:600}}
.primary{{background:#0b65c2;color:white}} .secondary{{background:#e8eaee;color:#333}}
</style></head><body><div class="card">
<h2>CPE 锁小区</h2><div class="state">{title}</div>
<button class="primary" onclick="choose('{action}')">{primary}</button>
<button class="secondary" onclick="choose('cancel')">{secondary}</button>
</div><script>
function choose(action) {{
  onConfirmChoice(action).then(() => document.body.innerHTML = '<h2 style="font-family:Microsoft YaHei">已收到，正在执行...</h2>');
}}
</script></body></html>"""
        await confirm_page.set_content(html, wait_until="load")
        ok("确认页已打开")

        for _ in range(300):
            if g_choice_evt.is_set():
                break
            await asyncio.sleep(0.2)
        else:
            g_choice = "cancel"
        await confirm_page.close()
        return g_choice

    async def perform_action(self, action):
        if action == "lock":
            sep(f"锁定 PCI={TARGET_PCI}, EARFCN={TARGET_EARFCN}")
            await self.set_switch(True)
            await asyncio.sleep(0.3)
            await self.fill_lock_inputs()
            await self.screenshot("05_before_lock_confirm")
            if not await self.click_confirm():
                fail("未找到确认按钮")
                return False
            ok("锁定命令已提交")
            return True
        if action == "unlock":
            sep("解锁小区")
            await self.set_switch(False)
            await asyncio.sleep(0.3)
            await self.screenshot("05_before_unlock_confirm")
            if not await self.click_confirm():
                fail("未找到确认按钮")
                return False
            ok("解锁命令已提交")
            return True
        if action == "status":
            return True
        info("已取消操作")
        return True

    async def run(self):
        print(f"\n{'=' * 18} CPE 锁小区工具 v2.5 {'=' * 18}\n", flush=True)
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            fail("未安装 playwright，请先在打包 Python 环境中安装 playwright")
            return False

        async with async_playwright() as p:
            try:
                user_dir = os.path.join(tempfile.gettempdir(), "cpe_toggle_edge")
                self.context = await p.chromium.launch_persistent_context(
                    user_dir,
                    headless=self.headless,
                    channel="msedge",
                    locale="zh-CN",
                    accept_downloads=True,
                    ignore_https_errors=True,
                    args=[
                        "--no-sandbox",
                        "--disable-web-security",
                        "--disable-features=TranslateUI,edge-translate,edge-translate-ui",
                        "--disable-translate",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                )
            except Exception as exc:
                fail(f"Edge 启动失败: {exc}")
                return False

            try:
                self.page = await self.context.new_page()
                if not await self.open_settings_fast():
                    if not await self.login():
                        return False
                    if not await self.open_settings_fast():
                        return False
                if not await self.open_lock_dialog():
                    return False
                state = await self.read_state()
                write_state_cache(state)
                info(f"当前状态: locked={state['locked']}, PCI={state['pci']}, EARFCN={state['earfcn']}")

                action = self.action
                if action is None:
                    action = await self.show_confirm_page(state)
                    info(f"用户选择: {action}")
                result = await self.perform_action(action)

                if result and action in ("lock", "unlock"):
                    write_state_cache({
                        "locked": action == "lock",
                        "pci": TARGET_PCI if action == "lock" else 0,
                        "earfcn": TARGET_EARFCN if action == "lock" else 0,
                    })
                    await asyncio.sleep(0.8)
                    ok("操作完成，CPE 可能会在数秒内短暂重连")
                if self.keep_open:
                    info("浏览器保持打开，按 Ctrl+C 结束脚本")
                    while True:
                        await asyncio.sleep(1)
                return result
            finally:
                if self.context and not self.keep_open:
                    await self.context.close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="PinSu R200C CPE cell lock helper")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--lock", action="store_true", help=f"lock to PCI {TARGET_PCI}, EARFCN {TARGET_EARFCN}")
    group.add_argument("--unlock", action="store_true", help="unlock cell lock")
    group.add_argument("--status", action="store_true", help="only read current lock state")
    parser.add_argument("--debug", action="store_true", help="save screenshots under debug_screenshots")
    parser.add_argument("--headless", action="store_true", help="run browser headless")
    parser.add_argument("--keep-open", action="store_true", help="keep browser open after action")
    parser.add_argument("--no-pause", action="store_true", help="do not wait for Enter before exit")
    parser.add_argument("--browser", action="store_true", help="force browser automation instead of direct API")
    return parser.parse_args(argv)


def action_from_args(args):
    if args.lock:
        return "lock"
    if args.unlock:
        return "unlock"
    if args.status:
        return "status"
    return None


def main(argv=None):
    args = parse_args(argv)
    action = action_from_args(args)
    exit_code = 1
    final_message = ""
    try:
        if action in ("status", "lock", "unlock") and not args.browser:
            result = run_api_action(action)
        else:
            mgr = CpeToggle(action=action, debug=args.debug, headless=args.headless, keep_open=args.keep_open)
            result = asyncio.run(mgr.run())
        if result:
            ok("任务完成")
            final_message = "CPE 锁小区任务已完成。"
            exit_code = 0
        else:
            fail("执行失败，请查看日志或 debug_screenshots 截图")
            final_message = "CPE 锁小区执行失败，请查看 debug_screenshots 截图。"
    except KeyboardInterrupt:
        info("用户中断")
        final_message = "用户中断了 CPE 锁小区任务。"
        exit_code = 130
    except Exception as exc:
        fail(f"发生异常: {exc}")
        final_message = f"CPE 锁小区发生异常：{exc}"
        import traceback
        traceback.print_exc()
    finally:
        if getattr(sys, "frozen", False) and args.no_pause and action in ("lock", "unlock"):
            try:
                title = "CPE 锁小区"
                ctypes.windll.user32.MessageBoxW(None, final_message or "CPE 锁小区任务已结束。", title, 0x40 if exit_code == 0 else 0x10)
            except Exception:
                pass
        if not args.no_pause:
            try:
                input("\n按 Enter 退出...")
            except EOFError:
                pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
