#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPE Network Disconnection Monitor - Desktop Edition v2.3
系统托盘模式：托盘常驻 + 浏览器打开监控面板
修复：UTF-8编码检测 + 去掉pywebview改用浏览器
"""

import sys, os, threading, time, webbrowser, socket

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import cpe_monitor as core

FLASK_PORT = 5000
FLASK_URL = "http://127.0.0.1:{0}".format(FLASK_PORT)

# ============================================================
# 单实例检测
# ============================================================
def is_already_running():
    """检查是否已有实例在运行（通过检测端口）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('127.0.0.1', FLASK_PORT))
        s.close()
        return True
    except:
        return False

# ============================================================
# Flask后台线程
# ============================================================
def run_flask():
    """在后台线程启动Flask"""
    try:
        core.app.run(host='127.0.0.1', port=FLASK_PORT, debug=False, use_reloader=False)
    except Exception as e:
        print("[Flask] 启动失败:", e)

# ============================================================
# 托盘图标
# ============================================================
def _load_tray_image():
    """加载托盘图标"""
    from PIL import Image
    # PyInstaller bundle vs 直接运行
    paths = [
        os.path.join(SCRIPT_DIR, 'tray_icon.png'),
        os.path.join(sys._MEIPASS, 'tray_icon.png') if hasattr(sys, '_MEIPASS') else None,
    ]
    for p in paths:
        if p and os.path.exists(p):
            return Image.open(p)
    # 内存中创建一个简单图标
    img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
    from PIL import ImageDraw
    d = ImageDraw.Draw(img)
    d.ellipse([4, 4, 28, 28], fill=(34, 197, 94, 255))
    return img

def _toggle_browser(icon=None, item=None):
    """点击托盘: 在默认浏览器打开/切换监控面板"""
    print("[Tray] 打开浏览器...")
    webbrowser.open(FLASK_URL)

def _quit_app(icon=None, item=None):
    """退出应用"""
    print("[Exit] 正在退出...")
    core.monitoring = False
    # 等待监控循环结束（让 end_monitor_session 有时间写入DB）
    time.sleep(3)
    try:
        icon.stop()
    except:
        pass
    os._exit(0)

def start_tray():
    """在主线程启动系统托盘"""
    import pystray
    img = _load_tray_image()
    menu = pystray.Menu(
        pystray.MenuItem("打开监控面板", _toggle_browser, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("退出监控", _quit_app),
    )
    icon = pystray.Icon("cpe_monitor", img, "CPE 断流监控", menu)
    icon.run()

# ============================================================
# 主入口
# ============================================================
def main():
    # 单实例检测
    if is_already_running():
        print("[Singleton] 已有实例在运行，打开浏览器...")
        webbrowser.open(FLASK_URL)
        return

    print("=" * 50)
    print("CPE 断流监控 v2.3")
    print("托盘常驻后台 | 点击托盘打开监控面板")
    print("=" * 50)

    # 初始化数据库
    print("[Init] 初始化数据库...")
    core.init_db()

    # 启动监控线程
    print("[Init] 启动监控线程...")
    core.monitoring = True
    core.monitor_thread = threading.Thread(target=core.monitor, daemon=True)
    core.monitor_thread.start()

    # 启动Flask线程
    print("[Init] 启动Web服务器...")
    flask_t = threading.Thread(target=run_flask, daemon=True)
    flask_t.start()

    # 等待Flask就绪
    time.sleep(2)

    # 自动打开浏览器
    print("[Init] 打开监控面板...")
    webbrowser.open(FLASK_URL)

    # 主线程：运行系统托盘（阻塞）
    print("[Init] 启动系统托盘...")
    start_tray()

if __name__ == '__main__':
    main()
