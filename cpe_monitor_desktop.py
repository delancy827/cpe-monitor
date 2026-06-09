#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPE Network Disconnection Monitor - Desktop Edition v2.8.1
系统托盘模式：托盘常驻 + 浏览器打开监控面板 + 开机自启选项
修复：单实例检测改为杀掉旧进程后重启，避免托盘无法创建
"""

import sys, os, threading, time, webbrowser, socket, subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import cpe_monitor as core

FLASK_PORT = 5000
FLASK_URL = "http://127.0.0.1:{}".format(FLASK_PORT)

# =============================================================================
# 单实例检测与清理
# =============================================================================
def kill_existing_instance():
    """通过端口5000查找并杀掉旧进程，确保托盘能正常创建"""
    try:
        result = subprocess.run(
            ['netstat', '-ano'],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        for line in result.stdout.split('\n'):
            if ':5000' in line and 'LISTENING' in line:
                parts = line.split()
                pid = int(parts[-1])
                print('[Singleton] 发现旧进程 PID={}, 正在终止...'.format(pid))
                subprocess.run(
                    ['taskkill', '/F', '/PID', str(pid)],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                time.sleep(2)
                return True
    except Exception as e:
        print('[Singleton] 清理旧进程失败:', e)
    return False

def is_already_running():
    """检查是否已有实例在运行（通过检测端口）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('127.0.0.1', FLASK_PORT))
        s.close()
        return True
    except:
        return False

# =============================================================================
# Flask后台线程
# =============================================================================
def run_flask():
    """在后台线程启动Flask"""
    try:
        core.app.run(host='127.0.0.1', port=FLASK_PORT, debug=False, use_reloader=False)
    except Exception as e:
        print("[Flask] 启动失败:", e)

# =============================================================================
# 开机自启管理
# =============================================================================
def _get_startup_path():
    """获取Windows启动文件夹路径"""
    return os.path.join(os.environ.get('APPDATA', ''),
                       'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')

def _get_startup_shortcut():
    """获取启动文件夹中快捷方式的完整路径"""
    return os.path.join(_get_startup_path(), 'CPE断流监控.lnk')

def _get_exe_path():
    """获取当前运行的exe/脚本路径"""
    if getattr(sys, 'frozen', False):
        return sys.executable
    else:
        return os.path.join(SCRIPT_DIR, 'cpe_monitor_desktop.py')

def is_autostart_enabled():
    """检查是否已设置开机自启"""
    return os.path.exists(_get_startup_shortcut())

def enable_autostart():
    """启用开机自启：在启动文件夹创建快捷方式"""
    shortcut_path = _get_startup_shortcut()
    exe_path = _get_exe_path()
    work_dir = os.path.dirname(exe_path)

    try:
        from win32com.client import Dispatch
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortcut(shortcut_path)

        if getattr(sys, 'frozen', False):
            shortcut.TargetPath = exe_path
            shortcut.WorkingDirectory = work_dir
        else:
            shortcut.TargetPath = sys.executable.replace('python.exe', 'pythonw.exe')
            shortcut.Arguments = '"' + exe_path + '"'
            shortcut.WorkingDirectory = work_dir

        shortcut.Description = 'CPE断流监控'
        shortcut.Save()
        print('[Startup] 已启用开机自启')
        return True
    except Exception as e:
        print('[Startup] 创建快捷方式失败:', e)
        try:
            vbs_path = shortcut_path.replace('.lnk', '.vbs')
            with open(vbs_path, 'w', encoding='utf-8') as f:
                f.write('CreateObject("WScript.Shell").Run """' + exe_path + '""", 0, False\n')
            print('[Startup] 已用VBS方案启用开机自启')
            return True
        except Exception as e2:
            print('[Startup] VBS方案也失败:', e2)
            return False

def disable_autostart():
    """禁用开机自启：删除启动文件夹中的快捷方式"""
    shortcut_path = _get_startup_shortcut()
    deleted = False
    for p in [shortcut_path, shortcut_path.replace('.lnk', '.vbs')]:
        try:
            if os.path.exists(p):
                os.remove(p)
                deleted = True
        except:
            pass
    if deleted:
        print('[Startup] 已禁用开机自启')
    return True

def _toggle_autostart(icon=None, item=None):
    """切换开机自启状态"""
    if is_autostart_enabled():
        disable_autostart()
    else:
        enable_autostart()

# =============================================================================
# 托盘图标
# =============================================================================
def _load_tray_image():
    """加载托盘图标"""
    from PIL import Image
    paths = [
        os.path.join(SCRIPT_DIR, 'tray_icon.png'),
        os.path.join(sys._MEIPASS, 'tray_icon.png') if hasattr(sys, '_MEIPASS') else None,
    ]
    for p in paths:
        if p and os.path.exists(p):
            return Image.open(p)
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
    """退出应用：先结束监控会话再退出"""
    print("[Exit] 正在退出...")
    # 先结束监控会话，确保数据库正确记录结束时间和时长
    try:
        core.end_monitor_session(core.monitor_session_id)
    except Exception as e:
        print("[Exit] 结束监控会话失败:", e)
    core.monitoring = False
    time.sleep(1)
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
        pystray.MenuItem(
            "开机自启",
            _toggle_autostart,
            checked=lambda item: is_autostart_enabled()
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("退出监控", _quit_app),
    )
    icon = pystray.Icon("cpe_monitor", img, "CPE 断流监控", menu)
    icon.run()

# =============================================================================
# 主入口
# =============================================================================
def main():
    # 先杀掉占用5000端口的旧进程，确保托盘能正常创建
    if is_already_running():
        print("[Singleton] 检测到旧进程，正在清理...")
        kill_existing_instance()

    print("=" * 50)
    print("CPE 断流监控 v2.8.1")
    print("托盘常驻后台 | 点击托盘打开监控面板")
    print("开机自启: {}".format("已启用" if is_autostart_enabled() else "未启用"))
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
