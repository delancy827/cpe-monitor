#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPE Network Disconnection Monitor v2.8
CPE网络断流监控工具 - 快慢分离检测：ping每秒 + netsh每30秒 + 失败重试
CPE网络断流监控工具 - 三重检测：网络接口/CPE网关/外网连通性
"""

import threading
import time
import subprocess
import platform
import json
import sqlite3
import os
import sys
from datetime import datetime, timedelta
from collections import deque
from flask import Flask, render_template_string, jsonify, request, Response

# =============================================================================
# 配置部分
# =============================================================================
PING_TARGET = "192.168.10.1"  # CPE网关（准确检测CPE是否在线）
PING_EXTERNAL = "8.8.8.8"       # 外网检测目标（备用）
PING_INTERVAL = 1                 # Ping间隔（秒），1秒提高检测精度
TIMEOUT = 2                       # Ping超时（秒）
RETRY_TIMEOUT = 1                 # 失败重试超时（秒），更快确认
NETSH_INTERVAL = 30               # 网络接口状态检查间隔（秒）
SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0                       # Ping超时时间（秒）
# DB路径：exe所在目录（PyInstaller打包）或脚本所在目录（直接运行）
if getattr(sys, 'frozen', False):
    DB_PATH = os.path.join(os.path.dirname(sys.executable), "cpe_monitor.db")
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpe_monitor.db")
CHECK_WIFI = True                 # 是否检测WiFi连接状态（Windows Only）

# =============================================================================
# 全局状态
# =============================================================================
monitoring = False
monitor_thread = None
monitor_session_id = None  # 当前监控会话ID
disconnection_events = deque(maxlen=1000)  # 存储最近1000次断流事件
current_status = "online"  # "online", "network_disconnected", "cpe_unreachable"
# 默认乐观假设在线，监控循环会在检测到断流时更新
last_online_time = None
current_offline_start = None
last_wifi_status = True  # 上次WiFi连接状态

# 统计数据
stats = {
    "total_disconnections": 0,
    "total_downtime": 0,
    "avg_downtime": 0,
    "avg_interval": 0,
    "last_disconnection": None,
    "current_status": "online",
    "current_offline_start": None,
    "conn_type": "检测中...",
    "version": "v2.8"
}

# =============================================================================
# 数据库操作
# =============================================================================
def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 创建事件表（如果不存在）
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  start_time TIMESTAMP,
                  end_time TIMESTAMP,
                  duration REAL,
                  event_type TEXT DEFAULT 'unknown',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # 尝试添加event_type列（如果表已存在但没有该列）
    try:
        c.execute("ALTER TABLE events ADD COLUMN event_type TEXT DEFAULT 'unknown'")
        print("[Init] 数据库已更新：添加 event_type 字段")
    except:
        pass  # 字段已存在
    
    # 创建监控会话表（记录每次监控的启动/停止时间）
    c.execute('''CREATE TABLE IF NOT EXISTS monitor_sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  start_time TIMESTAMP,
                  end_time TIMESTAMP,
                  duration REAL,
                  status TEXT DEFAULT 'active')''')
    
    # 关闭上次未正常结束的会话（异常退出遗留的active记录）
    c.execute("UPDATE monitor_sessions SET status='interrupted' WHERE status='active'")
    
    conn.commit()
    conn.close()

def log_disconnection(start_time, end_time, duration, event_type='unknown'):
    """记录断流事件到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO events (start_time, end_time, duration, event_type) VALUES (?, ?, ?, ?)",
              (start_time.isoformat(), end_time.isoformat(), duration, event_type))
    conn.commit()
    conn.close()

def get_recent_events(limit=100):
    """获取最近的断流事件"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        # 兼容旧数据（可能没有event_type字段）
        event_type = row[4] if len(row) > 4 else 'unknown'
        result.append({
            "id": row[0],
            "start": row[1],
            "end": row[2],
            "duration": row[3],
            "event_type": event_type
        })
    return result

def get_stats_from_db():
    """从数据库计算统计数据"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 最近7天统计
    c.execute("""SELECT 
                    COUNT(*) as total,
                    SUM(duration) as total_downtime,
                    AVG(duration) as avg_downtime,
                    MAX(end_time) as last_disconnection
                 FROM events
                 WHERE start_time > datetime('now', '-7 days')""")
    row = c.fetchone()
    
    # 计算平均断流间隔
    c.execute("""SELECT start_time FROM events 
                 WHERE start_time > datetime('now', '-7 days')
                 ORDER BY start_time ASC""")
    times = [row[0] for row in c.fetchall()]
    
    conn.close()
    
    result = {
        "total_disconnections": 0,
        "total_downtime": 0,
        "avg_downtime": 0,
        "avg_interval": 0,
        "last_disconnection": None
    }
    
    if row and row[0] > 0:
        result["total_disconnections"] = row[0]
        result["total_downtime"] = row[1] or 0
        result["avg_downtime"] = row[2] or 0
        result["last_disconnection"] = row[3]
        
        # 计算平均间隔
        if len(times) >= 2:
            intervals = []
            for i in range(1, len(times)):
                t1 = datetime.fromisoformat(times[i-1])
                t2 = datetime.fromisoformat(times[i])
                intervals.append((t2 - t1).total_seconds())
            result["avg_interval"] = sum(intervals) / len(intervals)
    
    return result

def get_hourly_stats():
    """获取24小时断流统计（按小时分组）——只统计今天的数据"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 初始化24小时数组
    hourly = [0] * 24
    
    # 查询今天的断流事件，按小时统计（避免跨天数据混入；使用本地时间）
    c.execute("""SELECT 
                    CAST(strftime('%H', start_time) AS INTEGER) as hour,
                    COUNT(*) as cnt
                 FROM events
                 WHERE date(start_time) = date('now', 'localtime')
                 GROUP BY hour
                 ORDER BY hour""")
    
    for row in c.fetchall():
        hour = row[0]
        cnt = row[1]
        hourly[hour] = cnt
    
    conn.close()
    
    # 生成标签（00:00 - 23:00）
    labels = []
    for i in range(24):
        labels.append("{:02d}:00".format(i))
    
    return {
        "labels": labels,
        "data": hourly
    }


def start_monitor_session():
    """开始一个新的监控会话"""
    now = datetime.now()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO monitor_sessions (start_time, status) VALUES (?, 'active')",
              (now.isoformat(),))
    session_id = c.lastrowid
    conn.commit()
    conn.close()
    print("[Session] 监控会话已开始, id={}".format(session_id))
    return session_id


def end_monitor_session(session_id):
    """结束监控会话"""
    if session_id is None:
        return
    now = datetime.now()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT start_time FROM monitor_sessions WHERE id=?", (session_id,))
    row = c.fetchone()
    if row:
        start = datetime.fromisoformat(row[0])
        duration = (now - start).total_seconds()
        c.execute("UPDATE monitor_sessions SET end_time=?, duration=?, status='closed' WHERE id=?",
                  (now.isoformat(), duration, session_id))
        print("[Session] 监控会话已结束, 持续 {:.1f} 分钟".format(duration / 60))
    conn.commit()
    conn.close()


def get_today_sessions():
    """获取今天的监控会话记录（使用本地时间，避免UTC时区偏差）"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 使用 datetime('now', 'localtime') 获取本地日期，避免UTC/北京时间偏差
    c.execute("""SELECT start_time, end_time, duration, status, id
                 FROM monitor_sessions
                 WHERE date(start_time) = date('now', 'localtime')
                 ORDER BY start_time ASC""")
    rows = c.fetchall()
    conn.close()
    
    sessions = []
    for row in rows:
        sessions.append({
            "start": row[0],
            "end": row[1],
            "duration": row[2] or 0,
            "status": row[3],
            "id": row[4]
        })
    return sessions


def get_today_monitor_minutes():
    """
    计算今天每个小时的监控分钟数（0-23，每项为该小时监控分钟数0-60）
    用于前端24小时图表叠加显示
    """
    # 初始化24小时：每小时的监控分钟数
    hourly_minutes = [0] * 24
    
    sessions = get_today_sessions()
    now = datetime.now()
    
    for s in sessions:
        start = datetime.fromisoformat(s["start"])
        # 对于active session，用当前时间作为结束
        end = datetime.fromisoformat(s["end"]) if s["end"] else now
        
        # 遍历从start到end的每个小时
        current = start.replace(minute=0, second=0, microsecond=0)
        while current <= end:
            h = current.hour
            # 计算这个小时内重叠的分钟数
            hour_start = max(start, current)
            hour_end = min(end, current.replace(hour=current.hour + 1) if current.hour < 23 
                          else current.replace(hour=23, minute=59, second=59))
            
            if hour_start < hour_end:
                minutes = (hour_end - hour_start).total_seconds() / 60
                if 0 <= h < 24:
                    hourly_minutes[h] = min(60, hourly_minutes[h] + minutes)
            
            current += timedelta(hours=1)
    
    return hourly_minutes


def get_monitor_time_stats():
    """获取监控时长统计"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    
    # 今天的总监控时长（使用本地时间）
    c.execute("""SELECT id, start_time, end_time, duration, status
                 FROM monitor_sessions
                 WHERE date(start_time) = date('now', 'localtime')""")
    rows = c.fetchall()
    
    today_seconds = 0
    for row in rows:
        sid, start_str, end_str, duration, status = row
        if status == 'active':
            # 用Python计算当前会话的时长（避免SQLite时区问题）
            start = datetime.fromisoformat(start_str)
            today_seconds += (now - start).total_seconds()
        else:
            today_seconds += (duration or 0)
    
    # 最近7天的总监控时长
    c.execute("""SELECT id, start_time, end_time, duration, status
                 FROM monitor_sessions
                 WHERE start_time > datetime('now', '-7 days')""")
    rows = c.fetchall()
    
    week_seconds = 0
    for row in rows:
        sid, start_str, end_str, duration, status = row
        if status == 'active':
            start = datetime.fromisoformat(start_str)
            week_seconds += (now - start).total_seconds()
        else:
            week_seconds += (duration or 0)
    
    conn.close()
    return {
        "today_seconds": today_seconds,
        "week_seconds": week_seconds
    }

# =============================================================================
# 网络检测函数
# =============================================================================
def _decode_output(raw_bytes):
    """智能解码Windows命令行输出：UTF-8优先，GBK兜底"""
    if not raw_bytes:
        return ""
    try:
        return raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return raw_bytes.decode('gbk', errors='ignore')
        except:
            return raw_bytes.decode('utf-8', errors='ignore')

def _run_netsh(cmd_args, timeout=5):
    """运行netsh命令并返回解码后的stdout"""
    result = subprocess.run(cmd_args, capture_output=True,
                          timeout=timeout, creationflags=SUBPROCESS_FLAGS)
    return _decode_output(result.stdout)


def ping(host, timeout=3):
    """
    Ping一个主机，返回True（在线）或False（离线）
    """
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    
    try:
        output = subprocess.run(cmd, capture_output=True, timeout=timeout + 2,
                              creationflags=SUBPROCESS_FLAGS)
        return output.returncode == 0
    except Exception as e:
        print("[Ping] 错误: " + str(e))
        return False


def check_wifi_connected():
    """
    检查Windows WiFi连接状态
    返回: (已连接?, 状态描述)
    """
    if platform.system().lower() != "windows":
        return True, "non-windows"
    try:
        output = _run_netsh(['netsh', 'wlan', 'show', 'interfaces'])
        for line in output.split('\n'):
            if 'State' in line and ':' in line:
                state = line.split(':', 1)[1].strip()
                if 'connected' in state.lower():
                    return True, "connected"
                else:
                    return False, state
        return False, "no_wifi_interface"
    except Exception as e:
        return False, "error: " + str(e)


def check_ethernet_connected():
    """
    检查Windows有线网卡（以太网）连接状态
    """
    if platform.system().lower() != "windows":
        return False
    try:
        output = _run_netsh(['netsh', 'interface', 'show', 'interface'])
        for line in output.split('\n'):
            if ('已连接' in line or 'Connected' in line) and \
               ('以太网' in line or 'Ethernet' in line.lower() or '乙太網路' in line):
                return True
        return False
    except:
        return False


def check_network_connected():
    """
    检查网络连接状态（有线+WiFi双模检测）
    返回: (network_ok, eth_ok, wifi_ok)
    """
    wifi_ok, _ = check_wifi_connected()
    eth_ok = check_ethernet_connected()
    return (eth_ok or wifi_ok), eth_ok, wifi_ok

# =============================================================================
# 监控函数
# =============================================================================
def monitor():
    """主监控循环 — 快慢分离：ping每秒检测，netsh每30秒检测"""
    global monitoring, current_status, last_online_time, current_offline_start, last_wifi_status, monitor_session_id
    
    monitor_session_id = start_monitor_session()
    print("[Monitor] 监控线程已启动 (ping间隔={}s, 超时={}s)".format(PING_INTERVAL, TIMEOUT))
    print("[Monitor] 网络检测: 有线+WiFi双模")
    
    # 慢速检测初始化
    network_ok, eth_ok, wifi_ok = check_network_connected()
    last_netsh_check = time.time()
    loop_count = 0
    
    while monitoring:
        now = datetime.now()
        loop_count += 1
        
        # 慢速检测：网络接口状态（每NETSH_INTERVAL秒一次）
        if time.time() - last_netsh_check >= NETSH_INTERVAL:
            network_ok, eth_ok, wifi_ok = check_network_connected()
            last_netsh_check = time.time()
            # 更新连接类型显示
            if eth_ok and wifi_ok:
                stats["conn_type"] = "以太网 + WiFi"
            elif eth_ok:
                stats["conn_type"] = "以太网"
            elif wifi_ok:
                stats["conn_type"] = "WiFi"
            else:
                stats["conn_type"] = "无连接"
        
        # 快速检测：Ping CPE网关
        cpe_online = ping(PING_TARGET, timeout=TIMEOUT)
        
        # 失败时立即重试确认（避免偶发性丢包误判）
        if not cpe_online and network_ok:
            cpe_online = ping(PING_TARGET, timeout=RETRY_TIMEOUT)
        
        # 诊断日志（每60次~60秒打印）
        if loop_count % 60 == 1:
            print("[Diag] loop=%d net=%s eth=%s wifi=%s cpe=%s status=%s" % (
                loop_count, network_ok, eth_ok, wifi_ok, cpe_online, current_status))
        
        # 判断事件类型
        event_type = "unknown"
        is_online = True
        
        if not network_ok:
            event_type = "network_disconnected"
            is_online = False
        elif not cpe_online:
            event_type = "cpe_unreachable"
            is_online = False
        else:
            event_type = "online"
            is_online = True
        
        # 4. 状态变化检测
        if is_online:
            if current_status in ("offline", "network_disconnected", "cpe_unreachable"):
                # 刚刚恢复在线
                end_time = now
                start_time = current_offline_start
                duration = (end_time - start_time).total_seconds()
                
                print("[Monitor] 断流恢复: 持续 {:.1f} 秒, 类型: {}".format(duration, current_status))
                
                # 记录所有断流事件：网络完全断开 / CPE网关不可达
                if current_status in ('network_disconnected', 'cpe_unreachable'):
                    log_disconnection(start_time, end_time, duration, current_status)
                    print('[Monitor] 已记录断流事件: ' + current_status)
                    # 更新统计数据
                    stats["total_disconnections"] += 1
                    stats["total_downtime"] += duration
                    stats["avg_downtime"] = stats["total_downtime"] / stats["total_disconnections"]
                    stats["last_disconnection"] = end_time.isoformat()
                    disconnection_events.append({
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                        "duration": duration,
                        "event_type": current_status
                    })
                else:
                    print('[Monitor] 忽略未知事件: ' + current_status)
                
                stats["current_offline_start"] = None
                current_offline_start = None
            
            current_status = "online"
            last_online_time = now
        else:
            if current_status == "online" or current_status == "unknown":
                # 刚刚断流
                print("[Monitor] 检测到断流: 类型=" + event_type)
                current_offline_start = now
                stats["current_offline_start"] = now.isoformat()
            
            current_status = event_type
        
        stats["current_status"] = current_status
        last_wifi_status = wifi_ok
        
        time.sleep(PING_INTERVAL)
    
    # 监控循环结束，关闭会话
    end_monitor_session(monitor_session_id)

# =============================================================================
# Flask Web应用
# =============================================================================
app = Flask(__name__)

# HTML模板（嵌入式）
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CPE 断流监控</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #0f1117;
            --card-bg: rgba(22,24,34,0.9);
            --card-border: rgba(255,255,255,0.06);
            --text: #e4e6ed;
            --text-dim: #8b8fa3;
            --accent: #6366f1;
            --accent-glow: rgba(99,102,241,0.25);
            --green: #22c55e;
            --green-glow: rgba(34,197,94,0.25);
            --red: #ef4444;
            --red-glow: rgba(239,68,68,0.25);
            --radius: 14px; --gap: 16px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
            background: var(--bg);
            background-image: 
                radial-gradient(ellipse at 20% 0%, rgba(99,102,241,0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 100%, rgba(34,197,94,0.04) 0%, transparent 50%);
            color: var(--text); min-height: 100vh; padding: 24px;
        }
        .container { max-width: 1300px; margin: 0 auto; }

        .header {
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 24px; padding-bottom: 16px;
            border-bottom: 1px solid var(--card-border);
        }
        .logo { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg,var(--accent),#8b5cf6); display: flex; align-items: center; justify-content: center; font-size: 16px; }
        .header h1 { font-size: 20px; font-weight: 600; letter-spacing: -0.3px; }
        .sub { font-size: 12px; color: var(--text-dim); display: block; }

        .status-bar { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
        .status-pill { display: inline-flex; align-items: center; gap: 8px; padding: 8px 18px; border-radius: 50px; font-weight: 600; font-size: 14px; background: var(--card-bg); border: 1px solid var(--card-border); transition: all 0.3s; }
        .status-pill.online { color: var(--green); border-color: rgba(34,197,94,0.3); box-shadow: 0 0 16px var(--green-glow); }
        .status-pill.offline { color: var(--red); border-color: rgba(239,68,68,0.3); box-shadow: 0 0 16px var(--red-glow); animation: pulse-red 1.5s infinite; }
        .status-pill .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
        .status-pill.online .dot { animation: pulse-green 2s infinite; }
        @keyframes pulse-green { 0%,100%{box-shadow:0 0 0 0 var(--green-glow)} 50%{box-shadow:0 0 0 8px transparent} }
        @keyframes pulse-red { 0%,100%{box-shadow:0 0 0 0 var(--red-glow)} 50%{box-shadow:0 0 0 8px transparent} }

        .stat-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: var(--gap); margin-bottom: var(--gap); }
        .stat-grid.v2 { grid-template-columns: repeat(4,1fr); }
        .stat-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius); padding: 20px; transition: transform 0.2s, border-color 0.2s; }
        .stat-card:hover { transform: translateY(-2px); border-color: rgba(255,255,255,0.1); }
        .stat-card.primary { border-left: 3px solid var(--accent); }
        .stat-card.success { border-left: 3px solid var(--green); }
        .stat-card.warning { border-left: 3px solid #f59e0b; }
        .label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .value { font-size: 26px; font-weight: 700; }
        .desc { font-size: 11px; color: var(--text-dim); margin-top: 4px; }

        .chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: var(--gap); margin-bottom: var(--gap); }
        .chart-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius); padding: 20px; }
        .chart-title { font-size: 13px; font-weight: 600; color: var(--text-dim); margin-bottom: 12px; }
        .chart-wrap { position: relative; height: 260px; }

        .table-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius); padding: 20px; margin-bottom: var(--gap); }
        .table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .table-title { font-size: 13px; font-weight: 600; color: var(--text-dim); }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        thead th { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--card-border); color: var(--text-dim); font-weight: 500; font-size: 11px; text-transform: uppercase; }
        tbody td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.03); }
        tbody tr:hover { background: rgba(255,255,255,0.02); }

        .btn { padding: 8px 16px; border-radius: 8px; border: none; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
        .btn-primary { background: var(--accent); color: #fff; }
        .btn-primary:hover { background: #5558e6; box-shadow: 0 4px 12px var(--accent-glow); }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 50px; font-size: 11px; font-weight: 600; }
        .badge-danger { background: rgba(239,68,68,0.15); color: var(--red); }
        .badge-warn { background: rgba(245,158,11,0.15); color: #f59e0b; }
        .badge-info { background: rgba(99,102,241,0.15); color: var(--accent); }

        @media (max-width:900px) { .stat-grid,.chart-row { grid-template-columns: 1fr 1fr; } }
        @media (max-width:600px) { .stat-grid,.chart-row { grid-template-columns: 1fr; } body { padding: 12px; } }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="logo">📡</div>
        <div><h1>CPE 断流监控</h1><span class="sub">网络完全断开事件追踪 &middot; 有线/WiFi双模检测</span></div>
    </div>

    <div class="status-bar">
        <div id="status-pill" class="status-pill"><span class="dot"></span><span id="status-text">检测中...</span></div>
        <span id="status-detail" style="font-size:13px;color:var(--text-dim);"></span>
        <span id="conn-type" style="font-size:11px;color:var(--text-dim);background:var(--card-bg);padding:4px 10px;border-radius:50px;border:1px solid var(--card-border);"></span>
    </div>

    <div class="stat-grid">
        <div class="stat-card success"><div class="label">监控时长 (今日)</div><div class="value" id="monitor-today">--</div><div class="desc">实际监测覆盖时间</div></div>
        <div class="stat-card"><div class="label">断流次数 (7天)</div><div class="value" id="total-disconnections">0</div></div>
        <div class="stat-card warning"><div class="label">今日断流</div><div class="value" id="today-disconnections">0</div><div class="desc" id="today-downtime-label">断流总计 0 秒</div></div>
        <div class="stat-card primary"><div class="label">断流率</div><div class="value" id="disconnection-rate">--</div><div class="desc">次/监控小时</div></div>
    </div>
    <div class="stat-grid">
        <div class="stat-card"><div class="label">总断流时长</div><div class="value" id="total-downtime">0 秒</div></div>
        <div class="stat-card"><div class="label">平均断流时长</div><div class="value" id="avg-downtime">0 秒</div></div>
        <div class="stat-card"><div class="label">平均断流间隔</div><div class="value" id="avg-interval">--</div></div>
        <div class="stat-card success"><div class="label">监控时长 (7天)</div><div class="value" id="monitor-week">--</div><div class="desc">累计监测覆盖</div></div>
    </div>

    <div class="chart-row">
        <div class="chart-card"><div class="chart-title">📊 断流时长 (最近20次)</div><div class="chart-wrap"><canvas id="timeline-chart"></canvas></div></div>
        <div class="chart-card"><div class="chart-title">📈 24小时断流分布 <span style="font-weight:400;font-size:11px;color:#6366f1;">━━ 监控中</span> <span style="font-weight:400;font-size:11px;color:rgba(255,255,255,0.04);">━━ 未监测</span></div><div class="chart-wrap"><canvas id="hourly-chart"></canvas></div></div>
    </div>

    <div class="table-card">
        <div class="table-header"><span class="table-title">📋 断流历史记录</span><button class="btn btn-primary" onclick="exportCSV()">导出 CSV</button></div>
        <table>
            <thead><tr><th>#</th><th>开始时间</th><th>结束时间</th><th>持续(秒)</th><th>持续(分:秒)</th><th>类型</th></tr></thead>
            <tbody id="history-table"><tr><td colspan="6" style="text-align:center;color:var(--text-dim);">暂无断流记录</td></tr></tbody>
        </table>
    </div>
</div>
<script>
let timelineChart=null,hourlyChart=null;
function initTimelineChart(){
    const ctx=document.getElementById('timeline-chart').getContext('2d');
    timelineChart=new Chart(ctx,{
        type:'bar',
        data:{labels:[],datasets:[{label:'断流时长(秒)',data:[],backgroundColor:'rgba(239,68,68,0.35)',borderColor:'#ef4444',borderWidth:1.5,borderRadius:6}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
            scales:{y:{beginAtZero:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#8b8fa3'}},x:{ticks:{color:'#8b8fa3',maxRotation:0}}}}
    });
}
function initHourlyChart(){
    const ctx=document.getElementById('hourly-chart').getContext('2d');
    hourlyChart=new Chart(ctx,{
        type:'line',
        data:{labels:[],datasets:[
            {label:'监控覆盖',data:[],backgroundColor:'rgba(99,102,241,0.08)',borderColor:'transparent',fill:true,pointRadius:0,tension:0,order:2},
            {label:'断流次数',data:[],backgroundColor:'rgba(239,68,68,0.1)',borderColor:'#ef4444',borderWidth:2,tension:0.4,fill:true,pointBackgroundColor:'#ef4444',pointRadius:3,order:1}
        ]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{
            label:function(ctx){if(ctx.datasetIndex===0){const m=ctx.raw;return m>0?'监控覆盖: '+m.toFixed(0)+' 分钟':'未监测';}return '断流: '+ctx.raw+' 次';}
        }}},
            scales:{y:{beginAtZero:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#8b8fa3',stepSize:1}},x:{ticks:{color:'#8b8fa3',maxTicksLimit:12,maxRotation:0}}}}
    });
}
function formatDuration(s){const m=Math.floor(s/60),sec=Math.floor(s%60);return String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');}
function formatHours(s){if(s<60)return Math.round(s)+' 秒';if(s<3600)return (s/60).toFixed(1)+' 分钟';return (s/3600).toFixed(1)+' 小时';}
function updateData(){
    fetch('/api/status').then(r=>r.json()).then(d=>{
        const pill=document.getElementById('status-pill'),txt=document.getElementById('status-text');
        const detail=document.getElementById('status-detail'),conn=document.getElementById('conn-type');
        pill.className='status-pill';
        if(d.current_status==='online'){pill.classList.add('online');txt.textContent='● 在线';detail.textContent='';}
        else if(d.current_status==='network_disconnected'){pill.classList.add('offline');txt.textContent='● 断流中';
            if(d.current_offline_start){const dur=(new Date()-new Date(d.current_offline_start))/1000;detail.textContent='已断流 '+Math.floor(dur)+' 秒';}}
        else if(d.current_status==='cpe_unreachable'){pill.classList.add('offline');txt.textContent='● CPE不可达';
            if(d.current_offline_start){const dur=(new Date()-new Date(d.current_offline_start))/1000;detail.textContent='CPE无响应 '+Math.floor(dur)+' 秒';}}
        else{txt.textContent='检测中...';detail.textContent='';}
        conn.textContent=d.conn_type||'';
        document.getElementById('monitor-today').textContent=formatHours(d.monitor_today_seconds||0);
        document.getElementById('total-disconnections').textContent=d.total_disconnections;
        document.getElementById('today-disconnections').textContent=d.today_disconnections||0;
        document.getElementById('today-downtime-label').textContent='断流总计 '+(d.today_downtime||0).toFixed(1)+' 秒';
        document.getElementById('disconnection-rate').textContent=(d.disconnection_rate||0).toFixed(2);
        document.getElementById('total-downtime').textContent=d.total_downtime.toFixed(1)+' 秒';
        document.getElementById('avg-downtime').textContent=d.avg_downtime.toFixed(1)+' 秒';
        document.getElementById('avg-interval').textContent=d.avg_interval>0?(d.avg_interval/3600).toFixed(1)+' 小时':'--';
        document.getElementById('monitor-week').textContent=formatHours(d.monitor_week_seconds||0);
    }).catch(console.error);
    fetch('/api/events?limit=20').then(r=>r.json()).then(events=>{
        const rev=[...events].reverse();
        timelineChart.data.labels=rev.map((_,i)=>'#'+(i+1));
        timelineChart.data.datasets[0].data=rev.map(e=>e.duration);timelineChart.update();
        const tbody=document.getElementById('history-table');tbody.innerHTML='';
        if(events.length===0){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--text-dim);">暂无断流记录</td></tr>';}
        else{events.forEach((e,i)=>{const r=tbody.insertRow();
            r.insertCell(0).textContent=i+1;r.insertCell(1).textContent=e.start;
            r.insertCell(2).textContent=e.end;r.insertCell(3).textContent=e.duration.toFixed(1);
            r.insertCell(4).textContent=formatDuration(e.duration);
            r.insertCell(5).innerHTML='<span class="badge '+(e.event_type==='network_disconnected'?'badge-danger':'badge-warn')+'">'+(e.event_type||'unknown')+'</span>';});
        }
    }).catch(console.error);
    fetch('/api/hourly_stats').then(r=>r.json()).then(d=>{
        hourlyChart.data.labels=d.labels;
        // 监控覆盖：将分钟数归一化到图表可见范围（0-60分钟 -> 0-maxY视觉区域）
        const monitorMins = d.monitor_minutes || [];
        const maxDisconn = Math.max(1, ...(d.data||[]));
        hourlyChart.data.datasets[0].data = monitorMins.map(function(m){return m/60*maxDisconn*0.8;}); // 缩放以匹配视觉范围
        hourlyChart.data.datasets[1].data = d.data;
        hourlyChart.update();
    }).catch(console.error);
}
function exportCSV(){fetch('/api/export').then(r=>r.blob()).then(b=>{const u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='cpe_monitor_'+new Date().toISOString().split('T')[0]+'.csv';a.click();URL.revokeObjectURL(u);}).catch(console.error);}
document.addEventListener('DOMContentLoaded',()=>{initTimelineChart();initHourlyChart();updateData();setInterval(updateData,5000);});
</script>
</body>
</html>"""


# =============================================================================
# Flask路由
# =============================================================================
@app.route('/')
def index():
    """主页"""
    return render_template_string(HTML_TEMPLATE, 
                                 target=PING_TARGET,
                                 db_path=DB_PATH)

@app.route('/api/status')
def api_status():
    """获取当前状态和统计"""
    db_stats = get_stats_from_db()
    # 只合并 DB 中不冲突的字段（保留内存中实时更新的 current_status 等）
    for k in ('avg_interval', 'last_disconnection'):
        if k in db_stats:
            stats[k] = db_stats[k]
    
    # 附加监控时长统计
    time_stats = get_monitor_time_stats()
    today_sec = time_stats["today_seconds"]
    
    # 今天的断流次数（只统计今天的，使用本地时间避免UTC偏差）
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*), COALESCE(SUM(duration),0) FROM events WHERE date(start_time) = date('now', 'localtime')")
    today_events, today_downtime = c.fetchone()
    conn.close()
    
    stats["monitor_today_seconds"] = today_sec
    stats["monitor_today_hours"] = round(today_sec / 3600, 1)
    stats["monitor_week_seconds"] = time_stats["week_seconds"]
    stats["today_disconnections"] = today_events or 0
    stats["today_downtime"] = today_downtime or 0
    
    # 断流率 = 今日断流次数 / 今日监控小时数
    if today_sec > 0:
        stats["disconnection_rate"] = round((today_events or 0) / (today_sec / 3600), 2)
    else:
        stats["disconnection_rate"] = 0
    
    return jsonify(stats)

@app.route('/api/events')
def api_events():
    """获取断流事件列表"""
    limit = request.args.get('limit', 100, type=int)
    events = get_recent_events(limit)
    return jsonify(events)

@app.route('/api/hourly_stats')
def api_hourly_stats():
    """获取24小时断流统计（含监控时段覆盖数据）"""
    result = get_hourly_stats()
    # 附加今天的监控分钟数，前端用做覆盖层
    result["monitor_minutes"] = get_today_monitor_minutes()
    return jsonify(result)

@app.route('/api/monitor_sessions')
def api_monitor_sessions():
    """获取今天的监控会话记录"""
    sessions = get_today_sessions()
    time_stats = get_monitor_time_stats()
    return jsonify({
        "sessions": sessions,
        "today_seconds": time_stats["today_seconds"],
        "today_hours": round(time_stats["today_seconds"] / 3600, 1),
        "week_seconds": time_stats["week_seconds"]
    })

@app.route('/api/today_monitor_hours')
def api_today_monitor_hours():
    """获取今天24小时每小时的监控分钟数"""
    return jsonify({
        "labels": ["{:02d}:00".format(i) for i in range(24)],
        "data": get_today_monitor_minutes()
    })

@app.route('/api/export')
def api_export():
    """导出CSV文件"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    
    # 生成CSV内容
    csv_content = "ID,开始时间,结束时间,持续时长(秒),持续时长(分:秒),断流类型\n"
    for row in rows:
        duration = row[3]
        mins = int(duration // 60)
        secs = int(duration % 60)
        duration_fmt = "{:02d}:{:02d}".format(mins, secs)
        event_type = row[4] if len(row) > 4 else 'unknown'
        csv_content += "{},{},{},{:.1f},{},{}\n".format(
            row[0], row[1], row[2], duration, duration_fmt, event_type)
    
    # 返回CSV文件
    response = Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=cpe_monitor_export.csv'}
    )
    return response

@app.route('/api/test_disconnect')
def api_test_disconnect():
    """测试端点：模拟一次 cpe_unreachable 事件（3秒后自动恢复）"""
    global current_status, current_offline_start
    if current_status != "online":
        return jsonify({"error": "当前不在线，无法测试", "status": current_status})
    
    now = datetime.now()
    # 模拟3秒前的断流
    start_time = now - timedelta(seconds=3)
    end_time = now
    duration = 3.0
    
    # 直接记录（模拟 recovery）
    log_disconnection(start_time, end_time, duration, "cpe_unreachable")
    stats["total_disconnections"] += 1
    stats["total_downtime"] += duration
    stats["avg_downtime"] = stats["total_downtime"] / stats["total_disconnections"]
    stats["last_disconnection"] = end_time.isoformat()
    disconnection_events.append({
        "start": start_time.isoformat(),
        "end": end_time.isoformat(),
        "duration": duration,
        "event_type": "cpe_unreachable"
    })
    
    return jsonify({
        "test": "ok",
        "event_type": "cpe_unreachable",
        "duration": duration,
        "message": "已模拟一条 cpe_unreachable 断流事件（3秒）"
    })

# =============================================================================
# 主程序入口
# =============================================================================
if __name__ == '__main__':
    print("=" * 60)
    print("CPE Network Disconnection Monitor")
    print("CPE网络断流监控工具 v1.1")
    print("=" * 60)
    
    # 初始化数据库
    print("[Init] 初始化数据库...")
    init_db()
    
    # 启动监控线程
    print("[Init] 启动监控线程...")
    monitoring = True
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    
    # 等待一下让监控线程开始工作
    time.sleep(1)
    
    # 启动Flask Web服务器
    print("[Init] 启动Web服务器...")
    print("[Init] 请在浏览器中打开: http://localhost:5000")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
