#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPE Network Disconnection Monitor v2.9.1
CPE网络断流监控工具 - 多维度检测 + 连续失败阈值

修复内容（v2.9.1）：
1. 修复遗留会话的结束时间显示为"进行中..."的问题
2. 修复退出时未调用end_monitor_session()导致会话未正确关闭
3. 监控时段表格增加"断流次数"列
4. 修复数据库初始化时遗留active会话未设置end_time和duration

优化内容（v2.9）：
1. 多维度探测：ICMP ping网关 + ICMP ping公网 + TCP连接检测 + DNS解析检测
2. 连续失败阈值：连续3次检测失败才判定为断流（避免偶发丢包误判）
3. 快速恢复检测：连续2次检测成功才判定为恢复（避免抖动）
4. 缩短检测间隔：ping间隔1秒，TCP/DNS检测每3秒一次
5. 记录断流类型：区分CPE网关不可达、外网不可达、DNS解析失败、TCP连接失败
"""

import threading
import time
import subprocess
import platform
import json
import sqlite3
import os
import sys
import socket
import datetime
from datetime import datetime, timedelta
from collections import deque
from flask import Flask, render_template_string, jsonify, request, Response

# =============================================================================
# 配置部分
# =============================================================================
PING_TARGET = "192.168.10.1"  # CPE网关（准确检测CPE是否在线）
PING_EXTERNAL = "8.8.8.8"     # 外网检测目标（Google DNS）
DNS_TEST_DOMAIN = "www.baidu.com"  # DNS解析测试域名
TCP_TEST_HOST = "www.baidu.com"     # TCP连接测试主机
TCP_TEST_PORT = 80                    # TCP连接测试端口
TCP_TEST_INTERVAL = 3                 # TCP检测间隔（秒）
DNS_TEST_INTERVAL = 3                 # DNS检测间隔（秒）

PING_INTERVAL = 1                    # Ping间隔（秒）
TIMEOUT = 2                          # Ping超时（秒）
FAILURE_THRESHOLD = 3               # 连续失败次数阈值（连续3次失败 = 断流）
RECOVERY_THRESHOLD = 2               # 连续恢复次数阈值（连续2次成功 = 恢复）
NETSH_INTERVAL = 10                  # 网络接口状态检查间隔（秒，缩短为10秒）

SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0

# DB路径：exe所在目录（PyInstaller打包）或脚本所在目录（直接运行）
if getattr(sys, 'frozen', False):
    DB_PATH = os.path.join(os.path.dirname(sys.executable), "cpe_monitor.db")
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpe_monitor.db")

CHECK_WIFI = True                    # 是否检测WiFi连接状态（Windows Only）

# =============================================================================
# 全局状态
# =============================================================================
monitoring = False
monitor_thread = None
monitor_session_id = None  # 当前监控会话ID

# 多维度检测结果
ping_gateway_fail_count = 0    # ping网关连续失败次数
ping_external_fail_count = 0    # ping公网连续失败次数
tcp_test_fail_count = 0         # TCP连接连续失败次数
dns_test_fail_count = 0          # DNS解析连续失败次数

# 综合状态
consecutive_failures = 0        # 综合连续失败次数
consecutive_successes = 0       # 综合连续成功次数
current_status = "online"        # "online", "disconnected"
disconnection_start_time = None   # 当前断流开始时间
disconnection_type = None         # 断流类型

# 统计数据
disconnection_events = deque(maxlen=1000)  # 存储最近1000次断流事件
stats = {
    "total_disconnections": 0,
    "total_downtime": 0,
    "avg_downtime": 0,
    "avg_interval": 0,
    "last_disconnection": None,
    "current_status": "online",
    "current_offline_start": None,
    "conn_type": "检测中...",
    "version": "v2.9.1",
    # 多维度统计
    "ping_gateway_fail_rate": 0,
    "ping_external_fail_rate": 0,
    "tcp_fail_rate": 0,
    "dns_fail_rate": 0,
}

# 上次网络接口检测结果
last_network_ok = True
last_eth_ok = False
last_wifi_ok = False
last_netsh_check = 0

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
    # 同时设置 end_time 和 duration，避免前端显示"进行中..."
    now = datetime.now()
    c.execute("""UPDATE monitor_sessions 
                 SET end_time = ?, duration = (julianday(?) - julianday(start_time)) * 86400, status = 'interrupted'
                 WHERE status = 'active'""", (now.isoformat(), now.isoformat()))
    
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
    """获取今天的监控会话记录，附带每个时段的断流次数"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT start_time, end_time, duration, status, id
                 FROM monitor_sessions
                 WHERE date(start_time) = date('now', 'localtime')
                 ORDER BY start_time ASC""")
    rows = c.fetchall()
    
    sessions = []
    for row in rows:
        sid, start, end, duration, status = row[4], row[0], row[1], row[2] or 0, row[3]
        # 计算该会话时段内的断流次数
        end_q = end if end else datetime.now().isoformat()
        c.execute("""SELECT COUNT(*) FROM events
                     WHERE start_time >= ? AND start_time <= ?""",
                  (start, end_q))
        disconnection_count = c.fetchone()[0]
        sessions.append({
            "start": start,
            "end": end,
            "duration": duration,
            "status": status,
            "id": sid,
            "disconnections": disconnection_count
        })
    conn.close()
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
# 网络检测函数（多维度）
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

def tcp_connect_test(host=TCP_TEST_HOST, port=TCP_TEST_PORT, timeout=3):
    """
    TCP连接测试：尝试连接到指定主机的指定端口
    返回True（连接成功）或False（连接失败）
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def dns_resolve_test(domain=DNS_TEST_DOMAIN, timeout=3):
    """
    DNS解析测试：尝试解析指定域名
    返回True（解析成功）或False（解析失败）
    """
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(domain)
        return True
    except Exception as e:
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
# 监控函数（多维度 + 连续失败阈值）
# =============================================================================
def monitor():
    """主监控循环 — 多维度检测 + 连续失败阈值"""
    global monitoring, current_status, stats
    global ping_gateway_fail_count, ping_external_fail_count
    global tcp_test_fail_count, dns_test_fail_count
    global consecutive_failures, consecutive_successes
    global disconnection_start_time, disconnection_type
    global last_network_ok, last_eth_ok, last_wifi_ok, last_netsh_check
    global monitor_session_id
    
    monitor_session_id = start_monitor_session()
    print("[Monitor] 监控线程已启动 (v2.9.1 多维度检测)")
    print("[Monitor] Ping网关: {} (间隔{}s)".format(PING_TARGET, PING_INTERVAL))
    print("[Monitor] Ping公网: {} (间隔{}s)".format(PING_EXTERNAL, PING_INTERVAL))
    print("[Monitor] TCP检测: {}:{} (间隔{}s)".format(TCP_TEST_HOST, TCP_TEST_PORT, TCP_TEST_INTERVAL))
    print("[Monitor] DNS检测: {} (间隔{}s)".format(DNS_TEST_DOMAIN, DNS_TEST_INTERVAL))
    print("[Monitor] 失败阈值: 连续{}次 => 断流".format(FAILURE_THRESHOLD))
    print("[Monitor] 恢复阈值: 连续{}次 => 恢复".format(RECOVERY_THRESHOLD))
    
    # 初始化检测计时器
    last_tcp_check = time.time()
    last_dns_check = time.time()
    loop_count = 0
    
    while monitoring:
        now = datetime.now()
        loop_count += 1
        current_time = time.time()
        
        # 1. 网络接口状态检测（每NETSH_INTERVAL秒一次）
        if current_time - last_netsh_check >= NETSH_INTERVAL:
            last_network_ok, last_eth_ok, last_wifi_ok = check_network_connected()
            last_netsh_check = current_time
            # 更新连接类型显示
            if last_eth_ok and last_wifi_ok:
                stats["conn_type"] = "以太网 + WiFi"
            elif last_eth_ok:
                stats["conn_type"] = "以太网"
            elif last_wifi_ok:
                stats["conn_type"] = "WiFi"
            else:
                stats["conn_type"] = "无连接"
        
        # 2. 多维度快速检测
        # 2.1 ICMP Ping 网关
        ping_gateway_ok = ping(PING_TARGET, timeout=TIMEOUT)
        
        # 2.2 ICMP Ping 公网（如果网关可达）
        ping_external_ok = ping(PING_EXTERNAL, timeout=TIMEOUT) if ping_gateway_ok else False
        
        # 2.3 TCP连接检测（每TCP_TEST_INTERVAL秒一次）
        tcp_ok = True
        if current_time - last_tcp_check >= TCP_TEST_INTERVAL:
            tcp_ok = tcp_connect_test()
            last_tcp_check = current_time
        
        # 2.4 DNS解析检测（每DNS_TEST_INTERVAL秒一次）
        dns_ok = True
        if current_time - last_dns_check >= DNS_TEST_INTERVAL:
            dns_ok = dns_resolve_test()
            last_dns_check = current_time
        
        # 3. 更新连续失败/成功计数
        # 综合判断：网关不可达 OR (网关可达但外网不可达 AND TCP失败 AND DNS失败)
        is_network_ok = last_network_ok
        is_gateway_ok = ping_gateway_ok
        is_external_ok = ping_external_ok or tcp_ok or dns_ok  # 任意一个外网检测成功即可
        
        if is_network_ok and is_gateway_ok and is_external_ok:
            # 网络正常
            consecutive_successes += 1
            consecutive_failures = 0
        else:
            # 网络异常
            consecutive_failures += 1
            consecutive_successes = 0
        
        # 4. 诊断日志（每60次~60秒打印）
        if loop_count % 60 == 1:
            print("[Diag] loop={} net={} gw={} ext={} tcp={} dns={} fail={} success={} status={}".format(
                loop_count, is_network_ok, is_gateway_ok, is_external_ok, tcp_ok, dns_ok,
                consecutive_failures, consecutive_successes, current_status))
        
        # 5. 断流检测：连续失败达到阈值
        if consecutive_failures >= FAILURE_THRESHOLD and current_status == "online":
            # 判定为断流
            disconnection_start_time = now
            current_status = "disconnected"
            stats["current_status"] = current_status
            stats["current_offline_start"] = now.isoformat()
            
            # 判断断流类型
            if not is_network_ok:
                disconnection_type = "network_disconnected"
            elif not is_gateway_ok:
                disconnection_type = "cpe_unreachable"
            elif not is_external_ok:
                disconnection_type = "external_unreachable"
            else:
                disconnection_type = "unknown"
            
            print("[Monitor] 检测到断流: 类型={} (连续{}次失败)".format(disconnection_type, consecutive_failures))
        
        # 6. 恢复检测：连续成功达到阈值
        elif consecutive_successes >= RECOVERY_THRESHOLD and current_status == "disconnected":
            # 判定为恢复
            end_time = now
            duration = (end_time - disconnection_start_time).total_seconds()
            
            print("[Monitor] 断流恢复: 持续 {:.1f} 秒, 类型: {}".format(duration, disconnection_type))
            
            # 记录断流事件
            if disconnection_type:
                log_disconnection(disconnection_start_time, end_time, duration, disconnection_type)
                print('[Monitor] 已记录断流事件: ' + disconnection_type)
                
                # 更新统计数据
                stats["total_disconnections"] += 1
                stats["total_downtime"] += duration
                stats["avg_downtime"] = stats["total_downtime"] / stats["total_disconnections"]
                stats["last_disconnection"] = end_time.isoformat()
                disconnection_events.append({
                    "start": disconnection_start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "duration": duration,
                    "event_type": disconnection_type
                })
            
            # 重置状态
            current_status = "online"
            stats["current_status"] = current_status
            stats["current_offline_start"] = None
            disconnection_start_time = None
            disconnection_type = None
        
        # 7. 更新统计数据中的失败率
        stats["ping_gateway_fail_rate"] = ping_gateway_fail_count / max(1, loop_count)
        stats["ping_external_fail_rate"] = ping_external_fail_count / max(1, loop_count // PING_INTERVAL)
        
        # 8. 等待下一个检测周期
        time.sleep(PING_INTERVAL)
    
    # 监控循环结束，关闭会话
    end_monitor_session(monitor_session_id)

# =============================================================================
# Flask Web应用
# =============================================================================
app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CPE 断流监控 v2.9.1</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Segoe UI', sans-serif; background:#f5f6fa; color:#2d3436; }
        .container { max-width:1200px; margin:0 auto; padding:20px; }
        .header { background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:white; padding:30px; border-radius:15px; margin-bottom:30px; box-shadow:0 10px 30px rgba(0,0,0,0.1); }
        .header h1 { font-size:28px; margin-bottom:10px; }
        .header p { opacity:0.9; font-size:14px; }
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:20px; margin-bottom:30px; }
        .stat-card { background:white; padding:25px; border-radius:15px; box-shadow:0 5px 15px rgba(0,0,0,0.05); transition:transform 0.3s; }
        .stat-card:hover { transform:translateY(-5px); }
        .stat-label { font-size:13px; color:#636e72; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px; }
        .stat-value { font-size:32px; font-weight:700; color:#2d3436; }
        .stat-value.online { color:#00b894; }
        .stat-value.disconnected { color:#d63031; }
        .chart-container { background:white; padding:25px; border-radius:15px; box-shadow:0 5px 15px rgba(0,0,0,0.05); margin-bottom:30px; }
        .chart-container h3 { margin-bottom:20px; color:#2d3436; font-size:18px; }
        canvas { max-height:300px; }
        .events-table { background:white; padding:25px; border-radius:15px; box-shadow:0 5px 15px rgba(0,0,0,0.05); }
        .events-table h3 { margin-bottom:20px; color:#2d3436; font-size:18px; }
        table { width:100%; border-collapse:collapse; }
        th { background:#f8f9fa; padding:12px; text-align:left; font-size:13px; color:#636e72; border-bottom:2px solid #e9ecef; }
        td { padding:12px; border-bottom:1px solid #e9ecef; font-size:14px; }
        .status-badge { display:inline-block; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:600; }
        .status-badge.online { background:#00b89420; color:#00b894; }
        .status-badge.disconnected { background:#d6303120; color:#d63031; }
        .status-badge.cpe_unreachable { background:#fdcb6e20; color:#fdcb6e; }
        .refresh-btn { position:fixed; bottom:30px; right:30px; background:#667eea; color:white; border:none; padding:15px 25px; border-radius:50px; cursor:pointer; box-shadow:0 5px 15px rgba(102,126,234,0.3); font-size:14px; font-weight:600; }
        .refresh-btn:hover { background:#5a6fd6; }
        .monitor-sessions { background:white; padding:25px; border-radius:15px; box-shadow:0 5px 15px rgba(0,0,0,0.05); margin-bottom:30px; }
        .monitor-sessions h3 { margin-bottom:20px; color:#2d3436; font-size:18px; }
        .hourly-chart { background:white; padding:25px; border-radius:15px; box-shadow:0 5px 15px rgba(0,0,0,0.05); margin-bottom:30px; }
        .hourly-chart h3 { margin-bottom:20px; color:#2d3436; font-size:18px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📡 CPE 断流监控</h1>
            <p>版本: <span id="version">v2.9.1</span> | 连接类型: <span id="conn-type">检测中...</span> | 监控时长: <span id="monitor-hours">0</span> 小时</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">当前状态</div>
                <div class="stat-value" id="current-status">检测中...</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">今天断流次数</div>
                <div class="stat-value" id="today-events">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">今天断流时长</div>
                <div class="stat-value" id="today-downtime">0 秒</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">平均断流间隔</div>
                <div class="stat-value" id="avg-interval">-- 小时</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">平均断流时长</div>
                <div class="stat-value" id="avg-downtime">0 秒</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">最后一次断流</div>
                <div class="stat-value" id="last-disconnection" style="font-size:16px;">--</div>
            </div>
        </div>

        <div class="monitor-sessions">
            <h3>📊 今日监控时段</h3>
            <div id="sessions-list">加载中...</div>
        </div>

        <div class="hourly-chart">
            <h3>📈 24小时断流分布 + 监控时长</h3>
            <canvas id="hourlyChart"></canvas>
        </div>

        <div class="events-table">
            <h3>📋 最近断流事件</h3>
            <table>
                <thead>
                    <tr>
                        <th>开始时间</th>
                        <th>结束时间</th>
                        <th>持续时长</th>
                        <th>类型</th>
                    </tr>
                </thead>
                <tbody id="events-tbody">
                    <tr><td colspan="4" style="text-align:center; color:#636e72;">暂无数据</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <button class="refresh-btn" onclick="location.reload()">🔄 刷新数据</button>

    <script>
        // 24小时图表
        const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
        let hourlyChart = new Chart(hourlyCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [
                    {
                        label: '断流次数',
                        data: [],
                        backgroundColor: 'rgba(214, 48, 49, 0.6)',
                        borderColor: 'rgba(214, 48, 49, 1)',
                        borderWidth: 1,
                        yAxisID: 'y'
                    },
                    {
                        label: '监控分钟数',
                        data: [],
                        type: 'line',
                        fill: false,
                        borderColor: 'rgba(102, 126, 234, 1)',
                        backgroundColor: 'rgba(102, 126, 234, 0.2)',
                        tension: 0.4,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        position: 'left',
                        title: { display: true, text: '断流次数' }
                    },
                    y1: {
                        beginAtZero: true,
                        position: 'right',
                        title: { display: true, text: '监控分钟数' },
                        grid: { drawOnChartArea: false }
                    }
                }
            }
        });

        function updateData() {
            fetch('/api/status')
                .then(r => r.json())
                .then(d => {
                    // 更新状态
                    const statusEl = document.getElementById('current-status');
                    statusEl.textContent = d.current_status === 'online' ? '✅ 在线' : '❌ 断流中';
                    statusEl.className = 'stat-value ' + d.current_status;

                    document.getElementById('today-events').textContent = d.total_disconnections;
                    document.getElementById('today-downtime').textContent = d.total_downtime.toFixed(1) + ' 秒';
                    document.getElementById('avg-downtime').textContent = d.avg_downtime.toFixed(1) + ' 秒';
                    document.getElementById('avg-interval').textContent = d.avg_interval > 0 ? (d.avg_interval / 3600).toFixed(1) + ' 小时' : '--';
                    document.getElementById('last-disconnection').textContent = d.last_disconnection || '--';
                    document.getElementById('conn-type').textContent = d.conn_type;
                    document.getElementById('version').textContent = d.version;

                    // 监控时长
                    fetch('/api/today_monitor_hours')
                        .then(r => r.json())
                        .then(h => {
                            const totalMinutes = h.total_minutes || 0;
                            document.getElementById('monitor-hours').textContent = (totalMinutes / 60).toFixed(1);
                        });
                });

            // 更新事件列表
            fetch('/api/events?limit=20')
                .then(r => r.json())
                .then(events => {
                    const tbody = document.getElementById('events-tbody');
                    if (events.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#636e72;">暂无数据</td></tr>';
                        return;
                    }
                    tbody.innerHTML = '';
                    events.forEach(ev => {
                        const typeClass = ev.event_type === 'cpe_unreachable' ? 'cpe_unreachable' : 'disconnected';
                        const typeText = ev.event_type === 'cpe_unreachable' ? 'CPE不可达' : 
                                        ev.event_type === 'network_disconnected' ? '网络断开' :
                                        ev.event_type === 'external_unreachable' ? '外网不可达' : '未知';
                        tbody.innerHTML += `
                            <tr>
                                <td>${ev.start}</td>
                                <td>${ev.end}</td>
                                <td>${ev.duration.toFixed(1)} 秒</td>
                                <td><span class="status-badge ${typeClass}">${typeText}</span></td>
                            </tr>
                        `;
                    });
                });

            // 更新监控会话
            fetch('/api/monitor_sessions')
                .then(r => r.json())
                .then(sessions => {
                    const container = document.getElementById('sessions-list');
                    if (sessions.length === 0) {
                        container.innerHTML = '<p style="color:#636e72;">今日暂无监控记录</p>';
                        return;
                    }
                    let html = '<table><thead><tr><th>开始时间</th><th>结束时间</th><th>持续时长</th><th>断流次数</th><th>状态</th></tr></thead><tbody>';
                    sessions.forEach(s => {
                        const end = s.end || '进行中...';
                        const status = s.status === 'active' ? '🟢 监测中' : '⚪ 已结束';
                        const dc = s.disconnections || 0;
                        const dcStyle = dc > 0 ? 'style="color:#e74c3c;font-weight:bold;"' : 'style="color:#27ae60;"';
                        html += `<tr><td>${s.start}</td><td>${end}</td><td>${(s.duration / 60).toFixed(1)} 分钟</td><td ${dcStyle}>${dc} 次</td><td>${status}</td></tr>`;
                    });
                    html += '</tbody></table>';
                    container.innerHTML = html;
                });

            // 更新24小时图表
            fetch('/api/hourly_stats')
                .then(r => r.json())
                .then(data => {
                    hourlyChart.data.labels = data.labels;
                    hourlyChart.data.datasets[0].data = data.data;
                    
                    // 获取监控分钟数
                    fetch('/api/today_monitor_minutes')
                        .then(r => r.json())
                        .then(minutes => {
                            hourlyChart.data.datasets[1].data = minutes;
                            hourlyChart.update();
                        });
                });
        }

        // 初始化
        updateData();
        setInterval(updateData, 5000);
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status')
def api_status():
    """返回当前状态和统计"""
    db_stats = get_stats_from_db()
    monitor_time = get_monitor_time_stats()
    
    today_minutes = monitor_time["today_seconds"] / 60
    
    return jsonify({
        "current_status": stats["current_status"],
        "total_disconnections": db_stats["total_disconnections"],
        "total_downtime": db_stats["total_downtime"],
        "avg_downtime": db_stats["avg_downtime"] or 0,
        "avg_interval": db_stats["avg_interval"] or 0,
        "last_disconnection": db_stats["last_disconnection"],
        "current_offline_start": stats["current_offline_start"],
        "conn_type": stats["conn_type"],
        "version": stats["version"],
        "today_monitor_minutes": today_minutes
    })

@app.route('/api/events')
def api_events():
    """返回最近的断流事件"""
    limit = int(request.args.get('limit', 50))
    return jsonify(get_recent_events(limit))

@app.route('/api/hourly_stats')
def api_hourly_stats():
    """返回24小时断流统计"""
    return jsonify(get_hourly_stats())

@app.route('/api/monitor_sessions')
def api_monitor_sessions():
    """返回今天的监控会话"""
    return jsonify(get_today_sessions())

@app.route('/api/today_monitor_hours')
def api_today_monitor_hours():
    """返回今天的监控时长（小时）"""
    monitor_time = get_monitor_time_stats()
    return jsonify({
        "today_hours": monitor_time["today_seconds"] / 3600,
        "today_minutes": monitor_time["today_seconds"] / 60,
        "week_hours": monitor_time["week_seconds"] / 3600
    })

@app.route('/api/today_monitor_minutes')
def api_today_monitor_minutes():
    """返回今天每小时的监控分钟数"""
    return jsonify(get_today_monitor_minutes())

@app.route('/api/test_disconnect', methods=['POST'])
def api_test_disconnect():
    """测试用：模拟一次断流事件"""
    start = datetime.now() - timedelta(seconds=3)
    end = datetime.now()
    duration = 3.0
    log_disconnection(start, end, duration, 'test')
    return jsonify({"status": "ok", "message": "测试事件已记录"})

# =============================================================================
# 主入口
# =============================================================================
if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("CPE 断流监控 v2.9.1")
    print("多维度检测 + 连续失败阈值")
    print("=" * 50)
    
    # 启动监控线程
    monitoring = True
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    
    # 启动Flask
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
