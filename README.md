# CPE 断流监控

CPE网络断流监控工具，托盘常驻后台运行，实时检测网络断流事件。

## 功能

- 🖥️ **系统托盘常驻**：关闭窗口=最小化到托盘，后台持续监控
- 📊 **浏览器面板**：Chart.js 可视化图表，24h断流分布 + 断流时长统计
- 🔍 **双重检测**：网络接口状态 + CPE网关可达性，准确区分断流类型
- ⏱️ **监控会话追踪**：记录实际监控时长，断流率 = 断流次数/监控小时数
- 📋 **CSV导出**：一键导出历史记录

## 断流类型

| 类型 | 颜色 | 含义 |
|---|---|---|
| `network_disconnected` | 🔴 红 | 所有网络接口断开 |
| `cpe_unreachable` | 🟠 橙 | CPE网关不可达 |

## 快速开始

### 方式一：直接下载 EXE（推荐）

从 [Releases](https://github.com/delancy827/cpe-monitor/releases) 下载最新的 `CPEMonitor.exe`，放到任意目录双击运行。

### 方式二：从源码运行

```bash
pip install flask pystray pillow pyinstaller
python cpe_monitor_desktop.py
```

### 打包为 EXE

```bash
pip install pyinstaller
cd cpe_monitor
pyinstaller --onefile --windowed --name "CPEMonitor" --add-data "cpe_monitor.py;." --add-data "tray_icon.png;." --hidden-import flask --hidden-import pystray --hidden-import PIL --hidden-import PIL.Image --hidden-import PIL.ImageDraw --exclude-module numpy cpe_monitor_desktop.py
```

EXE 生成在 `dist/CPEMonitor.exe`。

## 使用说明

1. **双击 `CPEMonitor.exe`** 启动
2. 自动打开浏览器显示监控面板
3. 系统托盘出现绿色图标 → 后台监控中
4. 关闭浏览器不影响监控（托盘还在运行）
5. **点击托盘图标** → 重新打开面板
6. **右键托盘 → 退出** → 完全退出

## 数据库

监控数据存储在 exe 同目录的 `cpe_monitor.db`（SQLite），删除即清空历史记录。
