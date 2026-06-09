## v2.9 多维度检测 + 连续失败阈值

### 🎯 核心优化

#### 1. 多维度探测
- **ICMP Ping 网关** (192.168.10.1)：检测CPE是否在线
- **ICMP Ping 公网** (8.8.8.8)：检测外网连通性
- **TCP连接检测** (www.baidu.com:80)：检测TCP层连通性
- **DNS解析检测** (www.baidu.com)：检测DNS解析是否正常

#### 2. 连续失败阈值
- **断流判定**：连续3次检测失败 → 判定为断流（避免偶发丢包误判）
- **恢复判定**：连续2次检测成功 → 判定为恢复（避免抖动）

#### 3. 检测间隔优化
- Ping间隔：1秒（快速检测）
- TCP检测间隔：3秒
- DNS检测间隔：3秒
- netsh网络接口检测：从30秒缩短为10秒

#### 4. 断流类型细分
- `network_disconnected`：网络接口全断（有线+WiFi都断开）
- `cpe_unreachable`：CPE网关不可达（ping 192.168.10.1失败）
- `external_unreachable`：外网不可达（ping/DNS/TCP都失败）

### 📊 检测精度提升

| 指标 | v2.8.1 | v2.9 |
|------|---------|------|
| 检测维度 | 1维（仅ping网关） | 4维（ping网关+ping公网+TCP+DNS） |
| 误判率 | 较高（偶发丢包） | 极低（连续3次失败才判定） |
| 恢复抖动 | 有（一次成功就恢复） | 无（连续2次成功才恢复） |
| netsh间隔 | 30秒 | 10秒 |
| 短时断流捕获 | 可能漏检 | 准确捕获（5秒以上） |

### 🔧 技术细节

#### 多维度检测逻辑
```python
# 综合判断：网关不可达 OR (网关可达但外网不可达 AND TCP失败 AND DNS失败)
is_network_ok = last_network_ok
is_gateway_ok = ping_gateway_ok
is_external_ok = ping_external_ok or tcp_ok or dns_ok  # 任意一个外网检测成功即可

if is_network_ok and is_gateway_ok and is_external_ok:
    consecutive_successes += 1
    consecutive_failures = 0
else:
    consecutive_failures += 1
    consecutive_successes = 0
```

#### 连续失败阈值
```python
# 断流检测：连续失败达到阈值
if consecutive_failures >= 3 and current_status == "online":
    # 判定为断流
    current_status = "disconnected"
    disconnection_start_time = now

# 恢复检测：连续成功达到阈值
elif consecutive_successes >= 2 and current_status == "disconnected":
    # 判定为恢复
    current_status = "online"
```

### 📦 安装说明

1. 下载 CPEMonitor.exe
2. 放到任意目录（建议 `F:\CPEMonitor\`）
3. 首次运行会自动创建数据库文件
4. 右键托盘图标可设置开机自启

### 🔄 从旧版升级

直接覆盖旧版exe即可，数据库文件会自动保留。

### ✅ 验证新版本

- 托盘图标应该正常显示
- 右键托盘可以看到"打开监控面板"和"开机自启"选项
- 浏览器打开 `http://127.0.0.1:5000` 可以看到版本号为 v2.9

### 🐛 已知问题

- 如果CPE本身不支持ping（关闭了ICMP响应），请修改 `PING_TARGET` 为其他可达的网关IP
- DNS解析检测可能因DNS服务器问题误判，已设置为"任意一个外网检测成功即可"

### 📝 完整更新日志

- ✅ 多维度探测：ICMP ping网关 + ICMP ping公网 + TCP连接检测 + DNS解析检测
- ✅ 连续失败阈值：连续3次检测失败才判定为断流
- ✅ 快速恢复检测：连续2次检测成功才判定为恢复
- ✅ 缩短检测间隔：netsh间隔从30秒缩短为10秒
- ✅ 新增断流类型：`external_unreachable`（外网不可达）
- ✅ 版本号升级到 v2.9
