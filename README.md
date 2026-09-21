# proxy_yungu

G11 多出口代理 + Clash Verge 自动切换脚本

## 文件说明

| 文件 | 用途 |
|---|---|
| `proxy_server.py` | 核心代理服务（HTTP / HTTPS-CONNECT / SOCKS5 多协议，PAC 动态生成，出口均衡） |
| `exits.json` | 出口节点配置（各 G11 机器的 MAC + IP） |
| `proxy.pac` | 静态 PAC 文件（`pac_host.py` 使用） |
| `pac_host.py` | 独立 PAC 文件 HTTP 服务器（可选） |
| `proxy-pac.service` | Linux systemd 服务文件（可选） |
| `start.sh` | 快速启动脚本 |
| `clash_auto_switch.py` | Clash Verge 自动最优节点切换脚本 |

---

## 代理服务器快速上手（G11 机器）

### 1. 在每台 G11 上启动

```bash
git clone https://github.com/garywanggali/proxy_yungu.git
cd proxy_yungu
./start.sh
```

### 2. G10 客户端配置

系统代理选「自动配置代理」，PAC 地址填：

```
http://10.0.165.32:8080/proxy.pac
```

三台 G11 都跑起来后，流量会按域名哈希均分到三台，某台下线自动切到另外两台。

### 3. 出口节点配置（`exits.json`）

```json
{
  "http_port": 8080,
  "exits": [
    { "name": "G11-1", "mac": "a0:9a:8e:0f:42:f6", "ip": "10.0.165.45" },
    { "name": "G11-2", "mac": "a0:9a:8e:3e:f6:0a", "ip": "10.0.165.32" },
    { "name": "G11-3", "mac": "f8:4d:89:92:a4:1b", "ip": "10.0.165.30" }
  ]
}
```

MAC 地址用于自动追踪 DHCP 变化的 IP，无需手动更新。

### 4. 可选：禁用特定域名出口

```bash
python3 proxy_server.py --block-domain google --block-domain youtube
```

---

## Clash 自动切换脚本（`clash_auto_switch.py`）

每 30 秒检测当前 Clash 节点延迟，超过 300 ms 自动测速全部节点并切换到最快的。

```bash
python3 clash_auto_switch.py
```

**可配置参数（文件顶部 CONFIG 区）：**

| 参数 | 默认值 | 说明 |
|---|---|---|
| `THRESHOLD_MS` | `300` | 触发切换的延迟阈值 |
| `CHECK_INTERVAL` | `30` | 检测间隔（秒） |
| `SELECTOR_NAME` | `🔰 选择节点` | 策略组名字 |
| `SKIP_KEYWORDS` | 下载专用/免费 | 跳过这些节点 |
