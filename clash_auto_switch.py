#!/usr/bin/env python3
"""
Clash Verge 自动最优节点切换脚本
====================================
每 30 秒检测一次当前节点延迟：
  - 低于 300 ms → 保持当前节点不动
  - 高于 300 ms 或超时 → 并发测试所有节点，切换到最快的那个

用法：
    python3 clash_auto_switch.py

可选参数（直接在文件开头的 CONFIG 区修改）：
    THRESHOLD_MS    : 延迟超过此值触发切换（默认 300 ms）
    CHECK_INTERVAL  : 检测周期（默认 30 秒）
    TEST_URL        : 测速用的目标 URL
    TEST_TIMEOUT_MS : 单节点测速超时（默认 2000 ms）
    SELECTOR_NAME   : Clash 里要自动切的策略组名字（默认「🔰 选择节点」）
    SKIP_KEYWORDS   : 节点名含这些词就跳过（如下载专用节点）
    SOCKET_PATH     : Mihomo API Unix socket 路径
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.parse
import sys
import os
from datetime import datetime
from typing import Optional
import http.client

# ════════════════════════════════════
#  CONFIG — 按需修改
# ════════════════════════════════════
THRESHOLD_MS     = 300          # ms，超过这个就换节点
CHECK_INTERVAL   = 30           # 秒，每隔多久检测一次
TEST_URL         = "https://www.google.com"
TEST_TIMEOUT_MS  = 2000         # ms，测速超时
SELECTOR_NAME    = "🔰 选择节点" # 策略组名字
SKIP_KEYWORDS    = ["下载专用", "免费", "DIRECT", "REJECT"]  # 跳过这些节点
MAX_CONCURRENT   = 8            # 最多并发测速节点数
SOCKET_PATH      = "/var/run/clash-verge-service/users/501/verge-mihomo.sock"
# ════════════════════════════════════


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str, level: str = "INFO") -> None:
    symbols = {"INFO": "●", "OK": "✓", "WARN": "!", "ERR": "✗", "SWITCH": "⚡"}
    sym = symbols.get(level, "●")
    print(f"[{ts()}] {sym} {msg}", flush=True)


def api_request(
    method: str,
    path: str,
    body: Optional[dict] = None,
    timeout: float = 5.0,
) -> Optional[dict]:
    """通过 Unix socket 调用 Mihomo REST API。"""
    try:
        conn = http.client.HTTPConnection("localhost", timeout=timeout)
        conn.sock = None  # will be replaced

        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(SOCKET_PATH)
        conn.sock = sock

        headers = {"Content-Type": "application/json"}
        payload = json.dumps(body).encode() if body else None
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        if raw:
            return json.loads(raw)
        return {}
    except Exception as exc:
        log(f"API 请求失败 {method} {path}: {exc}", "ERR")
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_selector_info() -> Optional[dict]:
    """获取策略组当前状态。"""
    encoded = urllib.parse.quote(SELECTOR_NAME)
    return api_request("GET", f"/proxies/{encoded}")


def get_current_node() -> Optional[str]:
    info = get_selector_info()
    return info.get("now") if info else None


def get_all_nodes() -> list[str]:
    info = get_selector_info()
    if not info:
        return []
    all_nodes = info.get("all", [])
    # 过滤掉跳过关键词的节点
    filtered = []
    for name in all_nodes:
        if any(kw in name for kw in SKIP_KEYWORDS):
            continue
        filtered.append(name)
    return filtered


def measure_latency(node_name: str) -> Optional[int]:
    """同步测速单个节点，返回延迟 ms，超时/失败返回 None。"""
    encoded = urllib.parse.quote(node_name)
    test_url_encoded = urllib.parse.quote(TEST_URL, safe="")
    path = f"/proxies/{encoded}/delay?url={test_url_encoded}&timeout={TEST_TIMEOUT_MS}"
    result = api_request("GET", path, timeout=(TEST_TIMEOUT_MS / 1000) + 1.0)
    if result and "delay" in result:
        return result["delay"]
    return None


def switch_to(node_name: str) -> bool:
    """切换策略组到指定节点。"""
    encoded = urllib.parse.quote(SELECTOR_NAME)
    result = api_request("PUT", f"/proxies/{encoded}", body={"name": node_name})
    return result is not None


async def async_measure_latency(
    node_name: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, Optional[int]]:
    """异步测速，受 semaphore 限制并发数。"""
    async with semaphore:
        loop = asyncio.get_event_loop()
        delay = await loop.run_in_executor(None, measure_latency, node_name)
        return node_name, delay


async def find_fastest_node(nodes: list[str]) -> Optional[tuple[str, int]]:
    """并发测速所有节点，返回最快的 (name, delay)。"""
    if not nodes:
        return None

    log(f"开始并发测速 {len(nodes)} 个节点（最大并发 {MAX_CONCURRENT}）...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [async_measure_latency(name, semaphore) for name in nodes]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid: list[tuple[str, int]] = []
    for r in results:
        if isinstance(r, Exception):
            continue
        name, delay = r
        if delay is not None:
            valid.append((name, delay))

    if not valid:
        log("所有节点测速失败或超时", "ERR")
        return None

    valid.sort(key=lambda x: x[1])
    log(f"测速完成，共 {len(valid)}/{len(nodes)} 个节点响应：")
    for name, delay in valid[:5]:
        bar = "█" * min(20, delay // 30)
        print(f"  {delay:>5} ms  {bar}  {name}")
    if len(valid) > 5:
        print(f"  ... 共 {len(valid)} 个有效节点")

    return valid[0]


async def check_and_switch() -> None:
    """单次检测并按需切换。"""
    current = get_current_node()
    if not current:
        log("无法获取当前节点，跳过本次检测", "WARN")
        return

    log(f"当前节点: {current}，测速中...")
    current_delay = measure_latency(current)

    if current_delay is not None:
        status = "OK" if current_delay < THRESHOLD_MS else "WARN"
        log(f"当前节点延迟: {current_delay} ms (阈值 {THRESHOLD_MS} ms)", status)

        if current_delay < THRESHOLD_MS:
            log(f"延迟正常，无需切换", "OK")
            return
        else:
            log(f"延迟过高（{current_delay} ms > {THRESHOLD_MS} ms），触发全节点测速！", "WARN")
    else:
        log(f"当前节点无响应/超时，触发全节点测速！", "WARN")

    # 触发全节点测速
    all_nodes = get_all_nodes()
    if not all_nodes:
        log("无法获取节点列表", "ERR")
        return

    best = await find_fastest_node(all_nodes)
    if not best:
        return

    best_name, best_delay = best

    if best_name == current:
        log(f"最快节点就是当前节点，保持不变（{best_delay} ms）", "OK")
        return

    log(f"切换: {current} → {best_name} ({best_delay} ms)", "SWITCH")
    if switch_to(best_name):
        log(f"✅ 已成功切换到 {best_name}（{best_delay} ms）", "OK")
    else:
        log(f"切换失败，API 请求异常", "ERR")


async def main_loop() -> None:
    log("=" * 55)
    log("Clash Verge 自动最优节点切换器 已启动")
    log(f"  策略组 : {SELECTOR_NAME}")
    log(f"  延迟阈值: {THRESHOLD_MS} ms")
    log(f"  检测间隔: {CHECK_INTERVAL} s")
    log(f"  测速地址: {TEST_URL}")
    log("=" * 55)

    # 验证 socket 存在
    if not os.path.exists(SOCKET_PATH):
        log(f"找不到 Clash Unix socket: {SOCKET_PATH}", "ERR")
        log("请确认 Clash Verge 正在运行，且以服务模式启动", "ERR")
        sys.exit(1)

    # 验证策略组存在
    info = get_selector_info()
    if not info:
        log(f"找不到策略组「{SELECTOR_NAME}」，请检查名字是否正确", "ERR")
        sys.exit(1)

    log(f"连接 Mihomo API 成功，当前节点: {info.get('now')}", "OK")
    log(f"策略组共 {len(info.get('all', []))} 个节点（将跳过含 {SKIP_KEYWORDS} 的节点）")
    log("")

    # 首次立即检测
    await check_and_switch()

    while True:
        log(f"等待 {CHECK_INTERVAL} 秒后进行下次检测...")
        await asyncio.sleep(CHECK_INTERVAL)
        print()
        await check_and_switch()


if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print()
        log("已停止", "INFO")
