#!/usr/bin/env python3
"""Share this Mac's network exit over HTTP and SOCKS5.

Only connections from the allowlisted source MAC/IP are accepted.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

HTTP_PORT = 8080
HTTPS_PORT = 8443
SOCKS_PORT = 1080
CERT_DIR = Path(__file__).with_name("certs")
BUFFER = 65536
CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 120
ARP_TTL = 5.0

DEFAULT_ALLOW_MACS = ("2c:ca:16:6f:fb:8d",)
DEFAULT_ALLOW_IPS = ("10.0.166.11",)
DEFAULT_LOG = Path(__file__).with_name("proxy.log")
_log_path: Path | None = DEFAULT_LOG
_advertise_host = "127.0.0.1"
_advertise_http_port = HTTP_PORT
_proxy_chain: list[tuple[str, int]] = []
EXITS_FILE = Path(__file__).with_name("exits.json")

# Hosts that must leave the source device directly, not via this proxy.
BYPASS_EXACT = {
    "task.yungu.org",
}
BYPASS_SUFFIXES = (
    ".dingtalk.com",
    ".dingtalkapps.com",
    ".dingtalk-inc.com",
    ".laiwang.com",
)
BYPASS_CONTAINS = (
    "dingtalk",
)
PAC_PATHS = {"/proxy.pac", "/wpad.dat"}


def log(msg: str) -> None:
    line = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    if _log_path is None:
        return
    with _log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")

MAC_RE = re.compile(r"([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})", re.I)
ARP_LINE_RE = re.compile(
    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{11,17})",
    re.I,
)


def should_bypass(host: str) -> bool:
    host = (host or "").lower().split("%")[0].rstrip(".")
    if not host:
        return False
    if host in BYPASS_EXACT:
        return True
    if any(host == suffix[1:] or host.endswith(suffix) for suffix in BYPASS_SUFFIXES):
        return True
    return any(token in host for token in BYPASS_CONTAINS)


def build_pac(proxy_chain: list[tuple[str, int]]) -> str:
    exact = ", ".join(f'"{h}"' for h in sorted(BYPASS_EXACT))
    suffixes = ", ".join(f'"{s}"' for s in BYPASS_SUFFIXES)
    contains = ", ".join(f'"{s}"' for s in BYPASS_CONTAINS)
    pac_hosts = ["127.0.0.1", "localhost", *[h for h, _ in proxy_chain]]
    pac_hosts_js = ", ".join(f'"{h}"' for h in pac_hosts)
    proxies_js = ", ".join(f'"PROXY {h}:{p}"' for h, p in proxy_chain)
    return f"""function FindProxyForURL(url, host) {{
    if (!host) return "DIRECT";
    host = host.toLowerCase();
    var pacHosts = [{pac_hosts_js}];
    var h;
    for (h = 0; h < pacHosts.length; h++) {{
        if (host === pacHosts[h]) return "DIRECT";
    }}
    var exact = [{exact}];
    var suffixes = [{suffixes}];
    var contains = [{contains}];
    var i;
    for (i = 0; i < exact.length; i++) {{
        if (host === exact[i] || dnsDomainIs(host, "." + exact[i])) return "DIRECT";
    }}
    for (i = 0; i < suffixes.length; i++) {{
        if (host === suffixes[i].slice(1) || dnsDomainIs(host, suffixes[i])) return "DIRECT";
    }}
    for (i = 0; i < contains.length; i++) {{
        if (host.indexOf(contains[i]) !== -1) return "DIRECT";
    }}
    var proxies = [{proxies_js}];
    var n = proxies.length;
    if (n === 0) return "DIRECT";
    var client = "";
    try {{ client = myIpAddress(); }} catch (e) {{ client = ""; }}
    var key = host;
    if (client && client !== "127.0.0.1") key = client + "|" + host;
    var hash = 0;
    for (i = 0; i < key.length; i++) {{
        hash = (hash * 31 + key.charCodeAt(i)) % 2147483647;
    }}
    var start = hash % n;
    var ordered = [];
    for (i = 0; i < n; i++) {{
        ordered.push(proxies[(start + i) % n]);
    }}
    return ordered.join("; ") + "; DIRECT";
}}
"""


async def send_pac(writer: asyncio.StreamWriter) -> None:
    body = build_pac(list(_proxy_chain)).encode("utf-8")
    writer.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
        b"Cache-Control: no-cache\r\n"
        b"Connection: close\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    await writer.drain()
    writer.close()


def normalize_mac(mac: str) -> str:
    parts = mac.replace("-", ":").lower().split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC: {mac}")
    return ":".join(p.zfill(2) for p in parts)


def local_ipv4s() -> list[str]:
    ips: list[str] = []
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        ip = info[4][0]
        if not ip.startswith("127.") and ip not in ips:
            ips.append(ip)
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("1.1.1.1", 80))
        ip = probe.getsockname()[0]
        probe.close()
        if ip not in ips and not ip.startswith("127."):
            ips.insert(0, ip)
    except OSError:
        pass
    return ips


class ArpCache:
    def __init__(self) -> None:
        self._expires = 0.0
        self._ip_to_mac: dict[str, str] = {}

    def refresh(self) -> None:
        now = time.monotonic()
        if now < self._expires:
            return
        mapping: dict[str, str] = {}
        try:
            out = subprocess.check_output(["arp", "-an"], text=True, timeout=2)
        except (subprocess.SubprocessError, OSError):
            return
        for match in ARP_LINE_RE.finditer(out):
            try:
                mapping[match.group(1)] = normalize_mac(match.group(2))
            except ValueError:
                continue
        self._ip_to_mac = mapping
        self._expires = now + ARP_TTL

    def mac_for(self, ip: str) -> str | None:
        self.refresh()
        return self._ip_to_mac.get(ip)

    def ip_for_mac(self, mac: str) -> str | None:
        self.refresh()
        mac = normalize_mac(mac)
        for ip, found in self._ip_to_mac.items():
            if found == mac:
                return ip
        return None


def load_config() -> dict:
    if not EXITS_FILE.exists():
        return {}
    try:
        return json.loads(EXITS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def load_exits() -> list[dict]:
    return list(load_config().get("exits") or [])


def pool_allow_lists() -> tuple[list[str], list[str]]:
    macs: list[str] = list(DEFAULT_ALLOW_MACS)
    ips: list[str] = list(DEFAULT_ALLOW_IPS)
    data = load_config()
    for key in ("exits", "clients"):
        for item in data.get(key) or []:
            mac = item.get("mac") or ""
            ip = (item.get("ip") or "").strip()
            if mac:
                try:
                    macs.append(normalize_mac(mac))
                except ValueError:
                    pass
            if ip:
                ips.append(ip)
    uniq_macs = list(dict.fromkeys(macs))
    uniq_ips = list(dict.fromkeys(ips))
    return uniq_macs, uniq_ips


def remember_exit_ip(mac: str, ip: str) -> None:
    if not EXITS_FILE.exists() or not ip:
        return
    try:
        data = json.loads(EXITS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    changed = False
    for item in data.get("exits") or []:
        try:
            if normalize_mac(item.get("mac", "")) == normalize_mac(mac) and item.get("ip") != ip:
                item["ip"] = ip
                changed = True
        except ValueError:
            continue
    if changed:
        EXITS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_proxy_chain(local_ip: str, http_port: int, arp: ArpCache) -> list[tuple[str, int]]:
    chain: list[tuple[str, int]] = []
    seen: set[str] = set()
    if local_ip and not local_ip.startswith("127."):
        chain.append((local_ip, http_port))
        seen.add(local_ip)
    for item in load_exits():
        mac = item.get("mac") or ""
        ip = (item.get("ip") or "").strip()
        try:
            if mac:
                found = arp.ip_for_mac(mac)
                if found:
                    ip = found
                    remember_exit_ip(mac, found)
        except ValueError:
            pass
        if ip and ip not in seen:
            chain.append((ip, int(item.get("http_port") or http_port)))
            seen.add(ip)
    return chain


async def refresh_proxy_chain_loop(local_ip: str, http_port: int) -> None:
    global _proxy_chain, _advertise_host
    arp = ArpCache()
    last = None
    while True:
        arp._expires = 0
        chain = build_proxy_chain(local_ip, http_port, arp)
        if chain != last:
            _proxy_chain = chain
            last = chain
            log("G11 出口: " + " / ".join(f"{h}:{p}" for h, p in chain) + " （PAC 按域名均分，挂了自动切）")
        await asyncio.sleep(15)


class AccessControl:
    def __init__(self, allow_macs: Iterable[str], allow_ips: Iterable[str]) -> None:
        self.allow_macs = {normalize_mac(m) for m in allow_macs}
        self.allow_ips = set(allow_ips)
        self.arp = ArpCache()

    def allowed(self, peer_ip: str) -> bool:
        if peer_ip in {"127.0.0.1", "::1"}:
            return True
        if peer_ip in self.allow_ips:
            return True
        mac = self.arp.mac_for(peer_ip)
        return bool(mac and mac in self.allow_macs)

    def describe(self, peer_ip: str) -> str:
        mac = self.arp.mac_for(peer_ip) or "-"
        return f"{peer_ip} ({mac})"


async def relay(a: asyncio.StreamReader, b: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await asyncio.wait_for(a.read(BUFFER), timeout=IDLE_TIMEOUT)
            if not data:
                break
            b.write(data)
            await b.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            b.close()
        except Exception:
            pass


async def pump(left_r, left_w, right_r, right_w) -> None:
    try:
        await asyncio.gather(
            relay(left_r, right_w),
            relay(right_r, left_w),
            return_exceptions=True,
        )
    finally:
        for writer in (left_w, right_w):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def open_remote(host: str, port: int):
    return await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=CONNECT_TIMEOUT,
    )


async def read_http_headers(reader: asyncio.StreamReader, first: bytes = b"") -> bytes:
    buf = first
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=15)
        if not chunk:
            break
        buf += chunk
    return buf


def parse_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, default_port


async def handle_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    first: bytes,
    peer: str,
) -> None:
    raw = await read_http_headers(reader, first)
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        writer.close()
        return
    head = raw[:header_end].decode("iso-8859-1", errors="replace")
    rest = raw[header_end + 4 :]
    lines = head.split("\r\n")
    if not lines:
        writer.close()
        return
    parts = lines[0].split()
    if len(parts) < 2:
        writer.close()
        return
    method, target = parts[0].upper(), parts[1]

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    if method == "CONNECT":
        host, port = parse_host_port(target, 443)
        if should_bypass(host):
            log(f"[BYPASS] {peer} -> {host}:{port} (use PAC so this goes DIRECT)")
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Connection: close\r\n"
                b"Content-Type: text/plain\r\n\r\n"
                b"Bypass host: connect directly, not via proxy.\n"
            )
            await writer.drain()
            writer.close()
            return
        log(f"[HTTPS CONNECT] {peer} -> {host}:{port}")
        try:
            remote_r, remote_w = await open_remote(host, port)
        except Exception as exc:
            log(f"[HTTPS CONNECT FAIL] {peer} -> {host}:{port} ({type(exc).__name__}: {exc})")
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                + str(exc).encode("utf-8", errors="replace")
            )
            await writer.drain()
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await pump(reader, writer, remote_r, remote_w)
        return

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlsplit(target)
        host = parsed.hostname or headers.get("host", "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    else:
        host_header = headers.get("host", "")
        host, port = parse_host_port(host_header, 80)
        path = target

    if path.split("?")[0] in PAC_PATHS:
        log(f"[PAC] {peer} <- {path.split('?')[0]}")
        await send_pac(writer)
        return

    if should_bypass(host):
        log(f"[BYPASS] {peer} -> {host}:{port}{path} (use PAC so this goes DIRECT)")
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Connection: close\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Bypass host: connect directly, not via proxy.\n"
        )
        await writer.drain()
        writer.close()
        return

    if not host:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    try:
        remote_r, remote_w = await open_remote(host, port)
    except Exception as exc:
        writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
            + str(exc).encode("utf-8", errors="replace")
        )
        await writer.drain()
        writer.close()
        return

    hop_by_hop = {
        "proxy-connection",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-authorization",
    }
    out = [f"{method} {path} HTTP/1.1", f"Host: {host if port in (80, 443) else f'{host}:{port}'}"]
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in hop_by_hop or key.strip().lower() == "host":
            continue
        out.append(f"{key.strip()}: {value.strip()}")
    out.append("Connection: close")
    payload = ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1", errors="replace") + rest
    remote_w.write(payload)
    await remote_w.drain()
    log(f"[HTTP {method}] {peer} -> {host}:{port}{path}")
    await pump(reader, writer, remote_r, remote_w)


async def handle_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    first: bytes,
    peer: str,
) -> None:
    greeting = first + await reader.readexactly(max(0, 2 - len(first)))
    if len(greeting) < 2 or greeting[0] != 0x05:
        writer.close()
        return
    nmethods = greeting[1]
    methods = greeting[2:]
    if len(methods) < nmethods:
        methods += await reader.readexactly(nmethods - len(methods))
    writer.write(b"\x05\x00")
    await writer.drain()

    req = await reader.readexactly(4)
    if req[0] != 0x05 or req[1] != 0x01:
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        return

    atyp = req[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("utf-8", errors="replace")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        return
    port = int.from_bytes(await reader.readexactly(2), "big")
    if should_bypass(host):
        log(f"[BYPASS] {peer} -> {host}:{port} (SOCKS)")
        writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        return

    try:
        remote_r, remote_w = await open_remote(host, port)
    except Exception:
        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        return

    bind_host, bind_port = remote_w.get_extra_info("sockname")[:2]
    try:
        addr = socket.inet_aton(bind_host)
        atyp_out = b"\x01"
    except OSError:
        addr = socket.inet_pton(socket.AF_INET6, bind_host)
        atyp_out = b"\x04"
    writer.write(b"\x05\x00\x00" + atyp_out + addr + bind_port.to_bytes(2, "big"))
    await writer.drain()
    log(f"[SOCKS5] {peer} -> {host}:{port}")
    await pump(reader, writer, remote_r, remote_w)


def deny(writer: asyncio.StreamWriter, reason: str) -> None:
    log(f"[DENY] {reason}")
    try:
        writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
    except Exception:
        pass
    writer.close()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    access: AccessControl,
    mode: str,
) -> None:
    peer_ip, peer_port = writer.get_extra_info("peername")[:2]
    peer = access.describe(peer_ip)
    if not access.allowed(peer_ip):
        deny(writer, peer)
        return
    try:
        first = await asyncio.wait_for(reader.read(1), timeout=15)
        if not first:
            writer.close()
            return
        if mode == "socks" or (mode == "auto" and first == b"\x05"):
            await handle_socks5(reader, writer, first, peer)
        else:
            await handle_http(reader, writer, first, peer)
    except TimeoutError:
        log(f"[TIMEOUT] {peer}: opened a connection but sent no request")
    except Exception as exc:
        log(f"[ERR] {peer}: {type(exc).__name__}: {exc or repr(exc)}")
        try:
            writer.close()
        except Exception:
            pass


def ensure_proxy_ssl_context(names: list[str]) -> ssl.SSLContext:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    cert_file = CERT_DIR / "proxy.crt"
    key_file = CERT_DIR / "proxy.key"
    san = ["DNS:localhost", "IP:127.0.0.1"]
    for name in names:
        item = f"IP:{name}" if re.match(r"^\d+\.\d+\.\d+\.\d+$", name) else f"DNS:{name}"
        if item not in san:
            san.append(item)
    if not cert_file.exists() or not key_file.exists():
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "825",
                "-nodes",
                "-keyout",
                str(key_file),
                "-out",
                str(cert_file),
                "-subj",
                "/CN=proxy-yungu",
                "-addext",
                "subjectAltName=" + ",".join(san),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log(f"已生成自签证书: {cert_file}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


async def serve(
    host: str,
    port: int,
    access: AccessControl,
    mode: str,
    ssl_ctx: ssl.SSLContext | None = None,
) -> asyncio.AbstractServer:
    return await asyncio.start_server(
        lambda r, w: handle_client(r, w, access, mode),
        host,
        port,
        ssl=ssl_ctx,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LAN HTTP + SOCKS5 proxy")
    parser.add_argument("--listen", default="0.0.0.0", help="bind address")
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--https-port", type=int, default=HTTPS_PORT)
    parser.add_argument("--socks-port", type=int, default=SOCKS_PORT)
    parser.add_argument(
        "--allow-mac",
        action="append",
        default=[],
        help="source MAC allowed to use the proxy (repeatable)",
    )
    parser.add_argument(
        "--allow-ip",
        action="append",
        default=[],
        help="source IP allowed to use the proxy (repeatable)",
    )
    parser.add_argument(
        "--log-file",
        default=str(DEFAULT_LOG),
        help="append access logs to this file",
    )
    return parser.parse_args()


async def main() -> None:
    global _log_path, _advertise_host, _advertise_http_port, _proxy_chain
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    _log_path = Path(args.log_file) if args.log_file else None
    allow_macs = list(args.allow_mac) if args.allow_mac else []
    allow_ips = list(args.allow_ip) if args.allow_ip else []
    pool_macs, pool_ips = pool_allow_lists()
    allow_macs = list(dict.fromkeys([*pool_macs, *allow_macs]))
    allow_ips = list(dict.fromkeys([*pool_ips, *allow_ips]))
    access = AccessControl(allow_macs, allow_ips)
    lan_ips = local_ipv4s()
    shown_ip = lan_ips[0] if lan_ips else "本机局域网IP"
    _advertise_host = shown_ip
    _advertise_http_port = args.http_port
    _proxy_chain = build_proxy_chain(shown_ip, args.http_port, ArpCache())

    http_server = await serve(args.listen, args.http_port, access, "http")
    socks_server = await serve(args.listen, args.socks_port, access, "socks")
    ssl_ctx = ensure_proxy_ssl_context(lan_ips + ["localhost"])
    https_server = await serve(args.listen, args.https_port, access, "http", ssl_ctx)

    log("出口代理已启动")
    log(f"  本机局域网地址: {', '.join(lan_ips) or '未知'}")
    log(f"  HTTP 代理:      {shown_ip}:{args.http_port}")
    log(f"  HTTPS 代理:     {shown_ip}:{args.http_port}  （系统设置填这个，CONNECT）")
    log(f"  HTTPS(TLS):     https://{shown_ip}:{args.https_port}  （连代理本身也加密）")
    log(f"  SOCKS5:         {shown_ip}:{args.socks_port}")
    log(f"  允许 MAC:       {', '.join(normalize_mac(m) for m in allow_macs)}")
    log(f"  允许 IP:        {', '.join(allow_ips)} （本机 127.0.0.1 也可测）")
    log(f"  日志文件:       {_log_path}")
    log("源设备请改用自动代理（PAC），钉钉 / task.yungu.org 才会直连：")
    log(f"  PAC 地址:   http://{shown_ip}:{args.http_port}/proxy.pac")
    if _proxy_chain:
        log("  G11 出口: " + " / ".join(f"{h}:{p}" for h, p in _proxy_chain) + " （按域名均分，挂了自动切）")
    log("  关掉手动 HTTP/HTTPS 代理，改成「自动」并填上面的 PAC")
    log("  三台 G11 都要跑 ./start.sh，G10 流量才会均分；某台关掉会切到另外两台")
    log("按 Ctrl+C 停止。")

    async with http_server, https_server, socks_server:
        await asyncio.gather(
            http_server.serve_forever(),
            https_server.serve_forever(),
            socks_server.serve_forever(),
            refresh_proxy_chain_loop(shown_ip, args.http_port),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("已停止")
