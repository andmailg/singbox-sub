"""VMess connectivity test functions for pipeline integration (Xray based).

Под актуальный Xray (26.x):
- outbound в плоском формате settings {address, port, id, security} (без vnext);
- network + method (см. transport_selector): raw / ws / httpupgrade — остальные транспорты (h2/http, grpc) парсер не пропускает;
- security none/zero Xray сам заменяет на auto (парсер делает то же самое заранее).
"""

import json
import os
import tempfile
from typing import Any

from src.testers._proc import (
    Child, probe_socks, release_port, reserve_port, run_connectivity, transport_selector,
)


def _build_tls_settings(tls_cfg: dict, fallback_host: str) -> dict:
    settings: dict[str, Any] = {"serverName": tls_cfg.get("server_name") or fallback_host}
    alpn = tls_cfg.get("alpn")
    if alpn:
        settings["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    utls = tls_cfg.get("utls")
    if isinstance(utls, dict) and utls.get("enabled") and utls.get("fingerprint"):
        settings["fingerprint"] = utls["fingerprint"]
    return settings


def _ws_path(transport: dict) -> str:
    """Путь WS; early data в Xray включается параметром ed в path."""
    path = transport.get("path") or "/"
    early = transport.get("max_early_data")
    if early and "ed=" not in path:
        path += ("&" if "?" in path else "?") + f"ed={int(early)}"
    return path


def _build_stream_settings(node: dict) -> dict:
    transport = node.get("transport")
    if not isinstance(transport, dict):
        transport = {}
    net = transport.get("type") or "tcp"

    if net == "ws":
        stream: dict[str, Any] = {**transport_selector("ws"), "wsSettings": {"path": _ws_path(transport)}}
        host = (transport.get("headers") or {}).get("Host")
        if host:
            stream["wsSettings"]["host"] = host
    elif net == "httpupgrade":
        stream = {**transport_selector("httpupgrade"), "httpupgradeSettings": {"path": transport.get("path") or "/"}}
        if transport.get("host"):
            stream["httpupgradeSettings"]["host"] = transport["host"]
    elif net == "tcp":
        stream = transport_selector("raw")
    else:
        raise ValueError(f"unsupported transport: {net}")

    tls_cfg = node.get("tls")
    if isinstance(tls_cfg, dict) and tls_cfg.get("enabled"):
        stream["security"] = "tls"
        stream["tlsSettings"] = _build_tls_settings(tls_cfg, node.get("server", ""))
    else:
        stream["security"] = "none"
    return stream


def _vmess_security(node: dict) -> str:
    security = str(node.get("security") or "auto").lower()
    return "auto" if security in ("none", "zero") else security


def _build_xray_config(node: dict, local_port: int) -> dict:
    """JSON-конфигурация Xray для тестирования одной ноды VMess (SOCKS5 inbound)."""
    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "port": local_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "listen": "127.0.0.1",
            }
        ],
        "outbounds": [
            {
                "protocol": "vmess",
                "settings": {
                    "address": node["server"],
                    "port": node["server_port"],
                    "id": node.get("uuid", ""),
                    "security": _vmess_security(node),
                },
                "streamSettings": _build_stream_settings(node),
                "tag": "proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


def test_vmess_node(node: dict, timeout: int = 5) -> dict | str | None:
    """Тестирует одну ноду VMess через Xray CLI с SOCKS5-прокси.

    Возвращает node с полем "_latency_ms" при успехе, иначе строку с причиной провала.
    """
    local_port = reserve_port()
    config_path = None
    child = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as cf:
            json.dump(_build_xray_config(node, local_port), cf, ensure_ascii=False)
            config_path = cf.name

        child = Child(["xray", "run", "-c", config_path])
        error = child.wait_ready(local_port, timeout=8.0)
        if error:
            return error
        return probe_socks(local_port, timeout, node)
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        if child:
            child.close()
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass
        release_port(local_port)


def test_vmess_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """Проверяет работоспособность VMess нод через Xray CLI + curl (только рабочие ноды)."""
    return run_connectivity(outbounds, test_vmess_node, "vmess", "xray", timeout, prefix)
