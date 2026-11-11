"""VLESS HTTP connectivity test functions for pipeline integration (Xray based).

Ссылки VLESS с `headerType=http` — это TCP-транспорт с HTTP-маскировкой заголовков
(Xray: network=tcp, tcpSettings.header.type=http). В sing-box-ноде такой транспорт
записан как transport.type="http", но для Xray это НЕ h2 (httpSettings требует TLS),
поэтому streamSettings строятся здесь отдельно.
"""

import json
import os
import tempfile
from typing import Any

from src.testers._proc import (
    Child, probe_socks, release_port, reserve_port, run_connectivity, transport_selector,
)


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v)]
    return [str(value)]


def _custom_headers(raw: Any) -> dict[str, list[str]]:
    """Пользовательские заголовки из ссылки (`header=[...]`) → headers Xray (значения — списки).

    Поддерживаются элементы-словари ({"Name": "value"}), пары {"name":..,"value":..}
    и строки "Name: value". Остальное пропускается.
    """
    result: dict[str, list[str]] = {}

    def add(name: Any, value: Any) -> None:
        name = str(name).strip()
        if name and name.lower() != "host":
            result.setdefault(name, []).extend(_as_list(value))

    items = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    for item in items:
        if isinstance(item, dict):
            if "name" in item and "value" in item:
                add(item["name"], item["value"])
            else:
                for k, v in item.items():
                    add(k, v)
        elif isinstance(item, str) and ":" in item:
            k, v = item.split(":", 1)
            add(k, v.strip())
    return result


def _build_stream_settings(node: dict) -> dict:
    """streamSettings Xray: TCP + HTTP-обфускация (security=none)."""
    transport = node.get("transport")
    if not isinstance(transport, dict):
        transport = {}

    headers: dict[str, list[str]] = {}
    hosts = _as_list(transport.get("host"))
    if hosts:
        headers["Host"] = hosts
    headers.update(_custom_headers(transport.get("headers")))

    request: dict[str, Any] = {
        "version": "1.1",
        "method": transport.get("method") or "GET",
        "path": [transport.get("path") or "/"],
    }
    if headers:
        request["headers"] = headers

    return {
        **transport_selector("tcp"),
        "security": "none",
        "tcpSettings": {"header": {"type": "http", "request": request}},
    }


def _build_xray_config(node: dict, local_port: int) -> dict:
    """JSON-конфигурация Xray для тестирования одной ноды VLESS HTTP (SOCKS5 inbound)."""
    vless_user: dict[str, Any] = {"id": node.get("uuid", ""), "encryption": "none"}
    if node.get("flow"):
        vless_user["flow"] = node["flow"]

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
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": node["server"],
                            "port": node["server_port"],
                            "users": [vless_user],
                        }
                    ]
                },
                "streamSettings": _build_stream_settings(node),
                "tag": "proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


def test_vless_http_node(node: dict, timeout: int = 5) -> dict | str | None:
    """Тестирует одну ноду VLESS HTTP через Xray CLI с SOCKS5-прокси.

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


def test_vless_http_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """Проверяет работоспособность VLESS HTTP нод через Xray CLI + curl (только рабочие ноды)."""
    return run_connectivity(outbounds, test_vless_http_node, "vless_http", "xray", timeout, prefix)
