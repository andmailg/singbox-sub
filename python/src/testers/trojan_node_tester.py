"""Trojan connectivity test functions for pipeline integration (Xray based).

Переиспользует streamSettings из vless_node_tester (ws / tls уже поддерживаются),
меняется только outbound: protocol=trojan вместо vless.
"""

import json
import os
import tempfile

from src.testers._proc import Child, probe_socks, release_port, reserve_port, run_connectivity
from src.testers.vless_node_tester import _build_stream_settings


def _build_xray_config(node: dict, local_port: int) -> dict:
    """Генерирует JSON-конфигурацию Xray для тестирования одной ноды Trojan."""
    transport_cfg = node.get("transport", {})
    if not isinstance(transport_cfg, dict):
        transport_cfg = {}
    network: str = transport_cfg.get("type") or "tcp"

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
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": node["server"],
                            "port": node["server_port"],
                            "password": node.get("password", ""),
                        }
                    ]
                },
                "streamSettings": _build_stream_settings(node, network),
                "tag": "proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


def test_trojan_node(node: dict, timeout: int = 5) -> dict | str | None:
    """
    Тестирует одну ноду Trojan через Xray CLI с SOCKS5-прокси.
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


def test_trojan_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """Проверяет работоспособность Trojan нод через Xray CLI + curl (только рабочие ноды)."""
    return run_connectivity(outbounds, test_trojan_node, "trojan", "xray", timeout, prefix)
