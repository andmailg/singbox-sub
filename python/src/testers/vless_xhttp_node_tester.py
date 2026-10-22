"""VLESS xhttp connectivity test functions for pipeline integration (Xray based)."""

import json
import os
import tempfile
from typing import Any

from src.testers._proc import Child, probe_socks, release_port, reserve_port, run_connectivity




def _build_xray_config(node: dict, local_port: int) -> dict:
    """
    Генерирует JSON-конфигурацию Xray для тестирования одной ноды VLESS xhttp.
    Автоматически определяет транспорт и настройки из sing-box ноды.
    """
    server = node["server"]
    port = node["server_port"]
    uuid = node.get("uuid", "")

    # Извлекаем flow (поле уровня VLESS, не внутри reality/TLS)
    flow = node.get("flow", "")

    # Определяем транспорт
    transport_cfg: dict[str, Any] = node.get("transport", {})
    if not isinstance(transport_cfg, dict):
        transport_cfg = {}
    network: str = transport_cfg.get("type") or "tcp"

    # Build streamSettings для Xray
    stream_settings: dict[str, Any] = _build_stream_settings(node, network)

    # Build VLESS outbound
    vless_user = {
        "id": uuid,
        "encryption": "none"
    }
    if flow:
        vless_user["flow"] = flow

    vless_settings = {
        "vnext": [
            {
                "address": server,
                "port": port,
                "users": [vless_user]
            }
        ]
    }

    config = {
        "log": {
            "loglevel": "error"
        },
        "inbounds": [
            {
                "port": local_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "listen": "127.0.0.1"
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": vless_settings,
                "streamSettings": stream_settings,
                "tag": "proxy"
            },
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }

    return config


def _build_stream_settings(node: dict, network: str) -> dict:
    """
    Генерирует streamSettings для Xray на основе транспорта и TLS/REALITY.
    """
    stream_settings: dict[str, Any] = {"network": network}

    tls_cfg = node.get("tls", {})
    if not isinstance(tls_cfg, dict):
        tls_cfg = {}

    has_reality = False
    has_tls = tls_cfg.get("enabled", False)

    if has_tls and isinstance(tls_cfg, dict):
        reality = tls_cfg.get("reality", {})
        if isinstance(reality, dict) and reality.get("enabled", False):
            has_reality = True

    # Настройки xhttp транспорта
    transport_cfg = node.get("transport", {})
    if isinstance(transport_cfg, dict) and transport_cfg.get("type") == "xhttp":
        path: str = transport_cfg.get("path") or "/"
        host_raw: list[str] | str = transport_cfg.get("host") or []
        mode: str = transport_cfg.get("mode") or "auto"

        # Xray ожидает Host как строку (comma-separated), а не массив
        if isinstance(host_raw, list) and len(host_raw) > 0:
            host_str = ",".join(host_raw)
        else:
            host_str = host_raw if isinstance(host_raw, str) else ""

        xhttp_settings: dict[str, Any] = {
            "path": path,
            "mode": mode,
        }
        if host_str:
            xhttp_settings["host"] = host_str

        stream_settings["xhttpSettings"] = xhttp_settings

    # Настройки безопасности
    if has_reality:
        stream_settings["security"] = "reality"
        reality = tls_cfg.get("reality", {})
        if isinstance(reality, dict):
            reality_settings = {}
            sni = tls_cfg.get("server_name", "")
            if sni:
                reality_settings["serverName"] = sni
            public_key = reality.get("public_key", "")
            if public_key:
                reality_settings["publicKey"] = public_key
            short_id = reality.get("short_id", "")
            if short_id:
                reality_settings["shortId"] = short_id
            spider_x = reality.get("spider_x", "/")
            if spider_x:
                reality_settings["spiderX"] = spider_x
            stream_settings["realitySettings"] = reality_settings
    elif has_tls:
        stream_settings["security"] = "tls"
        tls_settings = {}
        sni = tls_cfg.get("server_name", "")
        if sni:
            tls_settings["serverName"] = sni
        utls = tls_cfg.get("utls", {})
        if isinstance(utls, dict) and utls.get("enabled", False):
            fingerprint = utls.get("fingerprint", "")
            if fingerprint:
                tls_settings["fingerprint"] = fingerprint
        stream_settings["tlsSettings"] = tls_settings

    return stream_settings


def test_vless_xhttp_node(node: dict, timeout: int = 5) -> dict | str | None:
    """
    Тестирует одну ноду VLESS xhttp через Xray CLI с SOCKS5-прокси.
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


def test_vless_xhttp_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """Проверяет работоспособность VLESS xhttp нод через Xray CLI + curl (только рабочие ноды)."""
    return run_connectivity(outbounds, test_vless_xhttp_node, "vless_xhttp", "xray", timeout, prefix)
