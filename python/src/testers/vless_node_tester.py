"""VLESS connectivity test functions for pipeline integration (Xray based)."""

import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from src.testers.asn_resolver import resolve_asn




def get_free_port() -> int:
    """Находит случайный свободный порт на локальной машине."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


_ports_lock = threading.Lock()
_reserved_ports: set[int] = set()


def _reserve_port() -> int:
    """Свободный порт, не выданный другому потоку (get_free_port сам по себе гоночный)."""
    with _ports_lock:
        while True:
            port = get_free_port()
            if port not in _reserved_ports:
                _reserved_ports.add(port)
                return port


def _release_port(port: int) -> None:
    with _ports_lock:
        _reserved_ports.discard(port)


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Ожидает, пока порт станет доступен (поднят)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return True
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.2)
    return False


def _build_xray_config(node: dict, local_port: int) -> dict:
    """
    Генерирует JSON-конфигурацию Xray для тестирования одной ноды VLESS.
    Автоматически определяет транспорт и настройки из sing-box ноды.
    """
    server = node["server"]
    port = node["server_port"]
    uuid = node.get("uuid", "")

    # flow — поле уровня outbound (старые записи могли хранить его в tls.reality)
    flow = node.get("flow", "")
    if not flow:
        tls_cfg = node.get("tls", {})
        if tls_cfg and isinstance(tls_cfg, dict):
            reality = tls_cfg.get("reality", {})
            if isinstance(reality, dict):
                flow = reality.get("flow", "")

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

    # Настройки транспорта (на верхнем уровне streamSettings)
    transport_cfg = node.get("transport", {})
    if not isinstance(transport_cfg, dict):
        transport_cfg = {}

    if network in ("ws", "websocket"):
        path: str = transport_cfg.get("path") or "/"
        headers: dict[str, Any] = transport_cfg.get("headers") or {}
        stream_settings["wsSettings"] = {
            "path": path,
            "headers": headers
        }
    elif network in ("grpc", "gun"):
        service_name: str = transport_cfg.get("service_name") or ""
        stream_settings["grpcSettings"] = {
            "serviceName": service_name
        }
    elif network in ("http", "h2"):
        host: list[str] = transport_cfg.get("host") or []
        path = transport_cfg.get("path") or "/"
        stream_settings["httpSettings"] = {
            "host": host,
            "path": path
        }
    elif network == "httpupgrade":
        httpupgrade_host: str = transport_cfg.get("host") or ""
        path = transport_cfg.get("path") or "/"
        stream_settings["httpupgradeSettings"] = {
            "host": httpupgrade_host,
            "path": path
        }

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
            utls_cfg = tls_cfg.get("utls", {})
            if isinstance(utls_cfg, dict) and utls_cfg.get("fingerprint"):
                reality_settings["fingerprint"] = utls_cfg["fingerprint"]
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


def _wait_ready(proc: subprocess.Popen, port: int, timeout: float = 8.0) -> str | None:
    """Ждёт, пока Xray поднимет SOCKS5-порт. None — готов, строка — причина провала."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            err = (proc.stderr.read() if proc.stderr else "") or ""
            return f"CLI exit {proc.returncode}: {err.strip()[:200]}"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return None
        except OSError:
            time.sleep(0.1)
    return "SOCKS5 port not ready"


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_vless_node(node: dict, timeout: int = 5) -> dict | str | None:
    """
    Тестирует одну ноду VLESS через Xray CLI с SOCKS5-прокси.
    Возвращает:
      - node с полем "_latency_ms" при успехе,
      - строку с причиной провала при ошибке.
    """
    local_port = _reserve_port()
    config_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as cf:
            json.dump(_build_xray_config(node, local_port), cf, ensure_ascii=False)
            config_path = cf.name

        proc = subprocess.Popen(
            ["xray", "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        error = _wait_ready(proc, local_port)
        if error:
            return error

        res = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}:%{time_total}",
                "--socks5-hostname", f"127.0.0.1:{local_port}",
                "--max-time", str(timeout),
                "http://connectivitycheck.gstatic.com/generate_204",
            ],
            capture_output=True, text=True,
        )
        if res.returncode == 0 and ":" in res.stdout:
            http_code, time_total = res.stdout.strip().split(":", 1)
            if http_code in ("204", "200"):
                node["_latency_ms"] = round(float(time_total) * 1000)
                return node
            return f"HTTP {http_code}"
        return f"curl failed: {res.stderr.strip()[:150]}"
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        if proc:
            _stop(proc)
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass
        _release_port(local_port)


def test_vless_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """
    Проверяет работоспособность VLESS нод через Xray CLI + curl.
    Возвращает только рабочие ноды (с добавленным полем _latency_ms).
    """
    # Без xray результат теста не имеет смысла: падаем, а не считаем все ноды рабочими
    try:
        subprocess.run(["xray", "version"], capture_output=True, timeout=5, check=True)
    except Exception as e:
        raise RuntimeError(f"xray CLI недоступен: {e}") from e

    if not outbounds:
        return [], 0, ""

    num_workers = min(20, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} vless nodes with {num_workers} workers ({timeout}s timeout)...")

    # Сортируем для детерминизма
    sorted_outbounds = sorted(
        outbounds,
        key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)),
    )

    working: list[dict] = []
    failed = 0

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        futures = {
            pool.submit(test_vless_node, node, timeout): node
            for node in sorted_outbounds
        }

        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            server = node.get("server", "?")
            port = node.get("server_port", "?")
            asn = resolve_asn(server)
            sub_ids = node.get("_sub_ids", set())
            sub_ids_str = f" [{','.join(sorted(sub_ids))}]" if sub_ids else ""
            display = f"{server}:{port} {asn}" if asn else f"{server}:{port}"
            try:
                result = future.result()
                if result is not None:
                    if isinstance(result, str):
                        # Строка — причина провала
                        failed += 1
                        print(f"  [{i}/{len(sorted_outbounds)}] {display}{sub_ids_str}: FAIL — {result}")
                    else:
                        working.append(result)
                        print(f"  [{i}/{len(sorted_outbounds)}] {display}{sub_ids_str}: OK — {result.get('_latency_ms', '?')}ms")
                else:
                    failed += 1
                    print(f"  [{i}/{len(sorted_outbounds)}] {display}{sub_ids_str}: FAIL")
            except Exception as e:
                failed += 1
                print(f"  [{i}/{len(sorted_outbounds)}] {display}{sub_ids_str}: ERROR — {e}")

    # Восстанавливаем порядок
    working.sort(
        key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0))
    )

    all_sub_ids: set[str] = set()
    for w in working:
        all_sub_ids.update(w.get("_sub_ids", set()))
    sub_ids_summary = f" (subs: {','.join(sorted(all_sub_ids))})" if all_sub_ids else ""

    return working, failed, sub_ids_summary
