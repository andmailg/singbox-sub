"""VLESS connectivity test functions for pipeline integration (Xray based)."""

import json
import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# Кэш результатов теста подключения
_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "test_cache.json",
)


def _load_test_cache() -> dict:
    """Загружает кэш результатов теста из JSON-файла."""
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_test_cache(cache: dict) -> None:
    """Сохраняет кэш результатов теста в JSON-файл."""
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _cache_key(node: dict) -> str:
    """Уникальный ключ для кэширования ноды VLESS."""
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}"


def get_free_port() -> int:
    """Находит случайный свободный порт на локальной машине."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


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

    # Извлекаем flow из tls.reality если есть
    flow = ""
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


def test_vless_node(node: dict, timeout: int = 5) -> dict | str | None:
    """
    Тестирует одну ноду VLESS через Xray CLI с SOCKS5-прокси.
    Возвращает:
      - node с полем "_latency_ms" при успехе,
      - строку с причиной провала при ошибке,
      - None при критической ошибке (нет xray CLI и т.п.).
    """
    server = node["server"]
    port = node["server_port"]
    tag = node.get("tag", f"{server}:{port}")

    local_port = get_free_port()
    xray_config = _build_xray_config(node, local_port)

    proc = None
    config_file = None
    try:
        # 1. Создаём временный JSON-файл конфигурации Xray
        config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(xray_config, config_file, indent=2, ensure_ascii=False)
        config_file.close()

        # 2. Запускаем Xray с конфигом
        xray_cmd = ["xray", "run", "-c", config_file.name]

        proc = subprocess.Popen(
            xray_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Ждём стабильного запуска (3 сек)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass  # Процесс работает — это хорошо

        if proc.returncode is not None and proc.returncode != 0:
            stdout, stderr = proc.communicate()
            output = (stderr or stdout or "").strip()
            return f"CLI exit {proc.returncode}: {output[:200]}"

        # 3. Ждём, пока SOCKS5-порт станет доступен
        if not wait_for_port("127.0.0.1", local_port, timeout=5.0):
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
            return "SOCKS5 port not ready"

        # 4. Выполняем проверку через curl с проксированием
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}:%{time_total}",
            "--socks5-hostname", f"127.0.0.1:{local_port}",
            "--max-time", str(timeout),
            "http://connectivitycheck.gstatic.com/generate_204"
        ]

        res = subprocess.run(curl_cmd, capture_output=True, text=True)

        if res.returncode == 0 and res.stdout:
            parts = res.stdout.strip().split(":")
            if len(parts) >= 2:
                http_code = parts[0]
                time_total = float(parts[1])
                latency = round(time_total * 1000)

                if http_code in ("204", "200"):
                    node["_latency_ms"] = latency
                    return node
                else:
                    return f"HTTP {http_code}"

        return f"curl failed: {res.stderr.strip()[:150]}"

    except FileNotFoundError:
        return None
    except Exception as e:
        return None
    finally:
        # 5. Гарантированно убиваем фоновый процесс Xray
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()

        # Удаляем временный JSON-файл
        if config_file:
            try:
                os.unlink(config_file.name)
            except OSError:
                pass


def test_vless_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> list[dict]:
    """
    Проверяет работоспособность VLESS нод через Xray CLI + curl.
    Возвращает только рабочие ноды (с добавленным полем _latency_ms).

    Результаты теста кэшируются в test_cache.json для детерминизма.
    """
    # Быстрая проверка: есть ли xray CLI
    try:
        subprocess.run(
            ["xray", "version"],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError:
        print(f"{prefix}WARNING: 'xray' CLI not found — skipping connectivity test")
        return outbounds
    except Exception as e:
        print(f"{prefix}WARNING: xray CLI check failed ({e}) — skipping connectivity test")
        return outbounds

    # Загружаем кэш результатов
    cache = _load_test_cache()

    num_workers = min(20, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} vless nodes with {num_workers} workers ({timeout}s timeout)...")

    # Сортируем для детерминизма
    sorted_outbounds = sorted(
        outbounds,
        key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)),
    )

    working: list[dict] = []
    failed = 0
    cached_ok = 0
    cached_fail = 0

    # Разделяем ноды на кэшированные и новые
    new_nodes = []
    for node in sorted_outbounds:
        key = _cache_key(node)
        if key in cache:
            if cache[key]:
                node["_latency_ms"] = cache[key]
                working.append(node)
                cached_ok += 1
            else:
                failed += 1
                cached_fail += 1
        else:
            new_nodes.append(node)

    # Тестируем только новые ноды
    if new_nodes:
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = {
                pool.submit(test_vless_node, node, timeout): node
                for node in new_nodes
            }
            results_map: dict[int, dict | None] = {}

            for i, future in enumerate(as_completed(futures), 1):
                node = futures[future]
                tag = node.get("tag", f"node-{i}")
                node_id = id(node)
                try:
                    result = future.result()
                    if result is not None:
                        if isinstance(result, str):
                            # Строка — причина провала
                            results_map[node_id] = None
                            failed += 1
                            print(f"  [{i}/{len(new_nodes)}] {tag}: FAIL — {result}")
                        else:
                            results_map[node_id] = result
                            print(f"  [{i}/{len(new_nodes)}] {tag}: OK — {result.get('_latency_ms', '?')}ms")
                    else:
                        results_map[node_id] = None
                        failed += 1
                        print(f"  [{i}/{len(new_nodes)}] {tag}: FAIL")
                except Exception as e:
                    results_map[node_id] = None
                    failed += 1
                    print(f"  [{i}/{len(new_nodes)}] {tag}: ERROR — {e}")

            # Обновляем кэш результатами
            for node_id, result in results_map.items():
                for node in new_nodes:
                    if id(node) == node_id:
                        key = _cache_key(node)
                        if result is not None:
                            cache[key] = result.get("_latency_ms", 0)
                            working.append(result)
                        else:
                            cache[key] = None
                        break

    # Сохраняем кэш
    _save_test_cache(cache)

    # Восстанавливаем порядок
    working.sort(
        key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0))
    )

    if failed:
        print(f"{prefix}VLESS connectivity: {len(working)} working / {failed} failed ({len(outbounds)} total).")
        if cached_ok or cached_fail:
            print(f"{prefix}  (cached: {cached_ok} OK, {cached_fail} FAIL; tested: {len(new_nodes)} new)")

    return working
