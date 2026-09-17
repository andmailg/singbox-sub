"""Hysteria 2 connectivity test functions for pipeline integration."""

import json
import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Кэш результатов теста подключения
_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "hy2_test_cache.json",
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
    """Уникальный ключ для кэширования ноды."""
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('password')}"


def _hy2_build_yaml(node: dict, local_port: int) -> str:
    """Генерирует YAML-конфигурацию для Hysteria 2 client на основе ноды."""
    server = node["server"]
    port = node["server_port"]
    password = node["password"]
    sni = node.get("tls", {}).get("server_name", "")
    tls_cfg = node.get("tls", {})
    obfs_cfg = node.get("obfs", {})

    def _esc(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    lines = [
        "server: " + _esc(f"{server}:{port}"),
        "auth: " + _esc(password),
        "tls:",
    ]

    if sni:
        lines.append("  sni: " + _esc(sni))

    if "pinSHA256" not in tls_cfg:
        lines.append("  insecure: true")

    if obfs_cfg and obfs_cfg.get("type"):
        obfs_type = obfs_cfg["type"]
        lines.append("obfs:")
        if obfs_type == "salamander":
            lines.append("  type: salamander")
            lines.append("  salamander:")
            lines.append("    password: " + _esc(obfs_cfg.get("password", "")))
        elif obfs_type == "gecko":
            lines.append("  type: gecko")
            lines.append("  gecko:")
            lines.append("    password: " + _esc(obfs_cfg.get("password", "")))
            min_pkt = obfs_cfg.get("min_packet_size")
            max_pkt = obfs_cfg.get("max_packet_size")
            if min_pkt is not None:
                lines.append("    min_packet_size: " + str(min_pkt))
            if max_pkt is not None:
                lines.append("    max_packet_size: " + str(max_pkt))

    up = node.get("up_mbps")
    down = node.get("down_mbps")
    if up is not None or down is not None:
        lines.append("bandwidth:")
        if up is not None:
            lines.append("  up: " + str(up) + " mbps")
        if down is not None:
            lines.append("  down: " + str(down) + " mbps")

    lines.append("socks5:")
    lines.append("  listen: 127.0.0.1:" + str(local_port))
    lines.append("log:")
    lines.append("  level: error")

    return "\n".join(lines) + "\n"


def _hy2_get_free_port() -> int:
    """Находит случайный свободный порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _hy2_wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Ожидает, пока порт станет доступен."""
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


def test_hy2_node(node: dict, timeout: int = 5) -> dict | None:
    """
    Тестирует одну Hysteria2 ноду на работоспособность.
    Возвращает node с дополнительным полем "_latency_ms" при успехе,
    либо None если нода не работает.
    """
    server = node["server"]
    port = node["server_port"]
    tag = node.get("tag", f"{server}:{port}")

    local_port = _hy2_get_free_port()
    yaml_content = _hy2_build_yaml(node, local_port)

    proc = None
    config_file = None
    try:
        config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        config_file.write(yaml_content)
        config_file.close()

        hy2_cmd = ["hy2", "client", "-c", config_file.name]
        proc = subprocess.Popen(
            hy2_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass  # Процесс работает — это хорошо

        if proc.returncode is not None and proc.returncode != 0:
            stdout, stderr = proc.communicate()
            output = (stderr or stdout or "").strip()
            print(f"  [{tag}] FAIL — CLI exit {proc.returncode}: {output[:200]}")
            return None

        if not _hy2_wait_for_port("127.0.0.1", local_port, timeout=5.0):
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
            print(f"  [{tag}] FAIL — SOCKS5 port not ready")
            return None

        curl_cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}:%{time_total}",
            "--socks5-hostname", f"127.0.0.1:{local_port}",
            "--max-time", str(timeout),
            "http://connectivitycheck.gstatic.com/generate_204",
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
                    print(f"  [{tag}] FAIL — HTTP {http_code}")
                    return None

        print(f"  [{tag}] FAIL — curl failed: {res.stderr.strip()[:150]}")
        return None

    except FileNotFoundError:
        print(f"  [{tag}] ERROR — 'hy2' CLI not found in PATH")
        return None
    except Exception as e:
        print(f"  [{tag}] ERROR — {e}")
        return None
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
        if config_file:
            try:
                os.unlink(config_file.name)
            except OSError:
                pass


def test_hy2_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> list[dict]:
    """
    Проверяет работоспособность Hysteria2 нод через hy2 CLI + curl.
    Возвращает только рабочие ноды (с добавленным полем _latency_ms).
    
    Результаты теста кэшируются в hy2_test_cache.json для детерминизма.
    """
    # Быстрая проверка: есть ли hy2 CLI
    try:
        subprocess.run(
            ["hy2", "version"],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError:
        print(f"{prefix}WARNING: 'hy2' CLI not found — skipping connectivity test")
        return outbounds
    except Exception as e:
        print(f"{prefix}WARNING: hy2 CLI check failed ({e}) — skipping connectivity test")
        return outbounds

    # Загружаем кэш результатов
    cache = _load_test_cache()
    
    num_workers = min(20, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} hy2 nodes with {num_workers} workers ({timeout}s timeout)...")

    # Сортируем для детерминизма
    sorted_outbounds = sorted(outbounds, key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)))
    
    working: list[dict] = []
    failed = 0
    cached_ok = 0
    cached_fail = 0

    # Разделяем ноды на те, что уже в кэше, и новые
    new_nodes = []
    for node in sorted_outbounds:
        key = _cache_key(node)
        if key in cache:
            if cache[key]:
                # Нода прошла тест ранее
                node["_latency_ms"] = cache[key]
                working.append(node)
                cached_ok += 1
            else:
                # Нода не прошла тест ранее
                failed += 1
                cached_fail += 1
        else:
            new_nodes.append(node)

    # Тестируем только новые ноды
    if new_nodes:
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = {pool.submit(test_hy2_node, node, timeout): node for node in new_nodes}
            results_map: dict[int, dict | None] = {}
            for i, future in enumerate(as_completed(futures), 1):
                node = futures[future]
                tag = node.get("tag", f"node-{i}")
                node_id = id(node)
                try:
                    result = future.result()
                    if result is not None:
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

            # Обновляем кэш результатами новых тестов
            for node_id, result in results_map.items():
                # Находим ноду по id
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
    working.sort(key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)))
    
    removed = failed
    if removed:
        print(f"{prefix}Hy2 connectivity: {len(working)} working / {removed} failed ({len(outbounds)} total).")
        if cached_ok or cached_fail:
            print(f"{prefix}  (cached: {cached_ok} OK, {cached_fail} FAIL; tested: {len(new_nodes)} new)")

    return working
