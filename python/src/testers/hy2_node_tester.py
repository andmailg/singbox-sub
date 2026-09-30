"""Hysteria 2 connectivity test functions for pipeline integration."""

import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.rkn_filter import resolve_asn




def _hy2_get_free_port() -> int:
    """Находит случайный свободный порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _hy2_wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    """Ожидает, пока порт станет доступен."""
    # Начальная пауза для инициализации hy2 клиента
    time.sleep(1.0)
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return True
            except (ConnectionRefusedError, socket.timeout, OSError):
                time.sleep(0.3)
    return False


def _hy2_build_yaml(node: dict, local_port: int) -> str:
    """Генерирует YAML-конфиг для hy2 CLI client из ноды sing-box.

    Формат соответствует hysteria v2 config spec.
    """
    server = node["server"]
    port = node["server_port"]
    password = node.get("password", "")
    tls = node.get("tls", {})

    lines: list[str] = []

    # --- Core ---
    lines.append(f"server: {server}:{port}")
    lines.append(f"auth: {password}")
    lines.append("")

    # --- TLS ---
    sni = tls.get("server_name", server)
    lines.append("tls:")
    lines.append(f"  sni: {sni!r}")

    alpn = tls.get("alpn")
    if alpn:
        lines.append("  alpn:")
        for a in alpn:
            lines.append(f"    - {a!r}")

    pin_sha256 = tls.get("certificate", {}).get("pin_sha256")
    if pin_sha256:
        lines.append(f"  pinSHA256: {pin_sha256!r}")

    lines.append("")

    # --- Obfs (optional) ---
    obfs = node.get("obfs")
    if obfs and obfs.get("type") == "openssl":
        lines.append("obfs:")
        lines.append("  type: openssl")
        lines.append(f"  password: {obfs.get('password', '')!r}")
        lines.append("")

    # --- QUIC (optional tuning) ---
    lines.append("QUIC:")
    lines.append("  initStreamReceiveWindow: 8388608")
    lines.append("  maxStreamReceiveWindow: 8388608")
    lines.append("  initConnReceiveWindow: 8388608")
    lines.append("  maxInFlightReceiveWindow: 8388608")
    lines.append("  maxIncomingStreams: 1024")
    lines.append("  disablePathMTUDiscovery: false")
    lines.append("")

    # --- Transport ---
    lines.append("transport:")
    lines.append("  type: udp")
    lines.append("  udp:")
    lines.append("    hopInterval: 30s")
    lines.append("")

    # --- SOCKS5 (local proxy for testing) ---
    lines.append("socks5:")
    lines.append(f"  listen: 127.0.0.1:{local_port}")

    return "\n".join(lines) + "\n"


def test_hy2_node(node: dict, timeout: int = 5) -> dict | str | None:
    """
    Тестирует одну Hysteria2 ноду на работоспособность.
    Возвращает:
      - node с полем "_latency_ms" при успехе,
      - строку с причиной провала при ошибке,
      - None при критической ошибке.
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
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass  # Процесс работает — это хорошо

        if proc.returncode is not None and proc.returncode != 0:
            stdout, stderr = proc.communicate()
            output = (stderr or stdout or "").strip()
            return f"CLI exit {proc.returncode}: {output[:200]}"

        if not _hy2_wait_for_port("127.0.0.1", local_port, timeout=15.0):
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
            _, stderr = proc.communicate()
            err_info = stderr.strip()[:200] if stderr else "no output"
            return f"SOCKS5 port not ready ({err_info})"

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
                    return f"HTTP {http_code}"

        return f"curl failed: {res.stderr.strip()[:150]}"

    except FileNotFoundError:
        return None
    except Exception as e:
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

    num_workers = min(20, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} hy2 nodes with {num_workers} workers ({timeout}s timeout)...")

    # Сортируем для детерминизма
    sorted_outbounds = sorted(outbounds, key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)))

    working: list[dict] = []
    failed = 0

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        futures = {pool.submit(test_hy2_node, node, timeout): node for node in sorted_outbounds}
        results_map: dict[int, dict | None] = {}
        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            node_id = id(node)
            server = node.get("server", "?")
            port = node.get("server_port", "?")
            asn = resolve_asn(server)
            display = f"{server}:{port} {asn}" if asn else f"{server}:{port}"
            try:
                result = future.result()
                if result is not None:
                    if isinstance(result, str):
                        results_map[node_id] = None
                        failed += 1
                        print(f"  [{i}/{len(sorted_outbounds)}] {display}: FAIL — {result}")
                    else:
                        results_map[node_id] = result
                        working.append(result)
                        print(f"  [{i}/{len(sorted_outbounds)}] {display}: OK — {result.get('_latency_ms', '?')}ms")
                else:
                    results_map[node_id] = None
                    failed += 1
                    print(f"  [{i}/{len(sorted_outbounds)}] {display}: FAIL")
            except Exception as e:
                results_map[node_id] = None
                failed += 1
                print(f"  [{i}/{len(sorted_outbounds)}] {display}: ERROR — {e}")

    # Восстанавливаем порядок
    working.sort(key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)))

    if failed:
        print(f"{prefix}Hy2 connectivity: {len(working)} working / {failed} failed ({len(outbounds)} total).")

    return working
