import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def load_nodes(config_path: str) -> list[dict]:
    """Загружает ноды VLESS из конфигурационного файла JSON (sing-box формат)."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Ошибка: Файл конфигурации '{config_path}' не найден.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Ошибка: Файл '{config_path}' содержит некорректный JSON.")
        sys.exit(1)

    nodes = []
    for outbound in config.get("outbounds", []):
        if outbound.get("type") == "vless" and "server" in outbound:
            nodes.append(outbound)
    return nodes


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
    transport_cfg = node.get("transport", {})
    if not isinstance(transport_cfg, dict):
        transport_cfg = {}
    network = transport_cfg.get("type", "tcp")
    
    # Build streamSettings для Xray
    stream_settings = _build_stream_settings(node, network)
    
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
    stream_settings = {"network": network}
    
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
        path = transport_cfg.get("path") or "/"
        headers: dict = transport_cfg.get("headers") or {}
        stream_settings["wsSettings"] = {
            "path": path,
            "headers": headers
        }
    elif network in ("grpc", "gun"):
        service_name = transport_cfg.get("service_name") or ""
        stream_settings["grpcSettings"] = {
            "serviceName": service_name
        }
    elif network in ("http", "h2"):
        host: list = transport_cfg.get("host") or []
        path = transport_cfg.get("path") or "/"
        stream_settings["httpSettings"] = {
            "host": host,
            "path": path
        }
    elif network == "httpupgrade":
        host = transport_cfg.get("host") or ""
        path = transport_cfg.get("path") or "/"
        stream_settings["httpupgradeSettings"] = {
            "host": host,
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


def test_node_xray_vless(node: dict, timeout: int = 5) -> dict | None:
    """
    Тестирует ноду VLESS через Xray CLI с SOCKS5-прокси.
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
            return {
                "tag": tag, "server": server, "port": port, "status": "FAIL",
                "latency_ms": 0,
                "details": f"CLI exit {proc.returncode}: {output[:300]}"
            }

        # 3. Ждём, пока SOCKS5-порт станет доступен
        if not wait_for_port("127.0.0.1", local_port, timeout=5.0):
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
            return {
                "tag": tag, "server": server, "port": port, "status": "FAIL",
                "latency_ms": 0,
                "details": "SOCKS5 port did not become ready within 5s"
            }

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

                if http_code in ["204", "200"]:
                    status = "OK"
                    details = "Connected and verified"
                else:
                    status = "FAIL"
                    details = f"HTTP Status {http_code}"
            else:
                status = "FAIL"
                latency = 0
                details = f"Malformed curl output: {res.stdout}"
        else:
            status = "FAIL"
            latency = 0
            err_msg = res.stderr.strip() if res.stderr else f"Exit code {res.returncode}"
            details = f"Curl failed: {err_msg[:100]}"

    except Exception as e:
        status = "ERROR"
        latency = 0
        details = str(e)
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

    return {
        "tag": tag,
        "server": server,
        "port": port,
        "status": status,
        "latency_ms": latency,
        "details": details
    }


def format_table(results: list[dict]) -> str:
    """Форматирует результаты тестирования в текстовую таблицу."""
    lines = []
    header = f"{'Tag':<20} {'Server':<18} {'Port':<6} {'Status':<10} {'Latency':<10}"
    lines.append(header)
    lines.append("-" * len(header))
    for r in results:
        lines.append(
            f"{r['tag']:<20} {r['server']:<18} {r['port']:<6} {r['status']:<10} {r['latency_ms']}ms"
        )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    """Парсит аргументы командной строки для pipeline-интеграции."""
    parser = argparse.ArgumentParser(
        description="VLESS node connectivity tester (Xray based)"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="vless_reality_tun.json",
        help="Input Sing-box config with VLESS outbounds (default: vless_reality_tun.json)",
    )
    parser.add_argument(
        "-o", "--output",
        default="latest_results.json",
        help="Output results JSON file (default: latest_results.json)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=20,
        help="Max parallel workers (default: 20)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=5,
        help="Timeout per node test in seconds (default: 5)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print only summary (no table, no per-node output)",
    )
    parser.add_argument(
        "--min-ports",
        type=int,
        default=0,
        help="Minimum working ports required to pass (CI exit 1 if below)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Проверка наличия Xray CLI
    try:
        ver = subprocess.run(["xray", "version"], capture_output=True, text=True, timeout=5)
        print(f"Xray CLI: {ver.stdout.strip() or ver.stderr.strip()}")
    except FileNotFoundError:
        print("Ошибка: 'xray' не найден в PATH. Убедитесь, что Xray CLI установлен.")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка проверки Xray CLI: {e}")
        sys.exit(1)

    print(f"Loading nodes from {args.input}...")
    nodes = load_nodes(args.input)
    print(f"Found {len(nodes)} VLESS nodes")

    if not nodes:
        print("No VLESS nodes found!")
        sys.exit(1)

    print(f"Starting parallel test ({args.workers} workers, {args.timeout}s timeout)...\n")

    results = []
    start_all = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(test_node_xray_vless, node, args.timeout): node for node in nodes}
        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            tag = node.get("tag", f"node-{i}")
            try:
                res = future.result()
                if res:
                    results.append(res)
                    if not args.summary:
                        status_icon = "✓" if res["status"] == "OK" else "✗"
                        print(f"[{i}/{len(nodes)}] {tag}: {status_icon} {res['status']} — {res['latency_ms']}ms")
            except Exception as e:
                if not args.summary:
                    print(f"[{i}/{len(nodes)}] {tag}: ✗ ERROR — {e}")

    total_time = time.time() - start_all

    ok_count = sum(1 for r in results if r["status"] == "OK")
    fail_count = len(results) - ok_count

    if args.summary:
        print(f"Summary: {ok_count} OK / {fail_count} FAIL — Total: {len(results)} — Time: {total_time:.1f}s")
    else:
        print(f"\n{'='*70}")
        print(format_table(results))
        print(f"\nSummary: {ok_count} OK / {fail_count} FAIL — Total: {len(results)} — Time: {total_time:.1f}s")

    out_file = args.output or "latest_results.json"
    output_data = {
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_nodes": len(results),
        "working_nodes": ok_count,
        "results": results
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f"Results saved to {out_file}")

    # CI gate: fail if below minimum working ports
    if args.min_ports > 0 and ok_count < args.min_ports:
        print(f"\nCI FAIL: Only {ok_count} working ports, minimum required: {args.min_ports}")
        sys.exit(1)

    print("Done.")


if __name__ == "__main__":
    main()
