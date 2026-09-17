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
    """Загружает ноды Hysteria2 из конфигурационного файла JSON."""
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
        if outbound.get("type") == "hysteria2" and "server" in outbound:
            nodes.append(outbound)
    return nodes


def get_free_port() -> int:
    """Находит случайный свободный порт на локальной машине."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]  # Явно берем только инт порта


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


def _yaml_escape(value: str) -> str:
    """Экранирует строку для YAML — оборачивает в двойные кавычки."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _build_yaml(node: dict, local_port: int) -> str:
    """Генерирует YAML-конфигурацию для Hysteria 2 client на основе ноды."""
    server = node["server"]
    port = node["server_port"]
    password = node["password"]
    sni = node.get("tls", {}).get("server_name", "")
    tls_cfg = node.get("tls", {})
    obfs_cfg = node.get("obfs", {})

    lines = [
        "server: " + _yaml_escape(f"{server}:{port}"),
        "auth: " + _yaml_escape(password),
        "tls:",
    ]

    if sni:
        lines.append("  sni: " + _yaml_escape(sni))

    # insecure — если нет pinSHA256, отключаем проверку сертификата
    if "pinSHA256" not in tls_cfg:
        lines.append("  insecure: true")

    # obfs (obfuscation)
    if obfs_cfg and obfs_cfg.get("type"):
        obfs_type = obfs_cfg["type"]
        lines.append("obfs:")
        if obfs_type == "salamander":
            lines.append("  type: salamander")
            lines.append("  salamander:")
            lines.append("    password: " + _yaml_escape(obfs_cfg.get("password", "")))
        elif obfs_type == "gecko":
            lines.append("  type: gecko")
            lines.append("  gecko:")
            lines.append("    password: " + _yaml_escape(obfs_cfg.get("password", "")))
            min_pkt = obfs_cfg.get("min_packet_size")
            max_pkt = obfs_cfg.get("max_packet_size")
            if min_pkt is not None:
                lines.append("    min_packet_size: " + str(min_pkt))
            if max_pkt is not None:
                lines.append("    max_packet_size: " + str(max_pkt))

    # bandwidth
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


def test_node_hy2cli(node: dict, timeout: int = 5) -> dict | None:
    """
    Тестирует ноду в GitHub Actions, делая запрос через системный curl
    и поднятый локально SOCKS5-прокси Hysteria2.

    Hysteria 2 CLI работает ТОЛЬКО через YAML-конфигурационный файл.
    """
    server = node["server"]
    port = node["server_port"]
    tag = node.get("tag", f"{server}:{port}")

    local_port = get_free_port()
    yaml_content = _build_yaml(node, local_port)

    proc = None
    config_file = None
    try:
        # 1. Создаём временный YAML-файл конфигурации
        config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        config_file.write(yaml_content)
        config_file.close()

        # 2. Запускаем Hysteria 2 client с YAML-конфигом
        hy2_cmd = [
            "hy2", "client",
            "-c", config_file.name,
        ]

        proc = subprocess.Popen(
            hy2_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
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
        # 5. Гарантированно убиваем фоновый процесс Hysteria2
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()

        # Удаляем временный YAML-файл
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


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "hy2-tun.json"
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    # Проверка наличия hy2 CLI
    try:
        ver = subprocess.run(["hy2", "version"], capture_output=True, text=True, timeout=5)
        print(f"hy2 CLI: {ver.stdout.strip() or ver.stderr.strip()}")
    except FileNotFoundError:
        print("Ошибка: 'hy2' не найден в PATH. Убедитесь, что Hysteria CLI установлен.")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка проверки hy2 CLI: {e}")
        sys.exit(1)

    print(f"Loading nodes from {config_path}...")
    nodes = load_nodes(config_path)
    print(f"Found {len(nodes)} Hysteria2 nodes")

    if not nodes:
        print("No Hysteria2 nodes found!")
        sys.exit(1)

    print(f"Starting parallel test using hy2 CLI & curl ({workers} workers)...\n")
    
    results = []
    start_all = time.time()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(test_node_hy2cli, node): node for node in nodes}
        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            tag = node.get("tag", f"node-{i}")
            try:
                res = future.result()
                if res:
                    results.append(res)
                    status_icon = "✓" if res["status"] == "OK" else "✗"
                    print(f"[{i}/{len(nodes)}] {tag}: {status_icon} {res['status']} — {res['latency_ms']}ms")
            except Exception as e:
                print(f"[{i}/{len(nodes)}] {tag}: ✗ ERROR — {e}")

    total_time = time.time() - start_all

    print(f"\n{'='*70}")
    print(format_table(results))

    ok_count = sum(1 for r in results if r["status"] == "OK")
    fail_count = len(results) - ok_count
    print(f"\nSummary: {ok_count} OK / {fail_count} FAIL — Total: {len(results)} — Time: {total_time:.1f}s")

    out_file = "latest_results.json"
    output_data = {
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_nodes": len(results),
        "working_nodes": ok_count,
        "results": results
    }
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f"Results saved to {out_file}")


if __name__ == "__main__":
    main()
