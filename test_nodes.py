import json
import subprocess
import sys
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
        return s.getsockname()[1]


def test_node_hy2cli(node: dict, timeout: int = 5) -> dict | None:
    """
    Тестирует ноду в GitHub Actions, делая запрос через системный curl
    и поднятый локально SOCKS5-прокси Hysteria2.
    """
    server = node["server"]
    port = node["server_port"]
    password = node["password"]
    sni = node.get("tls", {}).get("server_name", "")
    tag = node.get("tag", f"{server}:{port}")

    local_port = get_free_port()

    # Формируем команду для запуска клиента Hysteria2
    hy2_cmd = [
        "hy2", "client",
        "--server", f"{server}:{port}",
        "--password", password,
        "--server-name", sni,
        "--socks5", f"127.0.0.1:{local_port}",
        "--log-level", "error"
    ]

    proc = None
    try:
        # 1. Запускаем туннель Hysteria2 в фоне
        proc = subprocess.Popen(
            hy2_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Даем 1 секунду на инициализацию локального порта
        time.sleep(1.0)
        
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            return {
                "tag": tag, "server": server, "port": port, "status": "FAIL",
                "latency_ms": 0,
                "details": f"CLI init failed: {(stdout or '') + (stderr or '')}".strip()[:200]
            }

        # 2. Выполняем проверку через системный curl с проксированием
        # --socks5-hostname заставляет резолвить домен внутри прокси (защита от утечек)
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}:%{time_total}",
            "--socks5-hostname", f"127.0.0.1:{local_port}",
            "--max-time", str(timeout),
            "https://connectivity.cloudflareclient.com"
        ]

        curl_start = time.time()
        res = subprocess.run(curl_cmd, capture_output=True, text=True)
        
        if res.returncode == 0 and res.stdout:
            # curl возвращает строку вида "204:0.145" (http_code:time_total)
            parts = res.stdout.strip().split(":")
            http_code = parts[0]
            time_total = float(parts[1]) if len(parts) > 1 else 0.0
            latency = round(time_total * 1000)

            if http_code in ["204", "200"]:
                status = "OK"
                details = "Connected and verified via curl"
            else:
                status = "FAIL"
                details = f"HTTP Status {http_code}"
        else:
            status = "FAIL"
            latency = round((time.time() - curl_start) * 1000)
            details = res.stderr.strip()[:200] if res.stderr else f"Curl exited with code {res.returncode}"

    except Exception as e:
        status = "ERROR"
        latency = 0
        details = str(e)
    finally:
        # 3. Гарантированно убиваем фоновый процесс Hysteria2
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()

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
