import json
import subprocess
import sys
import time
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


def test_node_hy2cli(node: dict, timeout: int = 5) -> dict | None:
    """Тестирует ноду, запускала hy2 CLI на короткое время."""
    server = node["server"]
    port = node["server_port"]
    password = node["password"]
    sni = node.get("tls", {}).get("server_name", "")
    tag = node.get("tag", f"{server}:{port}")

    # Используем --socks5 127.0.0.1:0, чтобы ОС выделяла случайный свободный порт
    # для каждого потока отдельно во избежание конфликтов "Port already in use".
    cmd = [
        "hy2", "connect",
        "--server", f"{server}:{port}",
        "--password", password,
        "--server-name", sni,
        "--socks5", "127.0.0.1:0"
    ]

    start = time.time()
    proc = None
    try:
        # Запускаем клиент в фоне
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        # Ждем 2 секунды (достаточно для установки соединения и хэндшейка)
        time.sleep(2.0)
        
        # Проверяем, не завершился ли процесс аварийно за это время
        return_code = proc.poll()
        elapsed = time.time() - start
        
        if return_code is not None:
            # Процесс завершился сам -> ошибка авторизации или сети
            stdout, stderr = proc.communicate()
            output = (stdout or "") + (stderr or "")
            return {
                "tag": tag,
                "server": server,
                "port": port,
                "status": "FAIL",
                "latency_ms": round(elapsed * 1000),
                "details": output.strip()[:200],
            }
        else:
            # Процесс активен и работает -> соединение успешно!
            proc.terminate()  # Корректно закрываем туннель
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                
            return {
                "tag": tag,
                "server": server,
                "port": port,
                "status": "OK",
                "latency_ms": round(elapsed * 1000),
                "details": "Connected successfully",
            }

    except FileNotFoundError:
        return None  # Утилита hy2 не установлена в системе
    except Exception as e:
        if proc:
            proc.kill()
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "ERROR",
            "latency_ms": 0,
            "details": str(e),
        }


def format_table(results: list[dict]) -> str:
    """Форматирует результаты тестирования в красивую текстовую таблицу."""
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
    # Парсим аргументы командной строки
    config_path = sys.argv[1] if len(sys.argv) > 1 else "hy2-tun.json"
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    print(f"Loading nodes from {config_path}...")
    nodes = load_nodes(config_path)
    print(f"Found {len(nodes)} Hysteria2 nodes")

    if not nodes:
        print("No Hysteria2 nodes found!")
        sys.exit(1)

    print(f"Starting parallel test using hy2 CLI ({workers} workers)...\n")
    
    results = []
    start_all = time.time()

    # Пул многопоточности для одновременной проверки
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(test_node_hy2cli, node): node for node in nodes}
        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            tag = node.get("tag", f"node-{i}")
            try:
                res = future.result()
                if res is None:
                    print("Ошибка: Бинарный файл 'hy2' не найден в PATH. Установите Hysteria2 CLI.")
                    sys.exit(1)
                
                results.append(res)
                status_icon = "✓" if res["status"] == "OK" else "✗"
                print(f"[{i}/{len(nodes)}] {tag}: {status_icon} {res['status']} — {res['latency_ms']}ms")
            except Exception as e:
                print(f"[{i}/{len(nodes)}] {tag}: ✗ ERROR — {e}")

    total_time = time.time() - start_all

    print(f"\n{'='*70}")
    print(format_table(results))

    # Считаем статистику
    ok_count = sum(1 for r in results if r["status"] == "OK")
    fail_count = len(results) - ok_count
    print(f"\nSummary: {ok_count} OK / {fail_count} FAIL — Total: {len(results)} — Time: {total_time:.1f}s")

    # Сохраняем результаты в постоянный файл для удобства отслеживания в Git
    out_file = "latest_results.json"
    
    # Добавляем метаданные о времени проверки внутрь структуры JSON
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
