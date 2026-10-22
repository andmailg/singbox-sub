"""Общие помощники для тестеров нод: запуск CLI-клиента, проверка через SOCKS5, пул потоков.

Раньше каждый тестер (vless, xhttp, hy2) содержал свою копию этого кода — с фиксированным
ожиданием 3–6 с на каждую ноду, гонкой за свободные порты и возвратом списка вместо
кортежа при отсутствии CLI.
"""

import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from src.testers.asn_resolver import resolve_asn

_ports_lock = threading.Lock()
_reserved_ports: set[int] = set()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def reserve_port() -> int:
    """Свободный локальный порт, не выданный другому потоку (bind(0)+close гоночный)."""
    with _ports_lock:
        while True:
            port = _free_port()
            if port not in _reserved_ports:
                _reserved_ports.add(port)
                return port


def release_port(port: int) -> None:
    with _ports_lock:
        _reserved_ports.discard(port)


class Child:
    """Фоновый CLI-клиент. Вывод идёт во временный файл, а не в PIPE: переполненный
    неprочитанный PIPE блокирует процесс."""

    def __init__(self, cmd: list[str]):
        self.log = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT)

    def output(self, limit: int = 200) -> str:
        try:
            self.log.seek(0)
            return self.log.read().decode("utf-8", "replace").strip()[:limit]
        except Exception:
            return ""

    def wait_ready(self, port: int, timeout: float, label: str = "CLI") -> str | None:
        """Ждёт SOCKS5-порт без фиксированной паузы. None — готов, иначе причина провала."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return f"{label} exit {self.proc.returncode}: {self.output()}"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return None
            except OSError:
                time.sleep(0.1)
        out = self.output()
        return f"SOCKS5 port not ready ({out})" if out else "SOCKS5 port not ready"

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def probe_socks(port: int, timeout: int, node: dict) -> dict | str:
    """Запрос через SOCKS5-прокси. node с _latency_ms при успехе, иначе строка-причина."""
    res = subprocess.run(
        [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}:%{time_total}",
            "--socks5-hostname", f"127.0.0.1:{port}",
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


def require_tool(tool: str, *version_args: str) -> None:
    """Без CLI результат теста не имеет смысла: падаем, а не считаем все ноды рабочими."""
    try:
        subprocess.run([tool, *(version_args or ("version",))], capture_output=True, timeout=5)
    except Exception as e:
        raise RuntimeError(f"'{tool}' CLI недоступен: {e}") from e


def _sort_key(o: dict) -> tuple:
    return (
        o.get("_country") or "",
        o.get("server") or "",
        o.get("server_port") or 0,
    )


def run_connectivity(
    outbounds: list[dict],
    test_fn: Callable[[dict, int], dict | str | None],
    label: str,
    tool: str,
    timeout: int = 5,
    prefix: str = "",
    max_workers: int = 20,
) -> tuple[list[dict], int, str]:
    """Параллельно тестирует ноды. Возвращает (рабочие ноды, число провалов, сводка подписок)."""
    require_tool(tool)
    if not outbounds:
        return [], 0, ""

    num_workers = min(max_workers, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} {label} nodes with {num_workers} workers ({timeout}s timeout)...")

    sorted_outbounds = sorted(outbounds, key=_sort_key)
    working: list[dict] = []
    failed = 0

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        futures = {pool.submit(test_fn, node, timeout): node for node in sorted_outbounds}
        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            server = node.get("server", "?")
            port = node.get("server_port", "?")
            asn = resolve_asn(server)
            sub_ids = node.get("_sub_ids", set())
            sub_ids_str = f" [{','.join(sorted(sub_ids))}]" if sub_ids else ""
            display = f"{server}:{port} {asn}" if asn else f"{server}:{port}"
            head = f"  [{i}/{len(sorted_outbounds)}] {display}{sub_ids_str}"
            try:
                result = future.result()
            except Exception as e:
                failed += 1
                print(f"{head}: ERROR — {e}")
                continue
            if isinstance(result, dict):
                working.append(result)
                print(f"{head}: OK — {result.get('_latency_ms', '?')}ms")
            else:
                failed += 1
                print(f"{head}: FAIL" + (f" — {result}" if result else ""))

    working.sort(key=_sort_key)
    all_sub_ids: set[str] = set()
    for w in working:
        all_sub_ids.update(w.get("_sub_ids", set()))
    summary = f" (subs: {','.join(sorted(all_sub_ids))})" if all_sub_ids else ""
    return working, failed, summary
