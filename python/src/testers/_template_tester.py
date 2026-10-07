"""Шаблон тестера для протокола X.

Для создания нового тестера:
1. Скопируй этот файл в src/testers/{proto}_node_tester.py
2. Реализуй test_{proto}_node() и test_{proto}_connectivity()
3. Укажи tester_func в pipeline вызове

Если тестирование не нужно — просто передай tester_func=None в run_pipeline().

Примеры:
  - src/testers/vless_node_tester.py — VLESS через Xray CLI + curl (SOCKS5)
  - src/testers/hy2_node_tester.py — Hysteria2 через hy2 CLI + curl
  - src/testers/vless_xhttp_node_tester.py — VLESS xhttp через Xray CLI + curl

Методы тестирования:
  1. CLI-тест: запустить клиент (xray, hy2, sing-box) с конфигом для одной ноды,
     проверить connectivitycheck.gstatic.com через curl --socks5.
  2. Прямой TCP: connect(host, port) + протокольный handshake.
  3. HTTP-запрос: через socks/proxy проверить connectivitycheck.gstatic.com.

Возврат из test_node():
  - При успехе: но́да (dict) с добавленным полем "_latency_ms".
  - При провале: строка с причиной (не печатать! — выводит test_connectivity).
  - При критической ошибке: None (например, нет CLI).

Возврат из test_connectivity():
  - tuple[list[dict], int, str] — (working_nodes, failed_count, sub_ids_summary).
  - Если CLI нет — возвращает исходный список без тестирования.
"""

import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


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


def _build_client_config(node: dict, local_port: int) -> tuple[str, list[str]]:
    """Генерирует конфигурацию клиента для тестирования ноды.

    Args:
        node: распарсенная нода в формате sing-box outbound.
        local_port: локальный порт для SOCKS5 прокси.

    Returns:
        Кортеж (config_content, cli_command).
        config_content — строка JSON/YAML конфигурации.
        cli_command — список команд для запуска клиента.
    """
    # TODO: реализуй генерацию конфигурации для клиента протокола X
    # Варианты:
    # 1. Xray CLI: JSON конфиг с outbounds/inbounds/streamSettings
    # 2. hy2 CLI: YAML конфиг с server/auth/tls/socks5
    # 3. sing-box CLI: JSON конфиг с outbounds
    #
    # Пример для Xray:
    #   config = {
    #       "log": {"loglevel": "error"},
    #       "inbounds": [{"port": local_port, "protocol": "socks", ...}],
    #       "outbounds": [{"protocol": "vless", "settings": {...}, "streamSettings": {...}}],
    #   }
    #   return json.dumps(config), ["xray", "run", "-c", config_file]

    raise NotImplementedError("Реализуй генерацию конфигурации клиента")


def test_node(node: dict, timeout: int = 5) -> dict | str | None:
    """Тестирует одну ноду протокола X на работоспособность.

    ВАЖНО: Не печатай логи внутри этой функции — возвращай причину провала
    как строку. Выводом занимается test_connectivity().

    Args:
        node: распарсенная нода в формате sing-box outbound.
        timeout: таймаут теста в секундах.

    Returns:
        - Но́да с полем "_latency_ms" при успехе,
        - Строка с причиной провала при ошибке (не печатать!),
        - None при критической ошибке (нет CLI и т.п.).

    Пример реализации через Xray CLI:
        1. Сгенерировать Xray-конфиг для ноды (включая reality settings).
        2. Запустить "xray run -c config.json" на локальном порту (SOCKS5).
        3. Дождаться готовности порта (wait_for_port).
        4. Выполнить "curl --socks5-hostname 127.0.0.1:{port} ..."
        5. Вернуть node с _latency_ms при HTTP 204/200, иначе — строку с ошибкой.

    Пример реализации через hy2 CLI:
        1. Сгенерировать YAML-конфиг с нодой в server/socks5.
        2. Запустить "hy2 client -c config.yaml".
        3. Проверить соединение через curl.

    Пример реализации через sing-box CLI:
        1. Сгенерировать sing-box-конфиг с нодой в outbounds.
        2. Запустить "sing-box run -c config.json".
        3. Проверить соединение через встроенный API или curl.
    """
    server = node["server"]
    port = node["server_port"]
    tag = node.get("tag", f"{server}:{port}")

    # TODO: реализуй тестирование ноды протокола X
    # Варианты:
    # 1. CLI-тест: запустить клиент (hy2, sing-box, v2ray) и проверить соединение
    # 2. Прямой TCP: connect(host, port) + протокольный handshake
    # 3. HTTP-запрос: через socks/proxy проверить connectivitycheck.gstatic.com
    # 4. Вернуть None если тестирование не требуется для этого протокола

    raise NotImplementedError("Реализуй тестирование протокола X")


def test_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """Проверяет работоспособность нод протокола X.

    Args:
        outbounds: список нод для тестирования.
        timeout: таймаут на каждую ноду.
        prefix: префикс для логов.

    Returns:
        Кортеж (working_nodes, failed_count, sub_ids_summary).
        working_nodes — только рабочие ноды (с добавленным полем _latency_ms).

    Пример реализации:
        1. Проверить доступность CLI (subprocess.run(["xray", "version"])).
        2. Если CLI нет — вернуть outbounds без тестирования.
        3. Запустить test_node в ThreadPoolExecutor (max_workers=20).
        4. Собрать результаты: working (с _latency_ms) и failed (причины).
        5. Отсортировать working по (country, server, port).
        6. Агрегировать sub_ids для summary.
    """
    # TODO: проверь доступность CLI/зависимостей для тестирования
    # Например: subprocess.run(["xray", "version"], ...) или ["hy2", "version"]

    num_workers = min(20, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} nodes with {num_workers} workers ({timeout}s timeout)...")

    # Сортируем для детерминизма
    sorted_outbounds = sorted(
        outbounds,
        key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0)),
    )

    working: list[dict] = []
    failed = 0

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        futures = {
            pool.submit(test_node, node, timeout): node
            for node in sorted_outbounds
        }
        results_map: dict[int, dict | str | None] = {}

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
                        print(f"  [{i}/{len(sorted_outbounds)}] {tag}: FAIL — {result}")
                    else:
                        results_map[node_id] = result
                        working.append(result)
                        print(f"  [{i}/{len(sorted_outbounds)}] {tag}: OK — {result.get('_latency_ms', '?')}ms")
                else:
                    results_map[node_id] = None
                    failed += 1
                    print(f"  [{i}/{len(sorted_outbounds)}] {tag}: FAIL")
            except Exception as e:
                results_map[node_id] = None
                failed += 1
                print(f"  [{i}/{len(sorted_outbounds)}] {tag}: ERROR — {e}")

    # Восстанавливаем порядок
    working.sort(
        key=lambda o: (o.get("_country", ""), o.get("server", ""), o.get("server_port", 0))
    )

    if failed:
        print(f"{prefix}Connectivity: {len(working)} working / {failed} failed ({len(outbounds)} total).")

    return working, failed, ""
