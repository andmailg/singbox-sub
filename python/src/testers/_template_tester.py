"""Шаблон тестера для протокола X.

Для создания нового тестера:
1. Скопируй этот файл в src/testers/{proto}_node_tester.py
2. Реализуй test_node() и test_connectivity()
3. Укажи tester_func в pipeline вызове

Если тестирование не нужно — просто передай tester_func=None в run_pipeline().
"""

import subprocess
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# TODO: измени имя файла кэша если нужно отдельный кэш для протокола
_CACHE_FILE = "test_cache.json"


def _cache_key(node: dict) -> str:
    """Уникальный ключ для кэширования ноды."""
    # TODO: используй уникальные поля протокола X
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('password', '')}"


def _load_test_cache() -> dict:
    """Загружает кэш результатов теста из JSON-файла."""
    import json
    import os
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_test_cache(cache: dict) -> None:
    """Сохраняет кэш результатов теста в JSON-файл."""
    import json
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


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
) -> list[dict]:
    """Проверяет работоспособность нод протокола X.

    Args:
        outbounds: список нод для тестирования.
        timeout: таймаут на каждую ноду.
        prefix: префикс для логов.

    Returns:
        Только рабочие ноды (с добавленным полем _latency_ms).
    """
    # TODO: проверь доступность CLI/зависимостей для тестирования
    # Например: subprocess.run(["sing-box", "version"], ...)

    # Загружаем кэш результатов
    cache = _load_test_cache()

    num_workers = min(20, len(outbounds))
    print(f"{prefix}Testing {len(outbounds)} nodes with {num_workers} workers ({timeout}s timeout)...")

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
                pool.submit(test_node, node, timeout): node
                for node in new_nodes
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
                        if result is not None and not isinstance(result, str):
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
        print(f"{prefix}Connectivity: {len(working)} working / {failed} failed ({len(outbounds)} total).")
        if cached_ok or cached_fail:
            print(f"{prefix}  (cached: {cached_ok} OK, {cached_fail} FAIL; tested: {len(new_nodes)} new)")

    return working
