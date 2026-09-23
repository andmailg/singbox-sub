"""Управление рабочими нодами Hysteria2 — хранение, загрузка, сохранение."""

import json
import os
from datetime import datetime, timezone

_WORKING_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "hy2_working.json",
)

# Нода считается "устаревшей", если последний успешный тест > STALE_DAYS назад
STALE_DAYS = 14


def _cache_key(node: dict) -> str:
    """Уникальный ключ для ноды: server:port:password."""
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('password')}"


def load_working_nodes(path: str = _WORKING_FILE) -> list[dict]:
    """Загружает список рабочих нод из JSON-файла."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("nodes", [])
    except Exception:
        return []


def save_working_nodes(nodes: list[dict], path: str = _WORKING_FILE) -> None:
    """Сохраняет список рабочих нод в JSON-файл."""
    data = {
        "last_tested": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nodes": nodes,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def remove_stale_nodes(nodes: list[dict], stale_days: int = STALE_DAYS) -> list[dict]:
    """Удаляет ноды, которые не тестировались дольше stale_days."""
    cutoff = datetime.now(timezone.utc).timestamp() - stale_days * 86400
    kept = []
    removed = 0
    for node in nodes:
        last_ok = node.get("_last_ok_ts", 0)
        if last_ok and last_ok >= cutoff:
            kept.append(node)
        else:
            removed += 1
    if removed:
        print(f"  Removed {removed} stale nodes (last test > {stale_days} days ago).")
    return kept


def dedup_nodes(nodes: list[dict]) -> list[dict]:
    """Удаляет дубликаты по ключу server:port:password, оставляя последнюю версию."""
    seen: dict[str, dict] = {}
    for node in nodes:
        key = _cache_key(node)
        seen[key] = node
    return list(seen.values())


def merge_new_nodes(
    existing: list[dict],
    candidates: list[dict],
) -> tuple[list[dict], int]:
    """Добавляет новые ноды к существующим (по ключу server:port:password).

    Возвращает (объединённый список, количество добавленных).
    """
    existing_map: dict[str, dict] = {
        _cache_key(n): n for n in existing
    }
    added = 0
    for node in candidates:
        key = _cache_key(node)
        if key not in existing_map:
            existing_map[key] = node
            added += 1
    result = list(existing_map.values())
    return result, added
