"""Управление pending-нодами — хранение, загрузка, сохранение.

Pending-ноды — это узлы, которые провалили тестирование и ожидают
переноса в blacklist по истечении --blacklist-timeout.

Формат файла: {"nodes": [...], "last_updated": "..."}
"""

import json
import os
from datetime import datetime, timezone


def load_pending_nodes(path: str) -> list[dict]:
    """Загружает список pending-нод из JSON-файла."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        nodes = data.get("nodes", [])
        for node in nodes:
            sub_ids = node.get("_sub_ids")
            if isinstance(sub_ids, list):
                node["_sub_ids"] = set(sub_ids)
        return nodes
    except Exception:
        return []


def save_pending_nodes(nodes: list[dict], path: str) -> None:
    """Сохраняет список pending-нод в JSON-файл."""
    for node in nodes:
        sub_ids = node.get("_sub_ids")
        if isinstance(sub_ids, set):
            node["_sub_ids"] = sorted(sub_ids)
    data = {
        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nodes": nodes,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def merge_pending_nodes(
    existing: list[dict],
    candidates: list[dict],
    cache_key_func,
) -> tuple[list[dict], int]:
    """Добавляет новые pending-ноды к существующим.

    Возвращает (объединённый список, количество добавленных).
    """
    existing_map: dict[str, dict] = {
        cache_key_func(n): n for n in existing
    }
    added = 0
    for node in candidates:
        key = cache_key_func(node)
        if key not in existing_map:
            existing_map[key] = node
            added += 1
    result = list(existing_map.values())
    return result, added


def remove_nodes_by_keys(nodes: list[dict], keys_to_remove: set[str], cache_key_func) -> list[dict]:
    """Удаляет ноды по множеству ключей."""
    return [n for n in nodes if cache_key_func(n) not in keys_to_remove]
