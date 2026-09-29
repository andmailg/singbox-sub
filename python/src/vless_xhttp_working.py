"""Управление рабочими нодами VLESS xhttp — хранение, загрузка, сохранение."""

import hashlib
import json
import os
from datetime import datetime, timezone

_WORKING_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "vless_xhttp_working.json",
)


def _asn_key() -> str:
    """Хеш текущего ASN_LIST для валидации working-файла."""
    try:
        from src.rkn_filter.extra_blocked_cidr import ASN_LIST
        raw = "|".join(sorted(ASN_LIST))
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    except Exception:
        return ""


def _cache_key(node: dict) -> str:
    """Уникальный ключ для ноды: server:port:uuid:path."""
    path = node.get("transport", {}).get("path", "/")
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}:{path}"


def load_working_nodes(path: str = _WORKING_FILE) -> list[dict]:
    """Загружает список рабочих нод из JSON-файла.
    
    Если _asn_key не совпадает с текущим ASN_LIST — возвращает пустой список.
    """
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        cached_key = data.get("_asn_key", "")
        current_key = _asn_key()
        if cached_key and cached_key != current_key:
            print(f"  [Working] ASN_LIST changed, discarding {os.path.basename(path)}")
            return []
        
        return data.get("nodes", [])
    except Exception:
        return []


def save_working_nodes(nodes: list[dict], path: str = _WORKING_FILE) -> None:
    """Сохраняет список рабочих нод в JSON-файл с метаданными ASN."""
    data = {
        "_asn_key": _asn_key(),
        "last_tested": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nodes": nodes,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def dedup_nodes(nodes: list[dict]) -> list[dict]:
    """Удаляет дубликаты по ключу server:port:uuid:path, оставляя последнюю версию."""
    seen: dict[str, dict] = {}
    for node in nodes:
        key = _cache_key(node)
        seen[key] = node
    return list(seen.values())


def merge_new_nodes(
    existing: list[dict],
    candidates: list[dict],
) -> tuple[list[dict], int]:
    """Добавляет новые ноды к существующим (по ключу server:port:uuid:path).

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
