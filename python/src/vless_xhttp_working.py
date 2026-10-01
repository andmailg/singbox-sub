"""Управление рабочими нодами VLESS xhttp — хранение, загрузка, сохранение."""

import hashlib
import json
import os
from datetime import datetime, timezone

from src.rkn_filter import load_rkn_list
from src.rkn_filter.rkn_filter import check_rkn_blocked
from src.common import session as http_session

_WORKING_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "vless_xhttp_working.json",
)


def _asn_key() -> str:
    """Хеш ASN_LIST + HARDCODED_CIDR для валидации working-файла."""
    try:
        from src.rkn_filter.rkn_config import ASN_LIST, HARDCODED_CIDR
        raw = "|".join(sorted(ASN_LIST))
        hc = "|".join(f"{asn}={','.join(sorted(cidrs))}" for asn, cidrs in sorted(HARDCODED_CIDR.items()))
        return hashlib.sha256((raw + "|" + hc).encode()).hexdigest()[:16]
    except Exception:
        return ""


def _cache_key(node: dict) -> str:
    """Уникальный ключ для ноды: server:port:uuid:path."""
    path = node.get("transport", {}).get("path", "/")
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}:{path}"


def load_working_nodes(path: str = _WORKING_FILE) -> list[dict]:
    """Загружает список рабочих нод из JSON-файла.
    
    Если _asn_key не совпадает — фильтрует ноды по обновлённому RKN-кэшу.
    """
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        cached_key = data.get("_asn_key", "")
        current_key = _asn_key()
        
        nodes = data.get("nodes", [])
        for node in nodes:
            sub_ids = node.get("_sub_ids")
            if isinstance(sub_ids, list):
                node["_sub_ids"] = set(sub_ids)
        
        # Если ключ совпадает — возвращаем как есть
        if not cached_key or cached_key == current_key:
            return nodes
        
        # Ключ не совпадает — фильтруем ноды по обновлённому RKN-кэшу
        print(f"  [Working] {os.path.basename(path)} ASN key mismatch, filtering nodes...")
        
        # Загружаем RKNBlockList (перестроит кэш если нужно)
        rkn = load_rkn_list(http_session)
        
        filtered = []
        removed_count = 0
        for node in nodes:
            server = node.get("server", "")
            result = check_rkn_blocked(server, rkn)
            if result is True:
                removed_count += 1
            else:
                # False (не заблокирована) или None (не удалось определить IP) — оставляем
                filtered.append(node)
        
        if removed_count:
            print(f"  [Working] Removed {removed_count} RKN-blocked node(s)")
            save_working_nodes(filtered, path)
        
        return filtered
    except Exception:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        cached_key = data.get("_asn_key", "")
        current_key = _asn_key()
        if cached_key and cached_key != current_key:
            print(f"  [Working] ASN_LIST changed, discarding {os.path.basename(path)}")
            return []
        
        nodes = data.get("nodes", [])
        # Конвертируем _sub_ids из list обратно в set
        for node in nodes:
            sub_ids = node.get("_sub_ids")
            if isinstance(sub_ids, list):
                node["_sub_ids"] = set(sub_ids)
        return nodes
    except Exception:
        return []


def save_working_nodes(nodes: list[dict], path: str = _WORKING_FILE) -> None:
    """Сохраняет список рабочих нод в JSON-файл с метаданными ASN."""
    # Конвертируем _sub_ids из set в list для сериализации
    for node in nodes:
        sub_ids = node.get("_sub_ids")
        if isinstance(sub_ids, set):
            node["_sub_ids"] = sorted(sub_ids)
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
