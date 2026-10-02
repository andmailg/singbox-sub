"""Whitelist for persistent nodes that always get tested and restored."""

import json
import os
from datetime import datetime, timezone

_WHITELIST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "whitelist.json",
)


def load_whitelist() -> dict[str, list[dict]]:
    """Загружает whitelist — словарь {protocol: [{key, node}]}.
    
    Каждая запись содержит:
      - key: уникальный ключ ноды
      - node: полная конфигурация ноды для восстановления
    """
    if not os.path.exists(_WHITELIST_FILE):
        return {"vless_xhttp": [], "vless_tcp": [], "hy2": []}
    try:
        with open(_WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = {}
        for proto, entries in data.get("whitelist", {}).items():
            result[proto] = entries if isinstance(entries, list) else []
        for proto in ("vless_xhttp", "vless_tcp", "hy2"):
            result.setdefault(proto, [])
        return result
    except Exception:
        return {"vless_xhttp": [], "vless_tcp": [], "hy2": []}


def save_whitelist(whitelist: dict[str, list[dict]]) -> None:
    """Сохраняет whitelist в JSON-файл с подсчётом количества нод."""
    counts = {proto: len(entries) for proto, entries in whitelist.items()}
    data = {
        "whitelist": {
            **{proto: entries for proto, entries in whitelist.items()},
            **{f"{proto}_count": counts.get(proto, 0) for proto in whitelist},
        },
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(_WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_whitelisted(node: dict, whitelist: dict[str, list[dict]], protocol: str) -> bool:
    """Проверяет, находится ли нода в whitelist для данного протокола."""
    entries = whitelist.get(protocol, [])
    if not entries:
        return False
    key = _cache_key(node, protocol)
    return any(e.get("key") == key for e in entries)


def add_to_whitelist(node: dict, protocol: str) -> None:
    """Добавляет ноду в whitelist для данного протокола."""
    whitelist = load_whitelist()
    entries = whitelist.setdefault(protocol, [])
    key = _cache_key(node, protocol)
    # Не дублируем
    if any(e.get("key") == key for e in entries):
        return
    # Копируем ноду, убираем внутренние поля
    node_copy = {k: v for k, v in node.items() if not k.startswith("_")}
    entries.append({"key": key, "node": node_copy})
    save_whitelist(whitelist)


def get_whitelist_nodes(protocol: str, whitelist: dict[str, list[dict]]) -> list[dict]:
    """Возвращает список полных нод из whitelist для данного протокола."""
    entries = whitelist.get(protocol, [])
    return [e.get("node", {}) for e in entries if "node" in e]


def _cache_key(node: dict, protocol: str) -> str:
    """Уникальный ключ для ноды с учётом протокола."""
    if protocol == "vless_xhttp":
        path = node.get("transport", {}).get("path", "/")
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}:{path}"
    elif protocol == "vless_tcp":
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}"
    elif protocol == "hy2":
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('password')}"
    else:
        return f"{node.get('server')}:{node.get('server_port')}"
