"""Whitelist for persistent nodes that always get tested."""

import json
import os
from datetime import datetime, timezone

_WHITELIST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "whitelist.json",
)


def load_whitelist() -> dict[str, set[str]]:
    """Загружает whitelist — словарь {protocol: set[cache_key]}."""
    if not os.path.exists(_WHITELIST_FILE):
        return {"vless_xhttp": set(), "vless_tcp": set(), "hy2": set()}
    try:
        with open(_WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = {}
        for proto, keys in data.get("whitelist", {}).items():
            result[proto] = set(keys)
        for proto in ("vless_xhttp", "vless_tcp", "hy2"):
            result.setdefault(proto, set())
        return result
    except Exception:
        return {"vless_xhttp": set(), "vless_tcp": set(), "hy2": set()}


def save_whitelist(whitelist: dict[str, set[str]]) -> None:
    """Сохраняет whitelist в JSON-файл."""
    data = {
        "whitelist": {
            proto: sorted(keys) for proto, keys in whitelist.items()
        },
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(_WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_whitelisted(node: dict, whitelist: dict[str, set[str]], protocol: str) -> bool:
    """Проверяет, находится ли нода в whitelist для данного протокола."""
    keys = whitelist.get(protocol, set())
    if not keys:
        return False
    key = _cache_key(node, protocol)
    return key in keys


def add_to_whitelist(node: dict, protocol: str) -> None:
    """Добавляет ноду в whitelist для данного протокола."""
    whitelist = load_whitelist()
    proto_keys = whitelist.setdefault(protocol, set())
    proto_keys.add(_cache_key(node, protocol))
    save_whitelist(whitelist)


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
