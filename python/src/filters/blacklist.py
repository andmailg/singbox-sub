"""Blacklist for permanently blocked proxy nodes.

Format: {"blacklist": {"vless_xhttp": [...], "vless_tcp": [...], "hy2": [...], "vless_grpc": [...]}}
"""

import json
import os
from datetime import datetime, timezone

_BLACKLIST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "blacklist.json",
)


def load_blacklist() -> dict[str, set[str]]:
    """Загружает blacklist — словарь {protocol: set[cache_key]}.
    
    Ключи для каждого протокола:
      vless_xhttp — server:port:uuid:path
      vless_tcp   — server:port:uuid
      hy2         — server:port:password
      vless_grpc  — server:port:uuid:service_name
    """
    if not os.path.exists(_BLACKLIST_FILE):
        return {"vless_xhttp": set(), "vless_tcp": set(), "hy2": set(), "vless_grpc": set()}
    try:
        with open(_BLACKLIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = {}
        for proto, keys in data.get("blacklist", {}).items():
            result[proto] = set(keys)
        # Ensure all protocols exist
        for proto in ("vless_xhttp", "vless_tcp", "hy2", "vless_grpc"):
            result.setdefault(proto, set())
        return result
    except Exception:
        return {"vless_xhttp": set(), "vless_tcp": set(), "hy2": set(), "vless_grpc": set()}


def save_blacklist(blacklist: dict[str, set[str]]) -> None:
    """Сохраняет blacklist в JSON-файл."""
    data = {
        "blacklist": {
            proto: sorted(keys) for proto, keys in blacklist.items()
        },
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(_BLACKLIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_blacklisted(node: dict, blacklist: dict[str, set[str]], protocol: str) -> bool:
    """Проверяет, находится ли нода в blacklist для данного протокола."""
    keys = blacklist.get(protocol, set())
    if not keys:
        return False
    key = _cache_key(node, protocol)
    return key in keys


def add_to_blacklist(node: dict, protocol: str) -> None:
    """Добавляет ноду в blacklist для данного протокола."""
    blacklist = load_blacklist()
    proto_keys = blacklist.setdefault(protocol, set())
    proto_keys.add(_cache_key(node, protocol))
    save_blacklist(blacklist)


def _cache_key(node: dict, protocol: str) -> str:
    """Уникальный ключ для ноды с учётом протокола."""
    if protocol == "vless_xhttp":
        path = node.get("transport", {}).get("path", "/")
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}:{path}"
    elif protocol == "vless_tcp":
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}"
    elif protocol == "hy2":
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('password')}"
    elif protocol == "vless_grpc":
        service_name = node.get("transport", {}).get("service_name", "")
        return f"{node.get('server')}:{node.get('server_port')}:{node.get('uuid')}:{service_name}"
    else:
        # Fallback — используем server:port
        return f"{node.get('server')}:{node.get('server_port')}"
