"""Парсинг и фильтрация ссылок VLESS with WebSocket."""

import urllib.parse


def parse_proxy_link(link: str, require_cloudfront: bool = False) -> dict | None:
    """
    Парсит VLESS WS ссылку.
    require_cloudfront=True — фильтрует только cloudfront.net узлы.
    """
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
        hostname = parsed.hostname
        if not hostname:
            return None
        hostname = hostname.strip("[]")
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Проверка типа сети — только ws
    net_type = params.get("type", [""])[0].lower()
    if net_type != "ws":
        return None

    # 2. Извлечение параметров host и path
    host = params.get("host", [""])[0].strip()
    path = params.get("path", ["/"])[0].strip()

    # 3. Cloudfront фильтр
    if require_cloudfront:
        has_cloudfront = "cloudfront.net" in hostname.lower() or "cloudfront.net" in host.lower()
        if not has_cloudfront:
            return None

    # 4. Извлечение UUID
    uuid_str = parsed.username
    if not uuid_str and "@" in parsed.netloc:
        uuid_str = parsed.netloc.split("@")[0]
    if not uuid_str:
        return None

    port = parsed.port or 80
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-WS-Node"

    # 5. Сборка outbound
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": uuid_str,
        "transport": {"type": "ws", "path": path},
    }

    if host:
        outbound["transport"]["headers"] = {"Host": host}

    # 6. Динамическая настройка шифрования
    security = params.get("security", ["none"])[0].lower()
    if security in ["tls", "reality"]:
        outbound["tls"] = {
            "enabled": True,
            "server_name": host if host else hostname,
            "insecure": False,
        }
        if security == "reality":
            pbk = params.get("pbk", [""])[0].strip()
            sid = params.get("sid", [""])[0].strip()
            if pbk:
                outbound["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": pbk,
                    "short_id": sid,
                }

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация VLESS WS ноды под спецификацию sing-box."""
    if not outbound:
        return None
    if outbound.get("type") == "vless":
        transport = outbound.get("transport", {})
        if transport.get("type") != "ws":
            return None
    return outbound
