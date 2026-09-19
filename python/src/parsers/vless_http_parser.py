"""Парсинг и фильтрация ссылок VLESS with HTTP transport."""

import json
import urllib.parse

from src.common import is_valid_host


def parse_proxy_link(link: str) -> dict | None:
    """Парсит VLESS HTTP ссылку."""
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

    # Проверка: headerType = http
    header_type = params.get("headerType", [""])[0].lower()
    if header_type != "http":
        return None

    # Проверка: security = none
    security = params.get("security", ["none"])[0].lower()
    if security not in ["", "none"]:
        return None

    # Проверка: encryption = none
    encryption = params.get("encryption", ["none"])[0].lower()
    if encryption != "none":
        return None

    # Извлечение UUID
    uuid_str = parsed.username
    if not uuid_str and "@" in parsed.netloc:
        uuid_str = parsed.netloc.split("@")[0]
    if not uuid_str:
        return None

    # Извлечение host (поддержка comma-separated list)
    raw_hosts = params.get("host", [""])[0].strip()
    http_hosts = [h.strip() for h in raw_hosts.split(",") if h.strip()] if raw_hosts else []

    # Извлечение path (по умолчанию "/")
    path = params.get("path", ["/"])[0].strip()

    # Извлечение method
    method = params.get("method", [""])[0].strip()

    # Извлечение custom headers (JSON array)
    raw_headers = params.get("header", [""])[0].strip()
    custom_headers = []
    if raw_headers:
        try:
            parsed_headers = json.loads(raw_headers)
            if isinstance(parsed_headers, list):
                custom_headers = parsed_headers
        except (json.JSONDecodeError, ValueError):
            return None

    port = parsed.port or 80
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-HTTP-Node"

    transport: dict = {
        "type": "http",
    }

    if http_hosts:
        transport["host"] = http_hosts

    if path:
        transport["path"] = path

    if method:
        transport["method"] = method

    if custom_headers:
        transport["headers"] = custom_headers

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": uuid_str,
        "transport": transport,
    }
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация VLESS HTTP ноды под спецификацию sing-box."""
    if not outbound:
        return None
    if outbound.get("type") == "vless":
        transport = outbound.get("transport", {})
        if transport.get("type") == "http":
            hosts = transport.get("host")
            if not hosts or not isinstance(hosts, list) or len(hosts) == 0:
                return None
            if not is_valid_host(str(hosts[0]).strip()):
                return None
        outbound.pop("tls", None)
    return outbound
