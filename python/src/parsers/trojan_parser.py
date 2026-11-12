"""Парсинг и фильтрация ссылок Trojan."""

import urllib.parse

from src.common import (
    is_valid_host,
    is_valid_domain
)

# Транспорты Trojan, которые умеет актуальный Xray и которые есть в share-ссылках
# (type=raw — новое имя tcp). HTTP/2 (http, h2) из Xray удалён, mKCP/hysteria в ссылках trojan:// не встречаются.
ALLOWED_TRANSPORTS = frozenset({"tcp", "ws", "grpc", "httpupgrade", "xhttp"})
# Транспорты, использующие path
TRANSPORTS_WITH_PATH = frozenset({"ws", "httpupgrade", "xhttp"})
# Транспорты, использующие Host header
TRANSPORTS_WITH_HOST_HEADER = frozenset({"ws", "httpupgrade"})
# Транспорты, требующие TLS-конфигурации (кроме TCP)
TLS_TRANSPORTS = frozenset({"ws", "grpc", "httpupgrade", "xhttp"})
# Режимы xhttp, которые принимает Xray
XHTTP_MODES = frozenset({"auto", "packet-up", "stream-up", "stream-one"})


def link_params(link: str) -> dict[str, str]:
    """Параметры query ссылки (первое значение каждого), для проверок до основного парсинга."""
    try:
        query = urllib.parse.urlparse(link.strip()).query
    except ValueError:
        return {}
    return {k: v[0] for k, v in urllib.parse.parse_qs(query).items() if v}


def has_workers_dev(outbound: dict) -> bool:
    """Проверяет, содержит ли нода 'workers.dev'."""
    target = "workers.dev"

    server = str(outbound.get("server", "")).lower()
    if target in server:
        return True

    tls = outbound.get("tls")
    if isinstance(tls, dict):
        server_name = str(tls.get("server_name", "")).lower()
        if target in server_name:
            return True

    transport = outbound.get("transport")
    if isinstance(transport, dict):
        # Проверяем headers -> host
        headers = transport.get("headers")
        if isinstance(headers, dict):
            for value in headers.values():
                if target in str(value).lower():
                    return True

        # Проверяем host (list или str)
        hosts = transport.get("host")
        if isinstance(hosts, list):
            if any(target in str(h).lower() for h in hosts):
                return True
        elif isinstance(hosts, str) and target in hosts.lower():
            return True

    return False


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата Trojan."""
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
        hostname = parsed.hostname
        if not hostname:
            return None
        if hostname.startswith("[") and hostname.endswith("]"):
            hostname = hostname[1:-1]
        port = parsed.port
        if not port:
            return None
    except (ValueError, Exception):
        return None

    if parsed.scheme.lower() != "trojan":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # Извлечение пароля: userinfo из URL (username/password)
    password = parsed.username
    if not password:
        return None

    params_get = params.get  # локальная ссылка для производительности
    security = params_get("security", [""])[0].lower()
    tls_enabled = security != "none"

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan-Node"

    host_raw = params_get("host", [""])[0].strip()
    sni_raw = params_get("sni", [""])[0].strip() or params_get("peer", [""])[0].strip()

    host = host_raw.split(":", 1)[0].strip() if host_raw else ""
    sni = sni_raw.split(":", 1)[0].strip() if sni_raw else ""

    outbound: dict[str, str | int | dict | None] = {
        "type": "trojan",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "password": password,
        "_dedup_key": f"{hostname}:{port}:{password}",
    }

    if tls_enabled:
        tls_config: dict[str, str | bool] = {"enabled": True}
        server_name = sni or host
        if server_name:
            if not is_valid_domain(server_name):
                return None
            tls_config["server_name"] = server_name
        outbound["tls"] = tls_config

    # Определяем тип транспорта (type или net)
    net_type = (
        params_get("type", [""])[0].lower()
        or params_get("net", [""])[0].lower()
    )
    if net_type == "raw":  # новое имя tcp в Xray
        net_type = "tcp"

    # Фильтр запрещённых типов транспорта (пустая строка = TCP по умолчанию)
    if net_type and net_type not in ALLOWED_TRANSPORTS:
        return None

    if net_type and net_type != "tcp":
        transport_config: dict[str, str | list[str] | dict[str, str]] = {"type": net_type}

        if net_type in TRANSPORTS_WITH_PATH:
            path = params_get("path", [""])[0]
            if path:
                transport_config["path"] = path

        if host:
            if net_type == "xhttp":
                transport_config["host"] = [host]
            elif net_type in TRANSPORTS_WITH_HOST_HEADER:
                transport_config["headers"] = {"Host": host}

        if net_type == "xhttp":
            mode = params_get("mode", [""])[0].strip().lower()
            if mode in XHTTP_MODES:
                transport_config["mode"] = mode

        service_name = (
            params_get("serviceName", [""])[0]
            or params_get("service_name", [""])[0]
        )
        if service_name and net_type == "grpc":
            transport_config["service_name"] = service_name

        outbound["transport"] = transport_config

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и валидация Trojan ноды под спецификацию sing-box."""
    if not outbound:
        return None

    if "_dedup_key" not in outbound:
        return None

    if has_workers_dev(outbound):
        return None

    tls_config = outbound.get("tls")
    if tls_config:
        if not tls_config.get("server_name"):
            return None

        transport = outbound.get("transport")
        if transport:
            net_type = transport.get("type")
            if not net_type or net_type not in TLS_TRANSPORTS:
                return None

            if net_type not in TRANSPORTS_WITH_PATH:
                transport.pop("path", None)

            if net_type in TRANSPORTS_WITH_HOST_HEADER:
                raw_host = transport.pop("host", None)
                if raw_host and "headers" not in transport:
                    h_val = raw_host[0] if isinstance(raw_host, list) else raw_host
                    if is_valid_host(str(h_val)):
                        transport["headers"] = {"Host": str(h_val)}

                headers = transport.get("headers", {})
                ws_host = headers.get("Host") or headers.get("host")
                if ws_host and not is_valid_host(str(ws_host).strip()):
                    return None

            elif net_type == "xhttp":
                hosts = transport.get("host")
                if hosts:
                    first_host = hosts[0] if isinstance(hosts, list) else hosts
                    if not is_valid_host(str(first_host).strip()):
                        return None

    return outbound
