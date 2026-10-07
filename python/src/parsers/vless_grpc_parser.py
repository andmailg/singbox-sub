"""Парсинг и фильтрация ссылок VLESS with gRPC (TLS + Reality)."""

import urllib.parse


def _param(params: dict, key: str) -> str | None:
    """Извлекает первое значение параметра query-строки."""
    vals = params.get(key)
    if vals and vals[0]:
        return vals[0].strip()
    return None


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата VLESS with gRPC (TLS / Reality)."""
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

    # 1. Порт
    try:
        port = parsed.port
    except ValueError:
        port_part = parsed.netloc.rsplit(":", 1)[-1].split("?")[0].split("#")[0]
        first_port = port_part.split("-")[0]
        port = int(first_port) if first_port.isdigit() else None

    if not port:
        return None

    # 2. UUID
    uuid = parsed.username
    if not uuid and "@" in parsed.netloc:
        user_part = parsed.netloc.split("@")[0]
        uuid = user_part.split(":", 1)[-1] if ":" in user_part else user_part
    if not uuid:
        return None

    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-Node"

    # 3. SNI
    sni = _param(params, "sni")
    if not sni:
        return None

    # 4. Transport — только gRPC
    network = _param(params, "type") or _param(params, "network")
    if not network or network.lower() != "grpc":
        return None

    # 5. TLS / Reality
    security = _param(params, "security") or "tls"
    tls_opts = {
        "enabled": True,
        "server_name": sni,
    }

    if security == "reality":
        pbk = _param(params, "pbk")
        sid = _param(params, "sid")
        fp = _param(params, "fp")
        spider_x = _param(params, "spiderX") or _param(params, "spiderx")
        flow = _param(params, "flow")

        if pbk:
            reality = {
                "enabled": True,
                "public_key": pbk,
            }
            if sid:
                reality["short_id"] = sid
            if spider_x:
                reality["spider_x"] = spider_x
            tls_opts["reality"] = reality

        utls_opts = {}
        if fp:
            utls_opts["enabled"] = True
            utls_opts["fingerprint"] = fp
        if utls_opts:
            tls_opts["utls"] = utls_opts

        if flow:
            tls_opts["flow"] = flow
    else:
        # Regular TLS
        fp = _param(params, "fp")
        if fp:
            tls_opts["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

    # 6. gRPC параметры
    grpc_service_name = _param(params, "serviceName") or ""
    mode = _param(params, "mode")  # gun / multi
    authority = _param(params, "authority")

    transport = {
        "type": "grpc",
        "service_name": grpc_service_name,
    }
    if mode:
        transport["initial_windows_size"] = 0 if mode == "gun" else None
    if authority:
        transport["authority"] = authority

    # 7. packetEncoding
    packet_encoding = _param(params, "packetEncoding")

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "tls": tls_opts,
        "transport": transport,
    }
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка ноды VLESS gRPC. Удаляет несовместимые поля."""
    if not outbound:
        return outbound

    transport = outbound.get("transport", {})
    if isinstance(transport, dict):
        # Убираем None-значения
        outbound["transport"] = {k: v for k, v in transport.items() if v is not None}

    return outbound



