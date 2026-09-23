"""Парсинг и фильтрация ссылок VLESS with gRPC (без reality)."""

import urllib.parse




def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата VLESS with gRPC (без reality)."""
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

    # Фильтр: Только VLESS
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Обработка портов
    try:
        port = parsed.port
    except ValueError:
        port_part = parsed.netloc.rsplit(":", 1)[-1].split("?")[0].split("#")[0]
        first_port = port_part.split("-")[0]
        port = int(first_port) if first_port.isdigit() else None

    if not port or port != 8443:
        return None

    # 2. Извлечение UUID (пароля для VLESS)
    uuid = parsed.username

    if not uuid and "@" in parsed.netloc:
        user_part = parsed.netloc.split("@")[0]
        uuid = user_part.split(":", 1)[-1] if ":" in user_part else user_part

    if not uuid:
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-Node"
    )

    # 3. Обработка SNI (serverName)
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # SNI обязателен для TLS
    if not sni:
        return None

    # 4. Сборка TLS options (без reality)
    tls_opts = {
        "enabled": True,
        "server_name": sni,
    }

    # 5. Обработка транспорта (network) — только gRPC
    network = params.get("type", [None])[0] or params.get("network", [None])[0]
    if not network or network.lower() != "grpc":
        return None

    # 6. Сборка объекта outbound для sing-box
    packet_encoding = params.get("packetEncoding", [None])[0]
    if packet_encoding and packet_encoding.lower() not in ("xudp", "udp"):
        return None

    # gRPC параметры
    grpc_service_name = params.get("serviceName", [None])[0] or ""

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "tls": tls_opts,
        "transport": {
            "type": "grpc",
            "service_name": grpc_service_name,
        },
    }
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """VLESS gRPC не требует дополнительной очистки. Заглушка на случай валидации transport"""
    return outbound



