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
    flow = None
    tls_opts = {
        "enabled": True,
        "server_name": sni,
    }

    alpn = _param(params, "alpn")
    if alpn:
        tls_opts["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    insecure = _param(params, "allowInsecure") or _param(params, "insecure")
    if insecure and insecure.lower() in ("1", "true"):
        tls_opts["insecure"] = True

    if security == "reality":
        pbk = _param(params, "pbk")
        sid = _param(params, "sid")
        fp = _param(params, "fp")
        # spx/spiderX нужен для ссылок и Xray; из sing-box JSON вырезается при экспорте
        spider_x = _param(params, "spx") or _param(params, "spiderX")
        flow = _param(params, "flow")

        # Reality в sing-box требует public_key и utls-fingerprint;
        # значения по умолчанию не подставляем — ноду без них пропускаем.
        if not pbk or not fp:
            return None

        reality = {
            "enabled": True,
            "public_key": pbk,
        }
        if sid:
            reality["short_id"] = sid
        if spider_x:
            reality["spider_x"] = spider_x
        tls_opts["reality"] = reality
        tls_opts["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }
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

    transport = {
        "type": "grpc",
        "service_name": grpc_service_name,
    }

    # 7. packetEncoding
    packet_encoding = _param(params, "packetEncoding")
    # "none" = отключено; в sing-box допустимы только "", "packetaddr", "xudp"
    if packet_encoding and packet_encoding.lower() == "none":
        packet_encoding = None

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "tls": tls_opts,
        "transport": transport,
        "_dedup_key": f"{hostname}:{port}:{urllib.parse.unquote(uuid)}:{grpc_service_name}",
    }
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding
    # flow в sing-box — поле уровня outbound, а не tls
    if flow:
        outbound["flow"] = flow

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка ноды VLESS gRPC. Удаляет несовместимые поля."""
    if not outbound:
        return None

    if "_dedup_key" not in outbound:
        return None

    transport = outbound.get("transport", {})
    if isinstance(transport, dict):
        # Убираем None-значения
        outbound["transport"] = {k: v for k, v in transport.items() if v is not None}

    return outbound



