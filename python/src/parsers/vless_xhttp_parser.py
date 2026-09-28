"""Парсинг и фильтрация ссылок VLESS с транспортом xhttp."""

import urllib.parse

from src.common import is_valid_host


def parse_proxy_link(link: str) -> dict | None:
    """Парсит VLESS ссылку с транспортом xhttp.

    Поддерживаемые варианты:
      - VLESS + xhttp + TLS          (security=tls)
      - VLESS + xhttp (plain)        (security=none)

    xhttp-транпорт имеет дополнительные параметры: mode, downloadBufferSize,
    uploadBufferSize, padding, maxDownloadSpeed, maxUploadSpeed и др.
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

    # Фильтр: Только VLESS
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Обработка портов
    try:
        port = parsed.port
    except ValueError:
        return None

    # 2. Извлечение UUID
    uuid = parsed.username
    if not uuid:
        return None

    UUID_PATTERN = __import__('re').compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )
    if not UUID_PATTERN.match(uuid):
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-Node"
    )

    # 3. Обработка транспорта (network) — ТОЛЬКО xhttp
    network = params.get("type", [None])[0] or params.get("network", [None])[0]
    if not network or network.lower() != "xhttp":
        return None

    # 4. Читаем security
    security = params.get("security", [None])[0]
    if not security:
        security = "none"
    security_lower = security.lower()

    # Читаем fp (fingerprint) из URL
    fp = params.get("fp", [None])[0]
    if not fp:
        return None

    VALID_FINGERPRINTS = (
        "chrome", "firefox", "safari", "ios", "android",
        "edge", "360", "qq", "random", "randomized"
    )
    if fp.lower() not in VALID_FINGERPRINTS:
        return None

    # 5. Обработка SNI (serverName)
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # 6. Сборка TLS options в зависимости от security
    tls_opts = None

    if security_lower == "tls":
        # VLESS + xhttp + TLS
        if not sni:
            return None
        tls_opts = {
            "enabled": True,
            "server_name": sni,
            "utls": {
                "enabled": True,
                "fingerprint": fp
            }
        }

    elif security_lower == "none":
        # VLESS + xhttp (plain, без шифрования) — tls не нужен
        tls_opts = None

    else:
        # Неизвестный security — отбрасываем
        return None

    # 7. Читаем flow (например, xtls-rprx-vision)
    flow = params.get("flow", [None])[0]

    # 8. Читаем xhttp-специфичные параметры
    # path (по умолчанию "/")
    path = params.get("path", ["/"])[0].strip()
    if not path:
        path = "/"

    # host (поддержка comma-separated list)
    raw_hosts = params.get("host", [""])[0].strip()
    http_hosts = [h.strip() for h in raw_hosts.split(",") if h.strip()] if raw_hosts else []

    # mode — режим xhttp ("auto", "packet-up", "stream-up")
    mode = params.get("mode", [None])[0]
    if not mode:
        mode = "auto"

    # downloadBufferSize
    download_buffer_size = params.get("downloadBufferSize", [None])[0]
    if download_buffer_size:
        try:
            download_buffer_size = int(download_buffer_size)
        except (ValueError, TypeError):
            download_buffer_size = 0

    # uploadBufferSize
    upload_buffer_size = params.get("uploadBufferSize", [None])[0]
    if upload_buffer_size:
        try:
            upload_buffer_size = int(upload_buffer_size)
        except (ValueError, TypeError):
            upload_buffer_size = 0

    # maxDownloadSpeed
    max_download_speed = params.get("maxDownloadSpeed", [None])[0]
    if max_download_speed:
        try:
            max_download_speed = int(max_download_speed)
        except (ValueError, TypeError):
            max_download_speed = None

    # maxUploadSpeed
    max_upload_speed = params.get("maxUploadSpeed", [None])[0]
    if max_upload_speed:
        try:
            max_upload_speed = int(max_upload_speed)
        except (ValueError, TypeError):
            max_upload_speed = None

    # padding
    padding_param = params.get("padding", [None])[0]
    if padding_param:
        padding = padding_param.lower() in ("true", "1", "yes")
    else:
        padding = None  # не указываем если не задано

    # encryption
    encryption = params.get("encryption", ["none"])[0].lower()

    # method
    method = params.get("method", [""])[0].strip()

    # 9. Сборка transport объекта
    transport: dict = {
        "type": "xhttp",
        "path": path,
        "mode": mode,
    }

    if http_hosts:
        transport["host"] = http_hosts

    if download_buffer_size:
        transport["downloadBufferSize"] = download_buffer_size

    if upload_buffer_size:
        transport["uploadBufferSize"] = upload_buffer_size

    if max_download_speed is not None:
        transport["maxDownloadSpeed"] = max_download_speed

    if max_upload_speed is not None:
        transport["maxUploadSpeed"] = max_upload_speed

    if padding is not None:
        transport["padding"] = padding

    if method:
        transport["method"] = method

    # 10. Сборка объекта outbound для sing-box
    outbound: dict = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "transport": transport,
    }

    if encryption and encryption != "none":
        outbound["encryption"] = encryption

    if tls_opts is not None:
        outbound["tls"] = tls_opts

    # flow — поле уровня vless, а не tls
    if flow:
        outbound["flow"] = flow

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и приведение VLESS xhttp ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "vless":
        return None

    transport = outbound.get("transport", {})
    if not isinstance(transport, dict) or transport.get("type") != "xhttp":
        return None

    # Валидация host
    hosts = transport.get("host")
    if hosts and isinstance(hosts, list) and len(hosts) > 0:
        if not is_valid_host(str(hosts[0]).strip()):
            return None

    return outbound
