"""Парсинг и фильтрация ссылок Hysteria2."""

import urllib.parse


def _param(params: dict, key: str) -> str | None:
    """Извлекает первое значение параметра запроса (case-sensitive)."""
    vals = params.get(key)
    if vals and vals[0]:
        return vals[0].strip()
    return None


def _parse_port_from_netloc(netloc: str) -> int | None:
    """Извлекает порт из netloc, поддерживая IPv6, диапазоны портов и alt_port.

    Форматы:
      - host:port
      - [ipv6]:port
      - host:port-alt_port
      - [ipv6]:port-alt_port

    Возвращает None если порт невозможно определить.
    Порт 0 считается "не указан" (fallback на alt_port).
    """
    # Извлекаем alt_port (после дефиса, если есть)
    alt_port = None
    alt_match = netloc.rsplit("-", 1)
    if len(alt_match) == 2 and alt_match[1].isdigit():
        alt_port = int(alt_match[1])
        netloc = alt_match[0]

    # Убираем query/fragment если вдруг попали
    netloc = netloc.split("?")[0].split("#")[0]

    # Определяем порт
    port = None
    if netloc.startswith("["):
        # IPv6: [addr] или [addr]:port
        bracket_end = netloc.find("]")
        if bracket_end == -1:
            return None
        if bracket_end + 1 < len(netloc) and netloc[bracket_end + 1] == ":":
            port_str = netloc[bracket_end + 2:]
            if port_str.isdigit():
                port = int(port_str)
        # Если port не указан и alt_port есть — берём его
        if port is None and alt_port is not None:
            return alt_port
    else:
        # IPv4 / hostname
        last_colon = netloc.rfind(":")
        if last_colon != -1:
            port_str = netloc[last_colon + 1:]
            if port_str.isdigit():
                port = int(port_str)

    # Порт 0 означает "не указан" — fallback на alt_port
    if (port is None or port == 0) and alt_port is not None:
        return alt_port

    return port if port else None


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата Hysteria2/Hy2."""
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    # Фильтр: Только Hysteria2
    if scheme not in ("hysteria2", "hy2"):
        return None

    hostname = parsed.hostname
    if not hostname:
        return None

    port = parsed.port
    if not port:
        return None

    params = urllib.parse.parse_qs(parsed.query)
    params_lower = {k.lower(): v for k, v in params.items()}

    # 1. Фильтрация небезопасных узлов (case-insensitive ключи)
    insecure_val = (
        params_lower.get("allowinsecure", params_lower.get("insecure", ["0"]))[0]
    )
    if insecure_val == "1" or insecure_val.lower() == "true":
        return None

    # 2. Обработка порта (поддержка IPv6, диапазонов, alt_port)
    port = _parse_port_from_netloc(parsed.netloc)
    if not port:
        return None

    # 3. Извлечение пароля
    password = parsed.username
    if not password:
        return None

    # 4. Тег ноды (fragment)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"

    # 5. SNI (необязателен — fallback на hostname)
    sni = _param(params, "sni")

    # 6. Сборка TLS-опций (server_name = SNI или hostname)
    tls_opts: dict = {
        "enabled": True,
        "server_name": sni if sni else hostname,
    }

    # ALPN
    alpn_raw = _param(params, "alpn")
    if alpn_raw:
        tls_opts["alpn"] = [h.strip() for h in alpn_raw.split(",") if h.strip()]

    # pinSHA256 (case-insensitive)
    pin_sha256 = _param(params_lower, "pinsha256")
    if pin_sha256:
        tls_opts["certificate"] = {"pin_sha256": pin_sha256}

    # 7. Obfuscation (obfs)
    obfs: dict | None = None
    obfs_type = _param(params, "obfs") or _param(params_lower, "obfs")
    obfs_password = _param(params_lower, "obfs-password")
    if obfs_type:
        if not obfs_password:
            return None
        obfs = {"type": obfs_type, "password": urllib.parse.unquote(obfs_password)}
    else:
        obfs = None

    # 8. Сборка outbound
    # server = tls.server_name (SNI или hostname)
    result: dict = {
        "type": "hysteria2",
        "tag": tag,
        "server": tls_opts["server_name"],
        "server_port": port,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts,
    }
    if obfs:
        result["obfs"] = obfs
    return result


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    tls_opts = outbound.get("tls")
    if tls_opts and tls_opts.get("enabled"):
        tls_opts.pop("reality", None)

    return outbound
