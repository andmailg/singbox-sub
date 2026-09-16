"""Парсинг и фильтрация ссылок Hysteria2."""

import urllib.parse



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
    host = netloc

    # Извлекаем alt_port (после дефиса, если есть)
    alt_port = None
    # alt_port идёт после port, отделяется дефисом (но не минусом в IPv6)
    # Безопасно: ищем "-<цифры>" в конце
    alt_match = host.rsplit("-", 1)
    if len(alt_match) == 2 and alt_match[1].isdigit():
        alt_port = int(alt_match[1])
        host = alt_match[0]

    # Убираем query/fragment если вдруг попали
    host = host.split("?")[0].split("#")[0]

    # Определяем порт
    port = None
    if host.startswith("["):
        # IPv6: [addr] или [addr]:port
        bracket_end = host.find("]")
        if bracket_end == -1:
            return None
        if bracket_end + 1 < len(host) and host[bracket_end + 1] == ":":
            port_str = host[bracket_end + 2:]
            if port_str.isdigit():
                port = int(port_str)
        # Если port не указан и alt_port есть — берём его
        if port is None and alt_port is not None:
            return alt_port
    else:
        # IPv4 / hostname
        last_colon = host.rfind(":")
        if last_colon != -1:
            port_str = host[last_colon + 1:]
            if port_str.isdigit():
                port = int(port_str)

    # Порт 0 означает "не указан" — fallback на alt_port
    if (port is None or port == 0) and alt_port is not None:
        return alt_port

    return port


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата Hysteria2/Hy2."""
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

    # Фильтр: Только Hysteria2
    if scheme not in ["hysteria2", "hy2"]:
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Фильтрация небезопасных узлов (case-insensitive ключи)
    # Поддержка: allowInsecure, allowinsecure, insecure
    _p_lower = {k.lower(): v for k, v in params.items()}
    insecure_val = (
        _p_lower.get("allowinsecure", _p_lower.get("insecure", ["0"]))[0]
    )
    if insecure_val == "1" or insecure_val.lower() == "true":
        return None

    # 2. Обработка порта (поддержка IPv6, диапазонов, alt_port)
    port = _parse_port_from_netloc(parsed.netloc)
    if not port:
        return None

    # 3. Извлечение пароля
    password = parsed.username
    if not password and "@" in parsed.netloc:
        user_part = parsed.netloc.split("@")[0]
        password = (
            user_part.split(":", 1)[-1] if ":" in user_part else user_part
        )
    if not password:
        return None

    # 4. Тег ноды (fragment)
    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Hy2-Node"
    )

    # 5. SNI (необязателен — fallback на hostname)
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None
    server_host = sni if sni else hostname

    # 6. Сборка TLS-опций
    tls_opts: dict = {
        "enabled": True,
        "server_name": server_host,
    }

    # ALPN
    alpn_raw = params.get("alpn", [None])[0]
    if alpn_raw:
        tls_opts["alpn"] = [h.strip() for h in alpn_raw.split(",") if h.strip()]

    # pinSHA256 (case-insensitive)
    pin_sha256 = _p_lower.get("pinsha256", [None])[0]
    if pin_sha256:
        tls_opts["certificate"] = {"pin_sha256": pin_sha256.strip()}

    # 7. Obfuscation (obfs)
    obfs_type = params.get("obfs", [None])[0]
    if obfs_type:
        obfs = {"type": obfs_type.strip()}
        obfs_password = params.get("obfs-password", [None])[0]
        if obfs_password:
            obfs["password"] = urllib.parse.unquote(obfs_password.strip())
        tls_opts["obfs"] = obfs

    # 8. Сборка outbound
    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server_host,
        "server_port": port,
        "password": urllib.parse.unquote(password),
        "tls": tls_opts,
    }

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение Hysteria2 ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "hysteria2":
        return outbound

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        # Очищаем неиспользуемый блок reality для hysteria2
        tls_opts.pop("reality", None)

    return outbound
