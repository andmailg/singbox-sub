"""Общие утилиты: сессия, валидаторы, DNS-проверки, константы."""

import base64
import functools
import ipaddress
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Инициализация сессии для повторного использования соединений
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
session.verify = False

# ============================================================
# Общие константы и утилиты
# ============================================================

# Внутренние поля, которые не должны попадать в экспорт
INTERNAL_FIELDS = frozenset({
    "_latency_ms", "_last_ok_ts", "_country", "_pending_since", "_sub_ids"
})


def clean_internal_fields(node: dict) -> None:
    """Удаляет внутренние поля из ноды (мутирует на месте)."""
    for key in INTERNAL_FIELDS:
        node.pop(key, None)


def resolve_server(server: str) -> str | None:
    """Резолвит домен в IP, если это не IP-адрес. Возвращает None при неудаче."""
    clean = server.strip("[]")
    if is_valid_ip(clean):
        return clean
    return resolve_domain(clean)


@functools.lru_cache(maxsize=4096)
def is_valid_ip(address: str) -> bool:
    """Проверяет, является ли строка валидным IPv4 или IPv6 адресом."""
    try:
        ipaddress.ip_address(address.strip("[]"))
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=4096)
def is_valid_domain(domain: str) -> bool:
    """Проверяет, является ли строка валидным доменным именем (не IP-адресом)."""
    if not domain or is_valid_ip(domain):
        return False
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))


@functools.lru_cache(maxsize=4096)
def resolve_domain(domain: str) -> str | None:
    """Кэшированный DNS-резолвинг домена в IPv4-адрес."""
    try:
        return socket.gethostbyname(domain.strip("[]"))
    except socket.gaierror:
        return None


@functools.lru_cache(maxsize=4096)
def is_valid_host(host_str: str) -> bool:
    """Проверяет, является ли raw-string валидным доменным именем.
    Предварительно очищает от [], портов (:), ведущих /.
    """
    if not host_str or not isinstance(host_str, str):
        return False
    clean_host = host_str.strip().strip("[]").split(":")[0].strip()
    if clean_host.startswith("/"):
        return False
    return is_valid_domain(clean_host)


# Зоны, узлы которых блокируются глобально
RU_ZONES = (".ru", ".su", ".рф")

# Домены фейковых нод, которые блокируются
FAKE_DOMAINS = ("whatsapp.com", "vk.com", "huawei", "bing.com", "google.com")

# Зарезервированные IP-диапазоны (RFC 1918 + др.), которые блокируются
RESERVED_IP_RANGES = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "127.0.0.0/8",
    "1.1.1.1/32",
    "fc00::/7",
)

# RU-домены для фильтрации тегов
RU_TAGS = ("ru", "russia")


@functools.lru_cache(maxsize=4096)
def is_ru_tag(node_tag: str) -> bool:
    """Проверяет, содержит ли тег RU/Russia зону."""
    return any(f"-{z}" in node_tag or f".{z}" in node_tag or f" {z}" in node_tag or node_tag.endswith(z) for z in RU_TAGS)


@functools.lru_cache(maxsize=4096)
def is_ru_server(server_val: str) -> bool:
    """Проверяет, содержит ли сервер RU-зону."""
    return server_val.endswith(RU_ZONES) or any(f"{z}:" in server_val for z in RU_ZONES)


@functools.lru_cache(maxsize=4096)
def is_fake_domain(value: str) -> bool:
    """Проверяет, содержит ли значение фейковый домен."""
    return any(d in value for d in FAKE_DOMAINS)


@functools.lru_cache(maxsize=4096)
def is_fake_ip(address: str) -> bool:
    """Проверяет, является ли адрес фейковым или зарезервированным IP."""
    addr = address.strip("[]")
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in (_cached_networks()))
    except ValueError:
        return False


@functools.lru_cache(maxsize=1)
def _cached_networks():
    """Кэшированные ip_network объекты для RESERVED_IP_RANGES."""
    return tuple(ipaddress.ip_network(n) for n in RESERVED_IP_RANGES)


def should_accept_outbound(
    outbound: dict,
    seen_fingerprints: set[str],
    *,
    protocol: str = "generic",
    tls_required: bool = False,
    port_whitelist: tuple[int, ...] | None = None,
    reality: bool = False,
) -> bool:
    """Универсальная быстрая фильтрация ноды после парсинга.

    Args:
        outbound: объект ноды в формате sing-box.
        seen_fingerprints: множество для дедупликации.
        protocol: тип протокола ("hy2", "vless", "vmess").
        tls_required: если True — проверяет наличие включённого TLS и server_name.
        port_whitelist: если указан — разрешены только эти порты.
        reality: если True — для reality-протоколов не фильтрует SNI по FAKE_DOMAINS.

    Returns:
        True если нода проходит все проверки.
    """
    if not outbound:
        return False

    # --- Базовые проверки (общие для всех протоколов) ---
    node_tag = str(outbound.get("tag", "")).lower()
    if is_ru_tag(node_tag):
        return False
    server_val = str(outbound.get("server", "")).lower()
    if not server_val or "@" in server_val:
        return False
    clean_server = server_val.strip().strip("[]").split(":")[0].strip()
    if not is_valid_ip(clean_server) and not is_valid_domain(clean_server):
        return False
    if is_ru_server(server_val):
        return False
    if is_fake_domain(server_val):
        return False
    if is_fake_ip(clean_server):
        return False

    # --- Фильтр по порту ---
    if port_whitelist is not None:
        if outbound.get("server_port") not in port_whitelist:
            return False

    # --- TLS-проверки ---
    if tls_required:
        tls_opts = outbound.get("tls")
        if not isinstance(tls_opts, dict) or not tls_opts.get("enabled"):
            return False
        server_name = tls_opts.get("server_name")
        if not server_name or not isinstance(server_name, str) or not server_name.strip():
            return False
        sni_val = server_name.lower()
        if not is_valid_domain(sni_val):
            return False
        if is_ru_server(sni_val):
            return False
        if not reality and is_fake_domain(sni_val):
            return False

    # --- Дедупликация ---
    fingerprint = _build_fingerprint(outbound, protocol)
    if not fingerprint or fingerprint in seen_fingerprints:
        return False
    seen_fingerprints.add(fingerprint)
    return True


def _build_fingerprint(outbound: dict, protocol: str) -> str | None:
    """Формирует ключ дедупликации в зависимости от протокола."""
    server = str(outbound.get("server", "")).lower()
    port = str(outbound.get("server_port", ""))

    match protocol:
        case "hy2":
            password = str(outbound.get("password", ""))
            return f"{server}:{port}:{password}"
        case "vless":
            uuid_val = str(outbound.get("uuid", ""))
            transport = outbound.get("transport", {}) or {}
            transport_type = transport.get("type", "")
            if transport_type == "grpc":
                # gRPC: уникальный сервер
                return server
            # VLESS WS/HTTP/TCP: server:port:uuid:path
            path = str(transport.get("path", "/")).lower()
            return f"{server}:{port}:{uuid_val}:{path}"
        case "vmess":
            uuid_val = str(outbound.get("uuid", ""))
            transport = outbound.get("transport", {}) or {}
            path = str(transport.get("path", "/")).lower()
            return f"{server}:{port}:{uuid_val}:{path}"
        case _:
            # Generic fallback: server:port
            return f"{server}:{port}"


def country_code_to_flag(cc: str) -> str:
    """Конвертирует ISO 3166-1 alpha-2 код страны в Unicode-флаг.
    Пример: 'US' -> '🇺🇸', 'DE' -> '🇩🇪'
    """
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(ord(c) - ord('A') + 0x1F1E6) for c in cc.upper())


# Схемы прокси-форматов для детекции в подписках
PROXY_SCHEMES = (
    "sing-box://", "vless://", "vmess://", "hysteria2://",
    "trojan://", "ss://", "ssr://",
)

# Строки, характерные для base64-encoded данных
B64_SIGNATURES = ("sgx://",)  # sing-box sub URL


def _detect_proxy_schemes(lines: list[str]) -> dict[str, int]:
    """Подсчитывает количество ссылок каждого прокси-формата.
    
    Returns:
        Словарь {scheme_name: count}
    """
    counts: dict[str, int] = {}
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue
        for scheme in PROXY_SCHEMES:
            if line_stripped.lower().startswith(scheme.lower()):
                # Извлекаем имя схемы без "://"
                name = scheme.replace("://", "")
                counts[name] = counts.get(name, 0) + 1
                break
        else:
            # Не распознанный формат
            counts["unknown"] = counts.get("unknown", 0) + 1
    return counts


def _detect_sub_format(raw_content: str) -> str:
    """Определяет формат подписки по его содержимому.
    
    Returns:
        "base64" | "plaintext" | "empty"
    """
    content = raw_content.strip()
    if not content:
        return "empty"
    
    # Однострочная — однозначно base64 (подписка-ссылка вида sing-box://...)
    is_single_line = "\n" not in content and "\r" not in content
    if is_single_line:
        return "base64"
    
    # Много строк — проверяем, содержат ли они прокси-схемы
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for scheme in PROXY_SCHEMES:
            if stripped.lower().startswith(scheme.lower()):
                return "plaintext"
    
    # Нет прокси-схем, но есть переносы — вероятно base64 с разбивкой
    return "base64"


def fetch_subscription(url: str) -> dict:
    """Скачивает и декодирует отдельную подписку.
    
    Returns:
        Словарь с информацией о подписке:
        - url: URL подписки
        - valid: True если подписка доступна
        - format: формат подписки (base64/plaintext)
        - link_count: общее количество строк
        - proxy_formats: словарь {proxy_scheme: count}
        - error: сообщение об ошибке (если есть)
        - lines: список распарсенных строк (если валидна)
    """
    result = {
        "url": url,
        "valid": False,
        "format": None,
        "link_count": 0,
        "proxy_formats": {},
        "error": None,
        "lines": [],
    }
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result

        raw_content = resp.text.strip()
        fmt = _detect_sub_format(raw_content)
        result["format"] = fmt

        if fmt == "plaintext":
            # Прямые строки, без base64
            lines = raw_content.splitlines()
        else:
            # base64 — пытаемся декодировать
            try:
                content_padded = raw_content + "=" * (-len(raw_content) % 4)
                decoded_content = base64.b64decode(content_padded).decode("utf-8", errors="ignore")
                lines = decoded_content.splitlines()
            except Exception:
                # base64 не удался, fallback на plaintext
                lines = raw_content.splitlines()

        result["valid"] = True
        result["link_count"] = len(lines)
        result["proxy_formats"] = _detect_proxy_schemes(lines)
        result["lines"] = lines
        return result
    except Exception as e:
        result["error"] = str(e)
        return result



