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


def should_accept_outbound(
    outbound: dict,
    seen_fingerprints: set[str],
    *,
    protocol: str = "generic",
    tls_required: bool = False,
    port_whitelist: tuple[int, ...] | None = None,
) -> bool:
    """Универсальная быстрая фильтрация ноды после парсинга.

    Args:
        outbound: объект ноды в формате sing-box.
        seen_fingerprints: множество для дедупликации.
        protocol: тип протокола ("hy2", "vless", "vmess").
        tls_required: если True — проверяет наличие включённого TLS и server_name.
        port_whitelist: если указан — разрешены только эти порты.

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
        if is_fake_domain(sni_val):
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


def fetch_subscription(url: str) -> list[str]:
    """Скачивает и декодирует отдельную подписку."""
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code != 200:
            return []

        content = resp.text.strip()
        try:
            content_padded = content + "=" * (-len(content) % 4)
            decoded_content = base64.b64decode(content_padded).decode("utf-8", errors="ignore")
            return decoded_content.splitlines()
        except Exception:
            return content.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []


def load_sources(sources_json_url: str) -> list[str]:
    """Загружает список URL подписок из JSON."""
    print(f"Fetching subscription sources from {sources_json_url}...")
    try:
        sources_resp = session.get(sources_json_url, timeout=15)
        sources_resp.raise_for_status()

        try:
            sub_urls = sources_resp.json()
        except Exception:
            sub_urls = __import__('json').loads(sources_resp.text)

        if isinstance(sub_urls, dict):
            sub_urls = list(sub_urls.values())

        if not isinstance(sub_urls, list):
            raise ValueError(f"Expected list or dict, got {type(sub_urls)}")

        print(f"✅ Successfully loaded {len(sub_urls)} subscription sources.")
        return sub_urls

    except Exception as e:
        print(f"❌ Error fetching sources JSON: {e}")
        return []
