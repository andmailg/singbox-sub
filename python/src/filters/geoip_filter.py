"""GeoIP: определение страны по IP/домену и фильтрация по стране."""

from __future__ import annotations

import ipaddress
import os

try:
    import maxminddb
except ImportError:
    maxminddb = None

from src.common import is_valid_ip, resolve_domain

_FILTERS_DIR = os.path.dirname(os.path.abspath(__file__))
_GEOIP_PATH = os.path.normpath(os.path.join(_FILTERS_DIR, "..", "..", "GeoLite2-Country.mmdb"))


def open_geoip_reader(mmdb_path: str = _GEOIP_PATH):
    """Открывает MaxMind GeoIP базу для чтения.

    Returns:
        Reader объект или None если база не найдена или maxminddb не установлен.
    """
    if not maxminddb or not os.path.exists(mmdb_path):
        return None
    try:
        return maxminddb.open_database(mmdb_path)
    except Exception as e:
        print(f"Error opening GeoIP database: {e}")
        return None


def _lookup_country_from_ip(reader, server: str) -> dict | None:
    """Выполняет GeoIP-поиск для IP-адреса (уже резолвнутый домен или IP).

    Returns:
        dict с ключами "ip" и "country" или None если не найдено.
    """
    node_ip = server.strip("[]")

    if not maxminddb or not os.path.exists(_GEOIP_PATH):
        return None

    try:
        geo_data = reader.get(node_ip)

        if isinstance(geo_data, tuple):
            geo_data = geo_data[0]
        if isinstance(geo_data, dict):
            country_data = geo_data.get("country")
            if isinstance(country_data, dict) and country_data:
                iso_code = country_data.get("iso_code")
                if isinstance(iso_code, str) and iso_code:
                    return {"ip": node_ip, "country": iso_code}
    except Exception:
        pass

    return None


def resolve_country(server: str, reader=None) -> str | None:
    """Определяет ISO-код страны по домену или IP-адресу.

    Args:
        server: IP или домен сервера.
        reader: опциональный GeoIP reader (если уже открыт). Если None — открывается новый.

    Returns:
        ISO-код страны (например "RU", "US") или None.
    """
    node_ip = server.strip("[]")

    if not is_valid_ip(node_ip):
        resolved = resolve_domain(node_ip)
        if resolved is None:
            return None
        node_ip = resolved

    local_reader = None
    if reader is None:
        reader = local_reader = open_geoip_reader()

    try:
        result = _lookup_country_from_ip(reader, node_ip)
        if result:
            return result["country"]
    finally:
        if local_reader:
            local_reader.close()

    return None


def lookup_geoip(
    server: str,
    reader,
    geoip_block_countries: tuple[str, ...] | None = None,
) -> dict | None | str:
    """Выполняет GeoIP-поиск с опциональной блокировкой по стране.

    Это единая функция, заменяющая resolve_country + check_geoip.

    Args:
        server: IP или домен сервера.
        reader: GeoIP reader (MaxMind).
        geoip_block_countries: кортеж ISO-кодов стран для блокировки (например ("ru", "ir")).
            Если None или пустой — блокировка по странам отключена.

    Returns:
        dict {"ip": ..., "country": ...} — если страна определена и не заблокирована,
        str (ISO-код страны в нижнем регистре) — если страна попала в список блокировки,
        None — если не удалось определить страну или база недоступна.
    """
    node_ip = server.strip("[]")

    if not is_valid_ip(node_ip):
        resolved = resolve_domain(node_ip)
        if resolved is not None:
            node_ip = resolved

    result = _lookup_country_from_ip(reader, node_ip)
    if not result:
        return None

    country = result["country"]
    ip = result["ip"]

    # Проверяем, нужно ли блокировать эту страну
    if geoip_block_countries and country.upper() in [c.upper() for c in geoip_block_countries]:
        return country.lower()

    return {"ip": ip, "country": country}
