"""GeoIP: фильтрация по стране, определение страны по IP/домену."""

from __future__ import annotations

import ipaddress
import os

try:
    import maxminddb
except ImportError:
    maxminddb = None

from src.common import is_valid_ip, resolve_domain

_RKN_FILTER_DIR = os.path.dirname(os.path.abspath(__file__))
_GEOIP_PATH = os.path.normpath(os.path.join(_RKN_FILTER_DIR, "..", "..", "GeoLite2-Country.mmdb"))


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


def resolve_country(server: str) -> str | None:
    """Определяет ISO-код страны по домену или IP-адресу.

    Args:
        server: IP или домен сервера.

    Returns:
        ISO-код страны (например "RU", "US") или None.
    """
    geoip_path = _GEOIP_PATH
    node_ip = server.strip("[]")

    if not is_valid_ip(node_ip):
        resolved = resolve_domain(node_ip)
        if resolved is None:
            return None
        node_ip = resolved

    if not maxminddb or not os.path.exists(geoip_path):
        return None

    try:
        reader = maxminddb.open_database(geoip_path)
        geo_data = reader.get(node_ip)
        reader.close()

        if isinstance(geo_data, tuple):
            geo_data = geo_data[0]
        if isinstance(geo_data, dict):
            country_data = geo_data.get("country")
            if isinstance(country_data, dict) and country_data:
                iso_code = country_data.get("iso_code")
                if isinstance(iso_code, str) and iso_code:
                    return iso_code
    except Exception:
        pass

    return None


def check_geoip(
    server: str,
    reader,
    geoip_filter_countries: tuple[str, ...] | None = None,
) -> dict | None | str:
    """Проверяет сервер по GeoIP базе.

    Args:
        server: IP или домен сервера.
        reader: GeoIP reader (MaxMind).
        geoip_filter_countries: кортеж ISO-кодов стран для фильтрации (например ("ru", "ir")).
            Если None или пустой — фильтрация по странам отключена.

    Returns:
        dict с ip/country — если база доступна и страна определена,
        None — если не удалось определить IP или база недоступна,
        str (ISO-код страны) — если страна попала в фильтр блокировки.
    """
    node_ip = server.strip("[]")

    if not is_valid_ip(node_ip):
        resolved = resolve_domain(node_ip)
        if resolved is None:
            return None
        node_ip = resolved

    try:
        ipaddress.ip_address(node_ip)
    except ValueError:
        return None

    if not reader:
        return None

    try:
        geo_data = reader.get(node_ip)
        if isinstance(geo_data, tuple):
            geo_data = geo_data[0]
        if geo_data and "country" in geo_data:
            country_obj = geo_data["country"]
            if isinstance(country_obj, dict):
                country = country_obj.get("iso_code", "")
                if country:
                    # Проверяем, нужно ли блокировать эту страну
                    if geoip_filter_countries and country.upper() in [c.upper() for c in geoip_filter_countries]:
                        return country.lower()
                    return {"ip": node_ip, "country": country}
    except Exception:
        pass

    return None
