"""RKN BlockList + GeoIP фильтрация для VLESS WS/HTTP нод (Оптимизированная версия)."""

from __future__ import annotations

import bisect
import ipaddress
import json
import os
from collections import OrderedDict

from src.common import is_valid_ip, resolve_domain, session
from .extra_blocked_cidr import _EXTRA_BLOCKED_CIDR

try:
    import maxminddb
except ImportError:
    maxminddb = None

# Файл локального кэша для тяжелых списков ASN
ASN_CACHE_FILE = "rkn_networks_cache.json"


def _fetch_aws_networks(session, timeout: int = 15) -> list[str]:
    """Напрямую выкачивает легковесный официальный JSON диапазонов Amazon AWS (вместо перебора ASN)."""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    raw_prefixes = []
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            # Собираем IPv4
            for item in data.get("prefixes", []):
                cidr = item.get("ip_prefix")
                if cidr:
                    raw_prefixes.append(cidr)
            # Собираем IPv6
            for item in data.get("ipv6_prefixes", []):
                cidr = item.get("ipv6_prefix")
                if cidr:
                    raw_prefixes.append(cidr)
            print(f"  [AWS] Directly loaded {len(raw_prefixes)} networks from official AWS JSON")
    except Exception as e:
        print(f"  [WARN] Failed to fetch official AWS IP ranges: {e}")
    return raw_prefixes


def _load_or_build_extra_networks(session) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Загружает дополнительный список сетей (из кэша, хардкода + RIPEstat API или AWS JSON)."""
    if os.path.exists(ASN_CACHE_FILE):
        try:
            with open(ASN_CACHE_FILE, "r", encoding="utf-8") as f:
                cached_strings = json.load(f)
            print(f"  [Cache] Loaded {len(cached_strings)} extra networks from local {ASN_CACHE_FILE}")
            return [ipaddress.ip_network(cidr, strict=False) for cidr in cached_strings]
        except Exception as e:
            print(f"  [Cache WARN] Failed to read cache file, rebuilding: {e}")

    print("  [Cache] Cache file not found or corrupted. Rebuilding...")
    all_cidr_strings: list[str] = []

    # 1. Сети из extra_blocked_cidr.py
    for asn_cidrs in _EXTRA_BLOCKED_CIDR.values():
        all_cidr_strings.extend(asn_cidrs)

    # 2. Официальный список AWS
    all_cidr_strings.extend(_fetch_aws_networks(session))

    # Валидируем и дедуплицируем строки перед кэшированием
    valid_networks = []
    for cidr in all_cidr_strings:
        try:
            valid_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue

    # Схлопываем подсети для минимизации размера кэш-файла
    v4 = [n for n in valid_networks if n.version == 4]
    v6 = [n for n in valid_networks if n.version == 6]
    collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))

    # Сохраняем в кэш
    try:
        with open(ASN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump([str(n) for n in collapsed], f, indent=2)
        print(f"  [Cache] Successfully saved {len(collapsed)} optimized networks to {ASN_CACHE_FILE}")
    except Exception as e:
        print(f"  [Cache WARN] Failed to save cache file: {e}")

    return collapsed


class RKNBlockList:
    """Оптимизированная проверка подсетей РКН через бинарный поиск."""

    def __init__(self, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]):
        # Схлопываем перекрывающиеся подсети — без этого bisect ломается
        v4 = list(ipaddress.collapse_addresses([n for n in networks if n.version == 4]))
        v6 = list(ipaddress.collapse_addresses([n for n in networks if n.version == 6]))

        self.v4_networks = sorted(v4, key=lambda x: int(x.network_address))
        self.v6_networks = sorted(v6, key=lambda x: int(x.network_address))

        self.v4_ranges = [(int(n.network_address), int(n.broadcast_address)) for n in self.v4_networks]
        self.v6_ranges = [(int(n.network_address), int(n.broadcast_address)) for n in self.v6_networks]

        # Предучисляем массивы start для бинарного поиска
        self.v4_starts = [r[0] for r in self.v4_ranges]
        self.v6_starts = [r[0] for r in self.v6_ranges]

        # Простой LRU-кэш (lru_cache на методе экземпляра утекает)
        self._cache: OrderedDict[str, bool] = OrderedDict()
        self._cache_max = 8192

    def is_blocked(self, ip_str: str) -> bool:
        # LRU-кэш: проверяем и обновляем порядок
        if ip_str in self._cache:
            self._cache.move_to_end(ip_str)
            return self._cache[ip_str]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_int = int(ip_obj)
            if ip_obj.version == 4:
                ranges = self.v4_ranges
                starts = self.v4_starts
            else:
                ranges = self.v6_ranges
                starts = self.v6_starts

            # Бинарный поиск: ищем диапазон с наибольшим start <= ip_int
            pos = bisect.bisect_right(starts, ip_int)
            result = False
            if pos > 0:
                start, end = ranges[pos - 1]
                result = start <= ip_int <= end

            # Сохраняем в кэш
            self._cache[ip_str] = result
            if len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
            return result
        except ValueError:
            self._cache[ip_str] = False
            return False


def load_rkn_list(session) -> RKNBlockList:
    """Возвращает RKNBlockList на основе оптимизированного кэша хостинг-провайдеров."""
    all_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    # Интеграция оптимизированных тяжелых подсетей (12 провайдеров РКН + Macarne)
    extra_nets = _load_or_build_extra_networks(session)
    if extra_nets:
        all_networks.extend(extra_nets)

    if not all_networks:
        print("  [WARN] No RKN blocklist sources returned data.")
        return RKNBlockList([])

    v4_nets = [n for n in all_networks if n.version == 4]
    v6_nets = [n for n in all_networks if n.version == 6]

    collapsed_v4 = list(ipaddress.collapse_addresses(v4_nets)) if v4_nets else []
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_nets)) if v6_nets else []

    collapsed = [*collapsed_v4, *collapsed_v6]
    print(f"{len(all_networks)} raw -> {len(collapsed)} collapsed networks.")
    return RKNBlockList(collapsed)


def open_geoip_reader(mmdb_path: str = "GeoLite2-Country.mmdb"):
    if not maxminddb or not os.path.exists(mmdb_path):
        return None
    try:
        return maxminddb.open_database(mmdb_path)
    except Exception as e:
        print(f"Error opening GeoIP database: {e}")
        return None

def resolve_country(server: str) -> str | None:
    """Определяет ISO-код страны по домену или IP-адресу."""
    geoip_path = "GeoLite2-Country.mmdb"
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

        if isinstance(geo_data, dict):
            country_data = geo_data.get("country")
            if isinstance(country_data, dict) and country_data:
                iso_code = country_data.get("iso_code")
                if isinstance(iso_code, str) and iso_code:
                    return iso_code
    except Exception:
        pass

    return None


def resolve_and_check(
    server: str,
    blocked_networks: RKNBlockList,
    reader=None,
) -> dict | None:
    """Проверяет сервер на блокировки и страну (исключает RU)."""
    node_ip_str = server.strip("[]")

    if not is_valid_ip(node_ip_str):
        resolved = resolve_domain(node_ip_str)
        if resolved is None:
            return None
        node_ip_str = resolved

    try:
        ipaddress.ip_address(node_ip_str)
    except ValueError:
        return None

    if blocked_networks.is_blocked(node_ip_str):
        return None

    country = None
    if reader:
        try:
            geo_data = reader.get(node_ip_str)
            if geo_data and "country" in geo_data:
                country_obj = geo_data["country"]
                if isinstance(country_obj, dict):
                    country = country_obj.get("iso_code", "")
                    if country == "RU":
                        return None
        except Exception:
            pass

    result: dict = {"ip": node_ip_str}
    if country:
        result["country"] = country

    return result

