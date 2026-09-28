"""RKN BlockList + GeoIP фильтрация для VLESS WS/HTTP нод (Оптимизированная версия)."""

import bisect
import ipaddress
import json
import os

from src.common import is_valid_ip, resolve_domain, session

try:
    import maxminddb
except ImportError:
    maxminddb = None

# Файл локального кэша для тяжелых списков ASN
ASN_CACHE_FILE = "rkn_networks_cache.json"

RKN_LIST_SOURCES: list[tuple[str, str]] = [
    ("https://raw.githubusercontent.com/bilibilio/ipv-rkn-list/master/ipv4.txt", "rkn"),
    ("https://raw.githubusercontent.com/bilibilio/ipv-rkn-list/master/ipv6.txt", "rkn"),
]

# Полный список ASN по реестру приземления РКН + Macarne
EXTRA_BLOCKED_ASNS: list[tuple[str, str]] = [
    # 1. Hetzner
    ("AS24940", "Hetzner Core"), ("AS213230", "Hetzner Cloud 2"), 
    ("AS212317", "Hetzner Cloud 3"), ("AS215859", "Hetzner Cloud 4"),
    # 2. Network Solutions
    ("AS33387", "Network Solutions"),
    # 3. WPEngine
    ("AS394625", "WPEngine US"), ("AS395246", "WPEngine Global"),
    # 4. HostGator / Newfold Digital
    ("AS46606", "Unified Layer"),
    # 5. Ionos SE
    ("AS8560", "IONOS Core"), ("AS29066", "IONOS Cloud"),
    # 6. DreamHost
    ("AS26347", "DreamHost"),
    # 7. FastComet
    ("AS53850", "FastComet"),
    # 8. GoDaddy
    ("AS26496", "GoDaddy Core"), ("AS40244", "GoDaddy Cloud"),
    # 10. Bluehost
    ("AS13364", "Bluehost Legacy"),
    # 11. Kamatera
    ("AS41853", "Kamatera"),
    # 12. DigitalOcean
    ("AS14061", "DigitalOcean"),
    # --- Сеть Macarne ---
    ("AS64289", "Macarne US"), ("AS151779", "Macarne APNIC"), 
    ("AS213756", "Macarne RIPE 1"), ("AS215827", "Macarne RIPE 2")
]


def _fetch_asn_networks(session, asn: str, source_type: str, timeout: int = 15) -> list[str]:
    """Загружает CIDR-диапазоны ASN через RIPE Statistics API и возвращает списком строк."""
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?data[asn]={asn}"
    raw_prefixes = []
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            print(f"  [WARN] {source_type} ({asn}): HTTP {resp.status_code}")
            return []
        data = resp.json()
        prefixes = data.get("data", {}).get("prefixes", [])
        for prefix_entry in prefixes:
            cidr_str = prefix_entry.get("prefix", "")
            if cidr_str:
                raw_prefixes.append(cidr_str)
        print(f"  [{source_type}] Fetched {len(raw_prefixes)} networks for {asn}")
    except Exception as e:
        print(f"  [WARN] {source_type} ({asn}): {e}")
    return raw_prefixes


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
    """Загружает дополнительный список сетей (из локального кэш-файла или собирает заново через API)."""
    if os.path.exists(ASN_CACHE_FILE):
        try:
            with open(ASN_CACHE_FILE, "r", encoding="utf-8") as f:
                cached_strings = json.load(f)
            print(f"  [Cache] Loaded {len(cached_strings)} extra networks from local {ASN_CACHE_FILE}")
            return [ipaddress.ip_network(cidr, strict=False) for cidr in cached_strings]
        except Exception as e:
            print(f"  [Cache WARN] Failed to read cache file, rebuilding: {e}")

    print("  [Cache] Cache file not found or corrupted. Rebuilding from APIs (this may take a minute)...")
    all_cidr_strings = []

    # 1. Скачиваем официальный список AWS (Провайдер №8 в списке РКН)
    all_cidr_strings.extend(_fetch_aws_networks(session))

    # 2. Скачиваем все остальные ASN из списка
    for asn, provider in EXTRA_BLOCKED_ASNS:
        all_cidr_strings.extend(_fetch_asn_networks(session, asn, provider))

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
        self.v4_networks = sorted([n for n in networks if n.version == 4], key=lambda x: int(x.network_address))
        self.v6_networks = sorted([n for n in networks if n.version == 6], key=lambda x: int(x.network_address))

        self.v4_ranges = [(int(n.network_address), int(n.broadcast_address)) for n in self.v4_networks]
        self.v6_ranges = [(int(n.network_address), int(n.broadcast_address)) for n in self.v6_networks]

        # Простой LRU-кэш через OrderedDict (lru_cache на методе экземпляра утекает)
        from collections import OrderedDict
        self._cache: OrderedDict[str, bool] = OrderedDict()
        self._cache_max = 8192

    def is_blocked(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_int = int(ip_obj)
            ranges = self.v4_ranges if ip_obj.version == 4 else self.v6_ranges

            positions = bisect.bisect_right([r[1] for r in ranges], ip_int)
            if positions > 0:
                start, end = ranges[positions - 1]
                return start <= ip_int <= end
            return False
        except ValueError:
            return False


def _fetch_networks(session, url: str, source_type: str, timeout: int = 12) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            print(f"  [WARN] {source_type}: HTTP {resp.status_code} from {url}")
            return raw
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cidr_str = line.split()[0]
                net_obj = ipaddress.ip_network(cidr_str, strict=False)
                raw.append(net_obj)
            except (ValueError, IndexError):
                continue
    except Exception as e:
        print(f"  [WARN] {source_type}: {e}")
    return raw


def load_rkn_list(session) -> RKNBlockList:
    """Скачивает стандартные списки и подмешивает оптимизированный кэш хостинг-провайдеров."""
    all_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    sources_fetched = 0
    sources_total = len(RKN_LIST_SOURCES)

    # Загрузка динамических листов РКН
    for url, source_type in RKN_LIST_SOURCES:
        nets = _fetch_networks(session, url, source_type)
        if nets:
            sources_fetched += 1
            all_networks.extend(nets)
            print(f"  [{source_type}] Loaded {len(nets)} networks from {url}")

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
    print(f"Aggregated {sources_fetched}/{sources_total} sources, "
          f"{len(all_networks)} raw -> {len(collapsed)} collapsed networks.")
    return RKNBlockList(collapsed)


def download_geoip(session, mmdb_path: str = "GeoLite2-Country.mmdb") -> bool:
    if os.path.exists(mmdb_path):
        return True
    print("Downloading local GeoIP database...")
    # GeoLite2 требует лицензионного ключа MaxMind. Скачайте вручную:
    # https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    print("  [WARN] Auto-download disabled (GeoLite2 requires MaxMind license key).")
    return False


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
            if isinstance(country_data, dict):
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
                country = geo_data["country"].get("iso_code", "")
                if country == "RU":
                    return None
        except Exception:
            pass

    result: dict = {"ip": node_ip_str}
    if country:
        result["country"] = country

    return result

