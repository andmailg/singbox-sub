"""RKN BlockList + GeoIP фильтрация для VLESS WS/HTTP нод (Оптимизированная версия)."""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
import os
from collections import OrderedDict

from src.common import is_valid_ip, resolve_domain, session
from .asn_prefixes import _EXTRA_BLOCKED_CIDR, ASN_LIST

try:
    import maxminddb
except ImportError:
    maxminddb = None

# Файл локального кэша для тяжелых списков ASN
_RKN_FILTER_DIR = os.path.dirname(os.path.abspath(__file__))
ASN_CACHE_FILE = os.path.join(_RKN_FILTER_DIR, "rkn_networks_cache.json")
_GEOIP_PATH = os.path.normpath(os.path.join(_RKN_FILTER_DIR, "..", "..", "GeoLite2-Country.mmdb"))

# Версия схемы кэша (увеличивать при изменении формата)
_CACHE_FORMAT_VERSION = 1

# Файл метки ASN_LIST для отслеживания изменений
_ASN_LABEL_FILE = os.path.join(_RKN_FILTER_DIR, ".asn_label")


def _asn_cache_key() -> str:
    """Хеш актуального ASN_LIST для валидации кэша."""
    raw = "|".join(sorted(ASN_LIST))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _flush_working_nodes_if_asn_changed() -> None:
    """Удаляет все *_working.json, если ASN_LIST изменился с прошлого запуска."""
    current_key = _asn_cache_key()

    # Читаем сохранённый ключ
    prev_key = None
    if os.path.exists(_ASN_LABEL_FILE):
        try:
            with open(_ASN_LABEL_FILE, "r", encoding="utf-8") as f:
                prev_key = f.read().strip()
        except Exception:
            pass

    # Если ключ изменился — удаляем все *_working.json и перегенерируем кэш
    if prev_key is not None and prev_key != current_key:
        print(f"  [ASN] ASN_LIST changed, flushing working nodes...")
        src_dir = os.path.dirname(_RKN_FILTER_DIR)
        for fname in os.listdir(src_dir):
            if fname.endswith("_working.json"):
                fpath = os.path.join(src_dir, fname)
                os.remove(fpath)
                print(f"  [ASN] Deleted: {fname}")

    # Сохраняем текущий ключ
    try:
        with open(_ASN_LABEL_FILE, "w", encoding="utf-8") as f:
            f.write(current_key)
    except Exception:
        pass


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
    current_key = _asn_cache_key()

    if os.path.exists(ASN_CACHE_FILE):
        try:
            with open(ASN_CACHE_FILE, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            # Проверяем метаданные кэша
            if isinstance(cache_data, dict) and cache_data.get("_v") == _CACHE_FORMAT_VERSION:
                if cache_data.get("_asn_key") == current_key:
                    cached_strings = cache_data.get("_cidrs", [])
                    print(f"  [Cache] Loaded {len(cached_strings)} extra networks from local {ASN_CACHE_FILE}")
                    return [ipaddress.ip_network(cidr, strict=False) for cidr in cached_strings]
                else:
                    print(f"  [Cache] ASN_LIST changed, rebuilding...")
            else:
                print(f"  [Cache] Legacy format, rebuilding...")

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

    # Сохраняем в кэш с метаданными
    try:
        cache_payload = {
            "_v": _CACHE_FORMAT_VERSION,
            "_asn_key": current_key,
            "_cidrs": [str(n) for n in collapsed],
        }
        with open(ASN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache_payload, f, indent=2)
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
    # Проверяем, изменился ли ASN_LIST — если да, удаляем *_working.json
    _flush_working_nodes_if_asn_changed()

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


def open_geoip_reader(mmdb_path: str = _GEOIP_PATH):
    if not maxminddb or not os.path.exists(mmdb_path):
        return None
    try:
        return maxminddb.open_database(mmdb_path)
    except Exception as e:
        print(f"Error opening GeoIP database: {e}")
        return None

def resolve_country(server: str) -> str | None:
    """Определяет ISO-код страны по домену или IP-адресу."""
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


def resolve_asn(server: str) -> str | None:
    """Определяет ASN (AS номер) по домену или IP-адресу."""
    asn_db_path = os.path.normpath(os.path.join(_RKN_FILTER_DIR, "..", "..", "GeoLite2-ASN.mmdb"))
    node_ip = server.strip("[]")

    if not is_valid_ip(node_ip):
        resolved = resolve_domain(node_ip)
        if resolved is None:
            return None
        node_ip = resolved

    if not maxminddb or not os.path.exists(asn_db_path):
        return None

    try:
        reader = maxminddb.open_database(asn_db_path)
        asn_data = reader.get(node_ip)
        reader.close()

        if isinstance(asn_data, tuple):
            asn_data = asn_data[0]
        if isinstance(asn_data, dict):
            asn_record = asn_data.get("autonomous_system_number")
            if isinstance(asn_record, int):
                return f"AS{asn_record}"
            if isinstance(asn_record, str):
                return asn_record
    except Exception:
        pass

    return None


def resolve_and_check(
    server: str,
    blocked_networks: RKNBlockList,
    reader=None,
) -> dict | None | str:
    """Проверяет сервер на блокировки и страну (исключает RU).

    Returns:
        dict с ip/country — если нода прошла,
        None — если не удалось определить IP,
        str ("rkn" / "ru") — причина отклонения.
    """
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
        return "rkn"

    country = None
    if reader:
        try:
            geo_data = reader.get(node_ip_str)
            if isinstance(geo_data, tuple):
                geo_data = geo_data[0]
            if geo_data and "country" in geo_data:
                country_obj = geo_data["country"]
                if isinstance(country_obj, dict):
                    country = country_obj.get("iso_code", "")
                    if country == "RU":
                        return "ru"
        except Exception:
            pass

    result: dict = {"ip": node_ip_str}
    if country:
        result["country"] = country

    return result

