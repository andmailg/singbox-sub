"""RKN BlockList — оптимизированная проверка подсетей (бинарный поиск)."""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
import os
from collections import OrderedDict
from pathlib import Path

from src.common import is_valid_ip, resolve_domain, session
from .asn_fetcher import EXTRA_BLOCKED_CIDR
from .rkn_config import ASN_LIST, HARDCODED_CIDR

# Файл локального кэша для тяжелых списков ASN
_RKN_FILTER_DIR = str(Path(__file__).resolve().parent)
ASN_CACHE_FILE = os.path.join(_RKN_FILTER_DIR, "rkn_networks_cache.json")

# Версия схемы кэша (увеличивать при изменении формата)
_CACHE_FORMAT_VERSION = 2


def _fetch_aws_networks(session, timeout: int = 15) -> tuple[list[str], str]:
    """Напрямую выкачивает легковесный официальный JSON диапазонов Amazon AWS (вместо перебора ASN).

    Returns:
        Кортеж (список CIDR-строк, SHA256 хеш всех CIDR для инвалидации кэша).
    """
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    raw_prefixes: list[str] = []
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
    # Хеш для инвалидации кэша при изменении AWS диапазонов
    aws_key = hashlib.sha256("|".join(sorted(raw_prefixes)).encode()).hexdigest()[:16]
    return raw_prefixes, aws_key


def _fetch_cloudflare_networks(session, timeout: int = 15) -> tuple[list[str], str]:
    """Выкачивает официальные диапазоны Cloudflare (IPv4 и IPv6) из текстовых файлов.

    Returns:
        Кортеж (список CIDR-строк, SHA256 хеш всех CIDR для инвалидации кэша).
    """
    raw_prefixes: list[str] = []
    urls = [
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ]
    for url in urls:
        try:
            resp = session.get(url, timeout=timeout)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    cidr = line.strip()
                    if cidr and "/" in cidr:
                        raw_prefixes.append(cidr)
        except Exception as e:
            print(f"  [WARN] Failed to fetch Cloudflare ranges from {url}: {e}")
    if raw_prefixes:
        print(f"  [CF] Loaded {len(raw_prefixes)} networks from official Cloudflare")
    # Хеш для инвалидации кэша при изменении Cloudflare диапазонов
    cf_key = hashlib.sha256("|".join(sorted(raw_prefixes)).encode()).hexdigest()[:16]
    return raw_prefixes, cf_key


def _load_or_build_extra_networks(session) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Загружает дополнительный список сетей (из кэша, хардкода + RIPEstat API или AWS JSON)."""
    current_asn_key = hashlib.sha256("|".join(sorted(ASN_LIST)).encode()).hexdigest()[:16]
    current_hardcoded_key = hashlib.sha256(
        "|".join(f"{asn}={','.join(sorted(cidrs))}" for asn, cidrs in sorted(HARDCODED_CIDR.items()))
        .encode()
    ).hexdigest()[:16]

    # Загружаем AWS для вычисления ключа
    aws_cidrs, current_aws_key = _fetch_aws_networks(session)
    # Загружаем Cloudflare для вычисления ключа
    cf_cidrs, current_cf_key = _fetch_cloudflare_networks(session)

    if os.path.exists(ASN_CACHE_FILE):
        try:
            with open(ASN_CACHE_FILE, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            # Проверяем метаданные кэша
            if isinstance(cache_data, dict) and cache_data.get("_v") == _CACHE_FORMAT_VERSION:
                cached_asn = cache_data.get("_asn_key")
                cached_hardcoded = cache_data.get("_hardcoded_key")
                cached_aws = cache_data.get("_aws_key")
                cached_cf = cache_data.get("_cf_key")
                if cached_asn == current_asn_key and cached_hardcoded == current_hardcoded_key and cached_aws == current_aws_key and cached_cf == current_cf_key:
                    cached_strings = cache_data.get("_cidrs", [])
                    print(f"  [Cache] Loaded {len(cached_strings)} extra networks from local {ASN_CACHE_FILE}")
                    return [ipaddress.ip_network(cidr, strict=False) for cidr in cached_strings]
                else:
                    reasons = []
                    if cached_asn != current_asn_key:
                        reasons.append("ASN_LIST")
                    if cached_hardcoded != current_hardcoded_key:
                        reasons.append("HARDCODED")
                    if cached_aws != current_aws_key:
                        reasons.append("AWS")
                    if cached_cf != current_cf_key:
                        reasons.append("CF")
                    print(f"  [Cache] {'+'.join(reasons) if reasons else 'keys'} changed, rebuilding...")
            else:
                print(f"  [Cache] Legacy format, rebuilding...")

        except Exception as e:
            print(f"  [Cache WARN] Failed to read cache file, rebuilding: {e}")

    print("  [Cache] Cache file not found or corrupted. Rebuilding...")
    all_cidr_strings: list[str] = []

    # 1. Сети из ASN_LIST (RIPEstat API)
    for asn_cidrs in EXTRA_BLOCKED_CIDR.values():
        all_cidr_strings.extend(asn_cidrs)

    # 2. Сети из HARDCODED_CIDR
    for asn_cidrs in HARDCODED_CIDR.values():
        all_cidr_strings.extend(asn_cidrs)

    # 3. Официальный список AWS
    all_cidr_strings.extend(aws_cidrs)

    # 4. Официальный список Cloudflare
    all_cidr_strings.extend(cf_cidrs)

    # Дедупликация и валидация
    seen: set[str] = set()
    unique_cidrs: list[str] = []
    for cidr in all_cidr_strings:
        s = cidr.strip()
        if s and s not in seen:
            seen.add(s)
            unique_cidrs.append(s)

    all_cidr_strings = unique_cidrs

    valid_networks = []
    for cidr in all_cidr_strings:
        try:
            valid_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            print(f"  [ERROR] Invalid CIDR in config: '{cidr}' — aborting workflow.")
            raise SystemExit(1)

    # Схлопываем подсети для минимизации размера кэш-файла
    v4 = [n for n in valid_networks if n.version == 4]
    v6 = [n for n in valid_networks if n.version == 6]
    collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))

    # Сохраняем в кэш с метаданными
    try:
        cache_payload = {
            "_v": _CACHE_FORMAT_VERSION,
            "_asn_key": current_asn_key,
            "_hardcoded_key": current_hardcoded_key,
            "_aws_key": current_aws_key,
            "_cf_key": current_cf_key,
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


# GeoIP functions moved to geoip_filter.py
from .geoip_filter import open_geoip_reader, resolve_country


def check_rkn_blocked(
    server: str,
    blocked_networks: RKNBlockList | None,
) -> bool | None:
    """Проверяет сервер на попадание в RKN blocklist.

    Args:
        server: IP или домен сервера.
        blocked_networks: RKNBlockList для проверки. Если None — проверка пропускается.

    Returns:
        True — сервер заблокирован РКН,
        False — сервер не заблокирован,
        None — не удалось определить IP (сервер пропускать).
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

    if blocked_networks is not None and blocked_networks.is_blocked(node_ip_str):
        return True

    return False

