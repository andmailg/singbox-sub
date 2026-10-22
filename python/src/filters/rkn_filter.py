"""RKN BlockList — оптимизированная проверка подсетей (бинарный поиск)."""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
import os
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from src.common import is_valid_ip, resolve_domain, session
from .rkn_asn_fetcher import get_asn_cidr, get_failed_asns
from .rkn_config import ASN_LIST, CIDR_LIST

# Файл локального кэша для тяжелых списков ASN
_RKN_FILTER_DIR = str(Path(__file__).resolve().parent)
ASN_CACHE_FILE = os.path.join(_RKN_FILTER_DIR, "rkn_networks_cache.json")

# Версия схемы кэша (увеличивать при изменении формата)
_CACHE_FORMAT_VERSION = 2


def _fetch_aws_networks(session, timeout: int = 15) -> tuple[list[str] | None, str]:
    """Напрямую выкачивает официальный JSON диапазонов Amazon AWS.

    Returns:
        (список CIDR, SHA256-хеш для инвалидации кэша). При сбое — (None, ""):
        пустой результат нельзя отличать от «диапазонов нет», иначе он попадёт в кэш.
    """
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    raw_prefixes: list[str] = []
    try:
        resp = session.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("prefixes", []):
            cidr = item.get("ip_prefix")
            if cidr:
                raw_prefixes.append(cidr)
        for item in data.get("ipv6_prefixes", []):
            cidr = item.get("ipv6_prefix")
            if cidr:
                raw_prefixes.append(cidr)
    except Exception as e:
        print(f"  [WARN] Failed to fetch official AWS IP ranges: {e}")
        return None, ""
    if not raw_prefixes:
        print("  [WARN] Official AWS IP ranges response is empty")
        return None, ""
    print(f"  [AWS] Directly loaded {len(raw_prefixes)} networks from official AWS JSON")
    return raw_prefixes, hashlib.sha256("|".join(sorted(raw_prefixes)).encode()).hexdigest()[:16]


def _fetch_cloudflare_networks(session, timeout: int = 15) -> tuple[list[str] | None, str]:
    """Выкачивает официальные диапазоны Cloudflare (IPv4 и IPv6).

    Returns:
        (список CIDR, SHA256-хеш). Если любой из файлов не получен — (None, "").
    """
    raw_prefixes: list[str] = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            part = [l.strip() for l in resp.text.splitlines() if "/" in l]
            if not part:
                raise ValueError("empty response")
            raw_prefixes.extend(part)
        except Exception as e:
            print(f"  [WARN] Failed to fetch Cloudflare ranges from {url}: {e}")
            return None, ""
    print(f"  [CF] Loaded {len(raw_prefixes)} networks from official Cloudflare")
    return raw_prefixes, hashlib.sha256("|".join(sorted(raw_prefixes)).encode()).hexdigest()[:16]


def _read_cache() -> dict | None:
    """Читает кэш подсетей. None — файла нет, он повреждён или старого формата."""
    if not os.path.exists(ASN_CACHE_FILE):
        return None
    try:
        with open(ASN_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [Cache WARN] Failed to read cache file: {e}")
        return None
    if isinstance(data, dict) and data.get("_v") == _CACHE_FORMAT_VERSION:
        return data
    print("  [Cache] Legacy format")
    return None


def _to_networks(cidrs, strict_abort: bool = False) -> list:
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError:
            if strict_abort:
                print(f"  [ERROR] Invalid CIDR in config: '{cidr}' — aborting workflow.")
                raise SystemExit(1)
    return nets


def _collapse(networks: list) -> list:
    v4 = [n for n in networks if n.version == 4]
    v6 = [n for n in networks if n.version == 6]
    return list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))


def _load_or_build_extra_networks(session) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Загружает дополнительный список сетей (из кэша, хардкода + RIPEstat API, AWS и Cloudflare).

    Кэш пишется только если ВСЕ внешние источники ответили. При сбое источника
    пустые данные в кэш не попадают: берётся прежний кэш, пересборка повторится в следующий запуск.
    """
    current_asn_key = hashlib.sha256("|".join(sorted(ASN_LIST)).encode()).hexdigest()[:16]
    current_hardcoded_key = hashlib.sha256(
        "|".join(f"{asn}={','.join(sorted(cidrs))}" for asn, cidrs in sorted(CIDR_LIST.items()))
        .encode()
    ).hexdigest()[:16]

    aws_cidrs, current_aws_key = _fetch_aws_networks(session)
    cf_cidrs, current_cf_key = _fetch_cloudflare_networks(session)

    cache = _read_cache()
    cached_cidrs = cache.get("_cidrs", []) if cache else []
    static_ok = bool(cache) and cache.get("_asn_key") == current_asn_key \
        and cache.get("_hardcoded_key") == current_hardcoded_key

    if static_ok:
        if aws_cidrs is None or cf_cidrs is None:
            # Ключи AWS/CF вычислить нельзя — сверять нечего, используем кэш как есть
            print(f"  [Cache] AWS/Cloudflare unavailable, using {len(cached_cidrs)} cached networks as is")
            return _to_networks(cached_cidrs)
        if cache.get("_aws_key") == current_aws_key and cache.get("_cf_key") == current_cf_key:
            print(f"  [Cache] Loaded {len(cached_cidrs)} extra networks from local {ASN_CACHE_FILE}")
            return _to_networks(cached_cidrs)
        print("  [Cache] AWS/CF changed, rebuilding...")
    elif cache:
        print("  [Cache] ASN_LIST/HARDCODED changed, rebuilding...")
    else:
        print("  [Cache] Cache file not found or corrupted. Rebuilding...")

    all_cidr_strings: list[str] = []

    # 1. Сети из ASN_LIST (RIPEstat API)
    for asn_cidrs in get_asn_cidr().values():
        all_cidr_strings.extend(asn_cidrs)
    # 2. Сети из CIDR_LIST
    for asn_cidrs in CIDR_LIST.values():
        all_cidr_strings.extend(asn_cidrs)
    # 3. AWS и 4. Cloudflare
    all_cidr_strings.extend(aws_cidrs or [])
    all_cidr_strings.extend(cf_cidrs or [])

    valid_networks = _to_networks(dict.fromkeys(s.strip() for s in all_cidr_strings if s.strip()), strict_abort=True)

    missing = []
    failed_asns = get_failed_asns()
    if failed_asns:
        missing.append("RIPEstat " + ",".join(failed_asns))
    if aws_cidrs is None:
        missing.append("AWS")
    if cf_cidrs is None:
        missing.append("Cloudflare")

    if missing:
        # Данные неполные: в кэш не пишем (иначе пробел закрепится), недостающее добираем из прежнего кэша
        print(f"  [Cache WARN] Sources unavailable: {'; '.join(missing)}. Cache is NOT updated, "
              f"{len(cached_cidrs)} previously cached networks added")
        return _collapse(valid_networks + _to_networks(cached_cidrs))

    # Схлопываем подсети для минимизации размера кэш-файла
    collapsed = _collapse(valid_networks)

    try:
        cache_payload = {
            "_v": _CACHE_FORMAT_VERSION,
            "_built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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

