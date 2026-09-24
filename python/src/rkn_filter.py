"""RKN BlockList + GeoIP фильтрация для VLESS WS/HTTP нод."""

import bisect
import ipaddress
import os
import socket
from functools import lru_cache

from src.common import is_valid_ip, session

try:
    import maxminddb
except ImportError:
    maxminddb = None

# Источники IP-блэклистов РКН — агрегируются вместе;
# каждый источник имеет свой формат (CIDR, comment-separated и т.д.).
RKN_LIST_SOURCES: list[tuple[str, str]] = [
    # Re-filter-lists (активно обновляется сообществом)
    (
        "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst",
        "rkn",
    ),
    # rkn-ip-lists (широкий охват, разные форматы)
    (
        "https://raw.githubusercontent.com/MayersScott/rkn-ip-lists/main/rkn-ip-lists.txt",
        "rkn",
    ),
    # d3blk (классический список, содержит комментарии в начале)
    (
        "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3blk",
        "d3",
    ),
    # RKN IP lists — aggregated from multiple community sources
    (
        "https://raw.githubusercontent.com/bannedip/rkn-dns/main/ips.txt",
        "rkn",
    ),
    (
        "https://raw.githubusercontent.com/AdguardTeam/IPFilter/rules.txt",
        "ads",
    ),
    (
        "https://raw.githubusercontent.com/fkremrousev/rkn-ip-list/main/rkn.txt",
        "rkn",
    ),
    (
        "https://raw.githubusercontent.com/WooyunGOS/Dorks/main/%E5%B7%A5%E4%BD%9C%E8%80%85/rkn_list",
        "rkn",
    ),
    (
        "https://anti-copyright.github.io/list/rkn/ru.txt",
        "rkn",
    ),
    (
        "https://raw.githubusercontent.com/AbcRsm/rkn_russia_list/master/russia.txt",
        "rkn",
    ),
    (
        "https://raw.githubusercontent.com/ipify/rkn/main/rkn.txt",
        "rkn",
    ),
]


class RKNBlockList:
    """Оптимизированная проверка подсетей РКН через бинарный поиск."""

    def __init__(self, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]):
        self.v4_networks = sorted(
            [n for n in networks if n.version == 4],
            key=lambda x: int(x.network_address),
        )
        self.v6_networks = sorted(
            [n for n in networks if n.version == 6],
            key=lambda x: int(x.network_address),
        )

        self.v4_ranges = [
            (int(n.network_address), int(n.broadcast_address))
            for n in self.v4_networks
        ]
        self.v6_ranges = [
            (int(n.network_address), int(n.broadcast_address))
            for n in self.v6_networks
        ]

    @lru_cache(maxsize=8192)
    def is_blocked(self, ip_str: str) -> bool:
        """Проверяет, находится ли IP в заблокированных подсетях."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_int = int(ip_obj)

            if ip_obj.version == 4:
                ranges = self.v4_ranges
            else:
                ranges = self.v6_ranges

            # Ищем позицию по end-адресам: первый диапазон, где end >= ip_int
            positions = bisect.bisect_right([r[1] for r in ranges], ip_int)

            if positions > 0:
                start, end = ranges[positions - 1]
                return start <= ip_int <= end

            return False
        except ValueError:
            return False


def _fetch_networks(session, url: str, source_type: str, timeout: int = 12) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Скачивает один источник и возвращает список IPvNetwork."""
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
    """Скачивает и объединяет RKN BlockList из нескольких источников."""
    all_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    sources_fetched = 0
    sources_total = len(RKN_LIST_SOURCES)

    for url, source_type in RKN_LIST_SOURCES:
        nets = _fetch_networks(session, url, source_type)
        if nets:
            sources_fetched += 1
            all_networks.extend(nets)
            print(f"  [{source_type}] Loaded {len(nets)} networks from {url}")

    if not all_networks:
        print("  [WARN] No RKN blocklist sources returned data.")
        return RKNBlockList([])

    v4_nets: list[ipaddress.IPv4Network] = [n for n in all_networks if n.version == 4]
    v6_nets: list[ipaddress.IPv6Network] = [n for n in all_networks if n.version == 6]

    collapsed_v4 = list(ipaddress.collapse_addresses(v4_nets)) if v4_nets else []
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_nets)) if v6_nets else []

    collapsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [*collapsed_v4, *collapsed_v6]
    print(f"Aggregated {sources_fetched}/{sources_total} sources, "
          f"{len(all_networks)} raw -> {len(collapsed)} collapsed networks.")
    return RKNBlockList(collapsed)


def download_geoip(session, mmdb_path: str = "GeoLite2-Country.mmdb") -> bool:
    """Скачивает GeoIP базу если её нет."""
    if os.path.exists(mmdb_path):
        return True
    print("Downloading local GeoIP database...")
    db_url = "https://git.io/GeoLite2-Country.mmdb"
    try:
        db_resp = session.get(db_url, timeout=30)
        if db_resp.status_code == 200:
            with open(mmdb_path, "wb") as db_file:
                db_file.write(db_resp.content)
            print("Local GeoIP database downloaded successfully.")
            return True
    except Exception as e:
        print(f"Error downloading GeoIP database: {e}")
    return False


def open_geoip_reader(mmdb_path: str = "GeoLite2-Country.mmdb"):
    """Открывает базу GeoIP для чтения. Возвращает reader или None."""
    if not maxminddb or not os.path.exists(mmdb_path):
        return None
    try:
        return maxminddb.open_database(mmdb_path)
    except Exception as e:
        print(f"Error opening GeoIP database: {e}")
        return None


@lru_cache(maxsize=4096)
def _resolve_dns(domain: str) -> str | None:
    """Кэшированный DNS-резолвинг."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def resolve_country(server: str) -> str | None:
    """Определяет страну по серверу (домен/IP) через GeoIP.
    Возвращает ISO 3166-1 alpha-2 код (например 'DE', 'PL') или None.
    
    GeoLite2-Country.mmdb должна быть доступна в корне репозитория
    (скачивается в CI/CD на этапе Install dependencies).
    """
    from src.common import is_valid_ip

    geoip_path = "GeoLite2-Country.mmdb"

    # 1. Резолвим домен в IP
    node_ip = server.strip("[]")
    if not is_valid_ip(node_ip):
        resolved = _resolve_dns(node_ip)
        if resolved is None:
            return None
        node_ip = resolved

    # 2. Ищем в GeoIP
    if not maxminddb or not os.path.exists(geoip_path):
        return None

    try:
        reader = maxminddb.open_database(geoip_path)
        geo_data = reader.get(node_ip)
        reader.close()
        if geo_data is None:
            return None
        # maxminddb returns a Record object; convert to dict for safe access
        if not isinstance(geo_data, dict):
            return None
        country_data = geo_data.get("country")
        if not isinstance(country_data, dict):
            return None
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
    """Атомарная проверка IP: DNS-резолвинг + RKN + GeoIP. Кэшируется.
    Возвращает {"ip": ..., "country": "US"} или None.
    """
    from src.common import is_valid_ip

    node_ip_str = server.strip("[]")
    if not is_valid_ip(node_ip_str):
        resolved = _resolve_dns(node_ip_str)
        if resolved is None:
            return None
        node_ip_str = resolved

    try:
        ip_obj = ipaddress.ip_address(node_ip_str)
    except ValueError:
        return None

    # 1. RKN check
    if blocked_networks.is_blocked(node_ip_str):
        return None

    # 2. GeoIP check
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
