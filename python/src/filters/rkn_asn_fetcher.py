"""Сбор полных CIDR-диапазонов ASN из RIPEstat API."""

import ipaddress
import time

import requests

from .rkn_config import ASN_LIST

API_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"

HEADERS = {
    "User-Agent": "asn-prefix-exporter/1.0",
    "Accept": "application/json",
}

_full_blocked_cidr: dict[str, dict[str, list[str]]] = {}

session = requests.Session()
session.headers.update(HEADERS)


def sort_networks(prefixes: list[str]) -> list[str]:
    """Сортировка CIDR по адресу сети и длине префикса."""
    networks = []

    for prefix in prefixes:
        try:
            networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            continue

    networks.sort(key=lambda network: (int(network.network_address), network.prefixlen))

    return [str(network) for network in networks]


def fetch_all() -> dict[str, list[str]]:
    """Собирает ASN-префиксы из RIPEstat API."""
    print("=" * 60)
    print("STEP 0: Fetch ASN prefixes from RIPEstat API")
    print("=" * 60)
    for asn in ASN_LIST:
        try:
            response = session.get(
                API_URL,
                params={"resource": asn},
                timeout=30,
            )

            response.raise_for_status()
            payload = response.json()

            if payload.get("messages"):
                print(f"[{asn}] Сообщения API: {payload['messages']}")

            prefixes = payload.get("data", {}).get("prefixes", [])

            raw_prefixes = []
            for item in prefixes:
                if isinstance(item, dict):
                    prefix = item.get("prefix")
                else:
                    prefix = item

                if prefix:
                    raw_prefixes.append(prefix)

            if not raw_prefixes:
                # Пустой ответ для ASN хостера — считаем сбоем API, а не «нет префиксов»
                print(f"[{asn}] EMPTY response")
                continue

            ipv4_list = sort_networks([p for p in raw_prefixes if ":" not in p])
            ipv6_list = sort_networks([p for p in raw_prefixes if ":" in p])

            _full_blocked_cidr[asn] = {
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
            }

            print(
                f"[{asn}] OK — IPv4 {len(ipv4_list)}, IPv6 {len(ipv6_list)}"
            )

        except requests.exceptions.Timeout:
            print(f"[{asn}] TIMEOUT")
        except requests.exceptions.HTTPError as error:
            print(f"[{asn}] HTTP error: {error}")
        except requests.exceptions.RequestException as error:
            print(f"[{asn}] Error: {error}")
        except ValueError as error:
            print(f"[{asn}] JSON error: {error}")
        except Exception as error:
            print(f"[{asn}] Unexpected: {error}")

        time.sleep(0.5)

    # Преобразуем в flat-список для совместимости с текущим импортом
    extra_blocked: dict[str, list[str]] = {}
    for asn in ASN_LIST:
        networks = _full_blocked_cidr.get(asn, {"ipv4": [], "ipv6": []})
        extra_blocked[asn] = networks["ipv4"] + networks["ipv6"]

    return extra_blocked


_asn_cidr_cache: dict[str, list[str]] | None = None


def get_asn_cidr() -> dict[str, list[str]]:
    """Префиксы ASN из RIPEstat. Запрос выполняется при первом вызове, а не при импорте."""
    global _asn_cidr_cache
    if _asn_cidr_cache is None:
        try:
            _asn_cidr_cache = fetch_all()
        except Exception:
            # Fallback: пустой словарь, если API недоступен
            _asn_cidr_cache = {}
    return _asn_cidr_cache


def get_failed_asns() -> list[str]:
    """ASN из ASN_LIST, префиксы которых получить не удалось (после get_asn_cidr)."""
    get_asn_cidr()
    return [asn for asn in ASN_LIST if asn not in _full_blocked_cidr]