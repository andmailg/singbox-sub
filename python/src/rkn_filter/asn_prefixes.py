"""Сбор полных CIDR-диапазонов ASN из RIPEstat API."""

import ipaddress
import time

import requests


ASN_LIST = [
    "AS26383", "AS31898", "AS20473", "AS36352"
]

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
    """Собирает и возвращает _EXTRA_BLOCKED_CIDR."""
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


# Генерируем при импорте (если API доступен)
try:
    _EXTRA_BLOCKED_CIDR: dict[str, list[str]] = fetch_all()
except Exception:
    # Fallback: пустой словарь, если API недоступен
    _EXTRA_BLOCKED_CIDR = {}
