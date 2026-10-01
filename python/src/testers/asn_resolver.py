"""Определение ASN (AS номер) по IP/домену."""

from __future__ import annotations

import os

try:
    import maxminddb
except ImportError:
    maxminddb = None

from src.common import is_valid_ip, resolve_domain

_RKN_FILTER_DIR = os.path.dirname(os.path.abspath(__file__))
_ASN_DB_PATH = os.path.normpath(os.path.join(_RKN_FILTER_DIR, "..", "rkn_filter", "GeoLite2-ASN.mmdb"))


def resolve_asn(server: str) -> str | None:
    """Определяет ASN (AS номер) по домену или IP-адресу.

    Args:
        server: IP или домен сервера.

    Returns:
        ASN в формате "AS12345" или None.
    """
    node_ip = server.strip("[]")

    if not is_valid_ip(node_ip):
        resolved = resolve_domain(node_ip)
        if resolved is None:
            return None
        node_ip = resolved

    if not maxminddb or not os.path.exists(_ASN_DB_PATH):
        return None

    try:
        reader = maxminddb.open_database(_ASN_DB_PATH)
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
