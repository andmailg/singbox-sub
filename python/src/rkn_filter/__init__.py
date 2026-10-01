"""RKN Blocklist + GeoIP фильтрация для VLESS WS/HTTP нод."""

from .geoip_filter import check_geoip, open_geoip_reader, resolve_country

# Re-export from testers for backward compatibility
from ..testers.asn_resolver import resolve_asn
from .rkn_config import ASN_LIST, CIDR_LIST
from .rkn_filter import (
    ASN_CACHE_FILE,
    RKNBlockList,
    _fetch_aws_networks,
    _load_or_build_extra_networks,
    check_rkn_blocked,
    load_rkn_list,
)

__all__ = [
    "ASN_LIST",
    "HARDCODED_CIDR",
    "ASN_CACHE_FILE",
    "RKNBlockList",
    "_fetch_aws_networks",
    "_load_or_build_extra_networks",
    "check_rkn_blocked",
    "check_geoip",
    "load_rkn_list",
    "open_geoip_reader",
    "resolve_asn",
    "resolve_country",
]