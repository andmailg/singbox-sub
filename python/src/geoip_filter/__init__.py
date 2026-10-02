"""GeoIP: фильтрация по стране, определение страны по IP/домену."""

from .geoip_filter import check_geoip, open_geoip_reader, resolve_country

__all__ = [
    "check_geoip",
    "open_geoip_reader",
    "resolve_country",
]
