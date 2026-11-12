"""Парсинг и фильтрация ссылок Trojan + TCP (raw).

Использует общий парсер Trojan (src.parsers.trojan_parser), но оставляет только
обычный TCP с TLS: без HTTP-маскировки (headerType=http) и без REALITY — параметры
pbk/sid в ноду не переносятся, поэтому такие ноды тест гарантированно бы провалил.
"""

from src.parsers import trojan_parser


def _is_raw(outbound: dict) -> bool:
    # у sing-box обычный TCP — это отсутствие поля transport
    return not isinstance(outbound.get("transport"), dict)


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку trojan://, пропуская всё, что не TCP (raw) + TLS."""
    params = trojan_parser.link_params(link)
    if params.get("security", "").lower() == "reality":
        return None
    if (params.get("headerType") or "none").lower() != "none":
        return None

    outbound = trojan_parser.parse_proxy_link(link)
    if not outbound or not _is_raw(outbound):
        return None
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация Trojan TCP ноды под спецификацию sing-box."""
    outbound = trojan_parser.clean_outbound(outbound)
    if not outbound or not _is_raw(outbound):
        return None
    return outbound
