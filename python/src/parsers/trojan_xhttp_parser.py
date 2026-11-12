"""Парсинг и фильтрация ссылок Trojan + xhttp.

Использует общий парсер Trojan (src.parsers.trojan_parser), но оставляет только
транспорт xhttp с TLS (REALITY не поддерживается: pbk/sid в ноду не переносятся)
и строит ключ дедупликации с учётом path. sing-box xhttp не поддерживает,
поэтому ноды экспортируются только ссылками для Xray.
"""

from src.parsers import trojan_parser

TRANSPORT = "xhttp"


def _is_valid(outbound: dict) -> bool:
    transport = outbound.get("transport")
    tls = outbound.get("tls")
    return (
        isinstance(transport, dict)
        and transport.get("type") == TRANSPORT
        and isinstance(tls, dict)
        and bool(tls.get("enabled"))
    )


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку trojan://, пропуская всё, что не xhttp + TLS."""
    if trojan_parser.link_params(link).get("security", "").lower() == "reality":
        return None

    outbound = trojan_parser.parse_proxy_link(link)
    if not outbound or not _is_valid(outbound):
        return None

    transport = outbound["transport"]
    transport.setdefault("path", "/")
    outbound["_dedup_key"] = (
        f"{outbound['server']}:{outbound['server_port']}:"
        f"{outbound['password']}:{transport['path']}"
    )
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация Trojan xhttp ноды."""
    outbound = trojan_parser.clean_outbound(outbound)
    if not outbound or not _is_valid(outbound):
        return None
    outbound["transport"].setdefault("path", "/")
    return outbound
