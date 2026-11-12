"""Парсинг и фильтрация ссылок Trojan + HTTPUpgrade.

Использует общий парсер Trojan (src.parsers.trojan_parser), но оставляет только
транспорт httpupgrade и строит ключ дедупликации с учётом path. Host хранится
строкой в transport.host (так его читают и sing-box, и тестер Xray).
"""

from src.parsers import trojan_parser

TRANSPORT = "httpupgrade"


def _is_httpupgrade(outbound: dict) -> bool:
    transport = outbound.get("transport")
    return isinstance(transport, dict) and transport.get("type") == TRANSPORT


def _normalize(outbound: dict) -> None:
    """headers.Host -> host (строка), path по умолчанию «/»."""
    transport = outbound["transport"]
    headers = transport.pop("headers", None) or {}
    host = headers.get("Host") or headers.get("host")
    if host and not transport.get("host"):
        transport["host"] = str(host)
    transport.setdefault("path", "/")


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку trojan://, пропуская всё, что не HTTPUpgrade."""
    if trojan_parser.link_params(link).get("security", "").lower() == "reality":
        return None  # REALITY с httpupgrade не работает

    outbound = trojan_parser.parse_proxy_link(link)
    if not outbound or not _is_httpupgrade(outbound):
        return None

    _normalize(outbound)
    outbound["_dedup_key"] = (
        f"{outbound['server']}:{outbound['server_port']}:"
        f"{outbound['password']}:{outbound['transport']['path']}"
    )
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация Trojan HTTPUpgrade ноды под спецификацию sing-box."""
    outbound = trojan_parser.clean_outbound(outbound)
    if not outbound or not _is_httpupgrade(outbound):
        return None
    _normalize(outbound)
    return outbound
