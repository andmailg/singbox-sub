"""Парсинг и фильтрация ссылок Trojan + WebSocket.

Использует общий парсер Trojan (src.parsers.trojan_parser), но оставляет только
транспорт ws и строит ключ дедупликации с учётом path.
"""

from src.parsers import trojan_parser


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку trojan://, пропуская всё, что не WebSocket."""
    outbound = trojan_parser.parse_proxy_link(link)
    if not outbound:
        return None

    transport = outbound.get("transport")
    if not isinstance(transport, dict) or transport.get("type") != "ws":
        return None

    transport.setdefault("path", "/")
    outbound["_dedup_key"] = (
        f"{outbound['server']}:{outbound['server_port']}:"
        f"{outbound['password']}:{transport['path']}"
    )
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация Trojan WS ноды под спецификацию sing-box."""
    outbound = trojan_parser.clean_outbound(outbound)
    if not outbound:
        return None

    transport = outbound.get("transport")
    if not isinstance(transport, dict) or transport.get("type") != "ws":
        return None
    transport.setdefault("path", "/")
    return outbound
