"""Парсинг и фильтрация ссылок VMess + TCP (raw).

Использует общий парсер VMess (src.parsers.vmess_parser), но оставляет только
транспорт tcp (raw, без HTTP-маскировки).
"""

from src.parsers import vmess_parser

TRANSPORT = "tcp"


def _transport_type(outbound: dict) -> str | None:
    transport = outbound.get("transport")
    if not isinstance(transport, dict):
        return None
    t = transport.get("type")
    return "ws" if t == "websocket" else t


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку vmess://, пропуская всё, что не TCP (raw)."""
    outbound = vmess_parser.parse_proxy_link(link)
    if not outbound or _transport_type(outbound) != TRANSPORT:
        return None

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация VMess TCP (raw) ноды под спецификацию sing-box."""
    outbound = vmess_parser.clean_outbound(outbound)
    if not outbound or _transport_type(outbound) != TRANSPORT:
        return None
    return outbound
