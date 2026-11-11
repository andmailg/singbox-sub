"""Парсинг и фильтрация ссылок VMess + WebSocket.

Использует общий парсер VMess (src.parsers.vmess_parser), но оставляет только
транспорт ws и строит ключ дедупликации с учётом path.
"""

from src.parsers import vmess_parser

TRANSPORT = "ws"


def _transport_type(outbound: dict) -> str | None:
    transport = outbound.get("transport")
    if not isinstance(transport, dict):
        return "tcp"  # у sing-box обычный TCP — это отсутствие поля transport
    t = transport.get("type")
    return "ws" if t == "websocket" else t


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку vmess://, пропуская всё, что не WebSocket."""
    outbound = vmess_parser.parse_proxy_link(link)
    if not outbound or _transport_type(outbound) != TRANSPORT:
        return None

    transport = outbound["transport"]
    transport.setdefault("path", "/")
    outbound["_dedup_key"] = (
        f"{outbound['server']}:{outbound['server_port']}:"
        f"{outbound['uuid']}:{transport['path']}"
    )

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация VMess WebSocket ноды под спецификацию sing-box."""
    outbound = vmess_parser.clean_outbound(outbound)
    if not outbound or _transport_type(outbound) != TRANSPORT:
        return None
    return outbound
