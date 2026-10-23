"""Парсинг и фильтрация ссылок Trojan + gRPC.

Использует общий парсер Trojan (src.parsers.trojan_parser), но оставляет только
транспорт grpc с TLS и строит ключ дедупликации с учётом service_name.
"""

from src.parsers import trojan_parser


def _is_valid(outbound: dict) -> bool:
    transport = outbound.get("transport")
    tls = outbound.get("tls")
    return (
        isinstance(transport, dict)
        and transport.get("type") == "grpc"
        and isinstance(tls, dict)
        and bool(tls.get("enabled"))
    )


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку trojan://, пропуская всё, что не gRPC + TLS."""
    outbound = trojan_parser.parse_proxy_link(link)
    if not outbound or not _is_valid(outbound):
        return None

    service_name = outbound["transport"].get("service_name", "")
    outbound["_dedup_key"] = (
        f"{outbound['server']}:{outbound['server_port']}:"
        f"{outbound['password']}:{service_name}"
    )
    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация Trojan gRPC ноды под спецификацию sing-box."""
    outbound = trojan_parser.clean_outbound(outbound)
    if not outbound or not _is_valid(outbound):
        return None
    return outbound
