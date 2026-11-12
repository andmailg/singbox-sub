"""Парсинг и фильтрация ссылок VMess + HTTPUpgrade.

Использует общий парсер VMess (src.parsers.vmess_parser), но оставляет только
транспорт httpupgrade и строит ключ дедупликации с учётом path
(ведущий слэш в path на ключ не влияет, при дубле побеждает версия со слэшем).
"""

from src.parsers import vmess_parser
from src.parsers.vmess_parser import normalize_path

TRANSPORT = "httpupgrade"


def _transport_type(outbound: dict) -> str | None:
    transport = outbound.get("transport")
    if not isinstance(transport, dict):
        return "tcp"  # у sing-box обычный TCP — это отсутствие поля transport
    t = transport.get("type")
    return "ws" if t == "websocket" else t


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылку vmess://, пропуская всё, что не HTTPUpgrade."""
    outbound = vmess_parser.parse_proxy_link(link)
    if not outbound or _transport_type(outbound) != TRANSPORT:
        return None

    transport = outbound["transport"]
    transport.setdefault("path", "/")
    # Ссылки, различающиеся только ведущим слэшем в path, считаются одной нодой;
    # версия со слэшем приоритетнее (_dedup_rank), оркестратор оставляет её независимо от порядка.
    outbound["_dedup_key"] = (
        f"{outbound['server']}:{outbound['server_port']}:"
        f"{outbound['uuid']}:{normalize_path(transport['path'])}"
    )
    outbound["_dedup_rank"] = 1 if str(transport["path"]).startswith("/") else 0

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Валидация VMess HTTPUpgrade ноды под спецификацию sing-box."""
    outbound = vmess_parser.clean_outbound(outbound)
    if not outbound or _transport_type(outbound) != TRANSPORT:
        return None
    return outbound
