"""Парсинг и фильтрация ссылок VMess."""

import base64
import functools
import json

from src.common import merge_sub_ids


@functools.lru_cache(maxsize=4096)
def _is_valid_uuid(s: str) -> bool:
    """Проверяет валидность UUID (32 hex chars with optional dashes)."""
    if not s or len(s) not in (32, 36):
        return False
    try:
        int(s.replace("-", ""), 16)
        return True
    except ValueError:
        return False


def _decode_vmess_json(link: str) -> dict | None:
    """Декодирует base64 JSON из vmess:// ссылки."""
    # Убираем префикс vmess://
    b64data = link.replace("vmess://", "", 1)
    try:
        # base64url -> base64
        b64data = b64data.replace("-", "+").replace("_", "/")
        # Добавляем padding
        b64data += "=" * (-len(b64data) % 4)
        decoded = base64.b64decode(b64data).decode("utf-8", errors="ignore")
        return json.loads(decoded)
    except Exception:
        return None


# Транспорты, актуальные в Xray и однозначно определяемые по vmess-ссылке:
#   tcp          — raw без HTTP-маскировки (net=tcp, type=none)
#   ws           — WebSocket (алиас net=websocket приводится к ws)
#   httpupgrade  — HTTPUpgrade
# Исключены: h2/http (транспорт удалён из Xray, а "http" неоднозначен: HTTP/2 или TCP с
# HTTP-маскировкой, причём у маскировки парсер теряет host/path), grpc (в Xray deprecated).
CURRENT_TRANSPORTS = ("tcp", "ws", "httpupgrade")

# Допустимые security у VMess. none/zero в Xray (>= 26.7.11) не отбрасываются, а заменяются на
# auto независимо от адреса, при этом сервер такого клиента принимает; приводим их к auto так же.
CURRENT_SECURITY = ("auto", "aes-128-gcm", "chacha20-poly1305")
LEGACY_SECURITY = ("none", "zero")


def parse_proxy_link(link: str) -> dict | None:
    """
    Парсит VMess ссылку формата vmess://base64json.
    
    Возвращает outbound в формате sing-box.
    """
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    # 1. Декодирование JSON
    vmess_data = _decode_vmess_json(link)
    if not vmess_data:
        return None

    # 2. Обязательные поля
    uuid = vmess_data.get("id") or vmess_data.get("id")
    if not uuid:
        return None
    if not _is_valid_uuid(uuid):
        return None

    server = vmess_data.get("add") or vmess_data.get("server")
    if not server:
        return None

    port = vmess_data.get("port") or vmess_data.get("tcp-port")
    if not port:
        return None
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None

    # 3. Tag (alias)
    tag = vmess_data.get("ps") or vmess_data.get("remarks") or "VMess-Node"
    tag = str(tag)

    # 4. AlterID и security
    aid = vmess_data.get("aid") or vmess_data.get("alterId")
    try:
        aid = int(aid) if aid is not None else 0
    except (ValueError, TypeError):
        aid = 0

    # Security
    security = vmess_data.get("scy") or vmess_data.get("security") or "auto"

    # 5. TLS
    tls_val = vmess_data.get("tls")
    tls_str = str(tls_val).lower() if tls_val else ""
    has_tls = tls_str == "tls"

    # 6. Network type
    net = (vmess_data.get("net") or vmess_data.get("type") or "tcp").lower()

    # 7. Transport config
    transport: dict = {"type": net}

    # Host (SNI для ws/h2, Host header для ws)
    host = vmess_data.get("host") or vmess_data.get("sni", "")

    # Path
    path = vmess_data.get("path") or ""

    # SNI
    sni = vmess_data.get("sni") or host

    # Fingerprint
    fp = (vmess_data.get("fp") or vmess_data.get("pbk") or "").lower()

    # ObfsParam (для v2ray-ng plugin)
    obfs_param = vmess_data.get("obfsParam") or ""

    # WebSocket
    ws_extra: dict = {}
    if net in ("ws", "websocket"):
        if path:
            transport["path"] = path
        # Check for early data support (H2 compatible)
        early_data = vmess_data.get("ed") or 0
        try:
            early_data = int(early_data)
        except (ValueError, TypeError):
            early_data = 0
        if early_data > 0:
            transport["max_early_data"] = early_data
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            transport["headers"] = {"Host": host}

    # HTTP/2
    if net in ("h2", "http", "httpupgrade"):
        if path:
            transport["path"] = path
        if host:
            transport["host"] = host
        transport["method"] = "GET"

    # TCP gRPC
    if net == "grpc":
        service_name = vmess_data.get("serviceName") or vmess_data.get("serviceId") or ""
        transport["service_name"] = service_name
        transport["idle_timeout"] = 30
        transport["ping_timeout"] = 30
        transport["permit_without_stream"] = False

    # TCP with header (fake http)
    if net == "tcp":
        tcp_header = (vmess_data.get("type") or "none").lower()
        if tcp_header and tcp_header != "none":
            transport["type"] = "http"
            # For fake HTTP, we may need to set up request
        else:
            transport["type"] = "tcp"

    # 8. Сборка TLS
    tls_opts: dict | None = None
    if has_tls:
        tls_opts = {
            "enabled": True,
            "server_name": sni or server,
            "insecure": False,
        }
        if fp and fp in ("chrome", "firefox", "safari", "ios", "android", "edge", "1password", "xtls"):
            tls_opts["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

    # 9. Сборка outbound
    outbound = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": security if security != "auto" else "auto",
        "transport": transport,
        "_dedup_key": f"{server}:{port}:{uuid}",
    }

    if tls_opts:
        outbound["tls"] = tls_opts

    return outbound


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и приведение VMess ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "vmess":
        return None

    if "_dedup_key" not in outbound:
        return None

    transport = outbound.get("transport", {})
    net_type = transport.get("type", "tcp")
    net_type = {"websocket": "ws"}.get(net_type, net_type)
    transport["type"] = net_type

    # Оставляем только актуальные транспорты, однозначно определяемые по ссылке
    if net_type not in CURRENT_TRANSPORTS:
        return None

    security = str(outbound.get("security") or "auto").lower()
    if security in LEGACY_SECURITY:
        security = "auto"
    if security not in CURRENT_SECURITY:
        return None
    outbound["security"] = security

    # У sing-box-транспорта httpupgrade нет поля method (его добавляет общая ветка выше)
    if net_type == "httpupgrade":
        transport.pop("method", None)

    # В sing-box обычный TCP — это отсутствие поля transport (type "tcp" там не существует)
    if net_type == "tcp":
        outbound.pop("transport", None)

    return outbound


def normalize_path(path) -> str:
    """Путь с ведущим слэшем: "x" -> "/x", "/x" и "//x" остаются как есть, пустой -> "/"."""
    path = str(path or "/")
    return path if path.startswith("/") else "/" + path


def drop_slashless_duplicates(nodes: list[dict]) -> list[dict]:
    """Среди нод, различающихся только ведущим слэшем в path, оставляет версию со слэшем.

    Подписки (_sub_ids) отброшенных копий переносятся в оставшуюся. Порядок групп сохраняется.
    """
    groups: dict[tuple, dict] = {}
    for node in nodes:
        transport = node.get("transport") or {}
        raw_path = str(transport.get("path") or "/")
        key = (
            node.get("server"), node.get("server_port"), node.get("uuid"),
            transport.get("type", "tcp"), normalize_path(raw_path),
        )
        kept = groups.get(key)
        if kept is None:
            groups[key] = node
            continue
        kept_has_slash = str((kept.get("transport") or {}).get("path") or "/").startswith("/")
        if not kept_has_slash and raw_path.startswith("/"):
            merge_sub_ids(node, kept)
            groups[key] = node
        else:
            merge_sub_ids(kept, node)
    return list(groups.values())


def strip_tcp_transport(outbounds: list[dict]) -> None:
    """Убирает transport {"type": "tcp"} у нод, сохранённых до исправления (sing-box его не знает)."""
    for outbound in outbounds:
        transport = outbound.get("transport")
        if isinstance(transport, dict) and transport.get("type") == "tcp":
            outbound.pop("transport", None)
