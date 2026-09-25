"""Шаблон парсера для протокола X.

Для создания нового парсера:
1. Скопируй этот файл в src/parsers/{proto}_parser.py
2. Реализуй функции parse_proxy_link() и clean_outbound()
3. Добавь case в common.py:_build_fingerprint() для dedup

Примеры:
  - src/parsers/vless_tcp_reality_parser.py — VLESS with Reality (TLS + reality.public_key)
  - src/parsers/hy2_parser.py — Hysteria2 (QUIC + auth_password)
  - src/parsers/vless_ws_parser.py — VLESS with WS (TLS + websocket transport)
  - src/parsers/vless_grpc_parser.py — VLESS with gRPC (TLS + gun)
"""

import urllib.parse


def _param(params: dict, key: str) -> str | None:
    """Извлекает первое значение параметра query-строки (case-sensitive)."""
    vals = params.get(key)
    if vals and vals[0]:
        return vals[0].strip()
    return None


def parse_proxy_link(link: str, **kwargs) -> dict | None:
    """Парсит ссылку протокола X в формат sing-box outbound.

    Args:
        link: строка ссылки (например "vless://uuid@host:port?...")
        **kwargs: дополнительные аргументы из pipeline.

    Returns:
        Словарь в формате sing-box outbound или None если ссылка невалидна.

    Пример возвращаемого значения для VLESS Reality:
        {
            "type": "vless",
            "tag": "My-Node",
            "server": "example.com",
            "server_port": 443,
            "uuid": "xxx-xxx-xxx",
            "tls": {
                "enabled": True,
                "server_name": "cdn.example.com",
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": "xxxxx...",
                    "short_id": "abcd",
                    "spider_x": "/path",
                }
            },
            "flow": "xtls-rprx-vision",  # опционально
        }

    Пример возвращаемого значения для Hysteria2:
        {
            "type": "hysteria2",
            "tag": "Hy2-Node",
            "server": "example.com",
            "server_port": 443,
            "password": "xxx-xxx-xxx",
            "tls": {"enabled": True, "server_name": "cdn.example.com"},
        }

    Шаги реализации:
        1. Определи scheme (vless://, hysteria2://, trojan://, etc.)
        2. Разбери URL: host, port, username (auth), fragment (tag)
        3. Извлеки query-параметры (sni, pbk, sid, spiderX, flow, fp, ...).
           Используй _param(params, "key") для безопасного доступа.
        4. Проверь обязательные поля протокола.
        5. Сформируй словарь в формате sing-box outbound.
        6. Верни None если невалидно.

    Важно:
        - Для reality-протоколов: tls.reality.enabled=True, tls.server_name=SNI,
          tls.reality.public_key=pbk, tls.reality.short_id=sid.
        - Для regular TLS: tls.enabled=True, tls.server_name=SNI.
        - transport.type определяет тип транспорта: "tcp", "ws", "grpc", "http", "httpupgrade".
    """
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        parsed = urllib.parse.urlparse(link)
        hostname = parsed.hostname
        if not hostname:
            return None
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    # TODO: добавь проверку scheme (например: if scheme != "vless": return None)

    params = urllib.parse.parse_qs(parsed.query)

    # TODO: реализуй парсинг ссылки протокола X
    # 1. Извлеки port (parsed.port), auth (parsed.username), tag (parsed.fragment)
    # 2. Проверь обязательные поля
    # 3. Сформируй outbound в формате sing-box
    # 4. Верни None если невалидно

    raise NotImplementedError("Реализуй парсер протокола X")


def clean_outbound(outbound: dict) -> dict | None:
    """Очистка и приведение ноды к спецификации sing-box.

    Удаление несовместимых полей, нормализация значений.

    Args:
        outbound: распарсенная нода.

    Returns:
        Очищенная нода или None если ноду нужно пропустить.

    Примеры очистки:
        - Для reality: удалить пустой short_id, если не указан.
        - Для hy2: проверить, что transport не содержит полей ws/grpc.
        - Для всех: удалить поля, которые не поддерживаются sing-box.
    """
    if not outbound:
        return outbound

    # TODO: добавь специфичную для протокола очистку
    # Например: убрать reality если не используется, убрать лишние поля

    return outbound
