"""Шаблон парсера для протокола X.

Для создания нового парсера:
1. Скопируй этот файл в src/parsers/{proto}_parser.py
2. Реализуй функции parse_proxy_link() и clean_outbound()
3. Добавь case в common.py:_build_fingerprint() для dedup
"""


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

    Пример возвращаемого значения:
        {
            "type": "vless",
            "tag": "",
            "server": "example.com",
            "server_port": 443,
            "uuid": "xxx-xxx-xxx",
            "tls": {
                "enabled": True,
                "server_name": "example.com",
            },
            "transport": {
                "type": "ws",
                "path": "/path",
            },
        }
    """
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    # TODO: реализуй парсинг ссылки протокола X
    # 1. Определи scheme (vless://, trojan://, etc.)
    # 2. Извлеки host, port, auth, query-params
    # 3. Проверь обязательные поля
    # 4. Сформируй словарь в формате sing-box outbound
    # 5. Верни None если невалидно

    raise NotImplementedError("Реализуй парсер протокола X")


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение ноды к спецификации sing-box.

    Удаление несовместимых полей, нормализация значений.

    Args:
        outbound: распарсенная нода.

    Returns:
        Очищенная нода или None если ноду нужно пропустить.
    """
    if not outbound:
        return outbound

    # TODO: добавь специфичную для протокола очистку
    # Например: убрать reality если не используется, убрать лишние поля

    return outbound
