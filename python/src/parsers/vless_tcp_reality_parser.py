"""Парсинг и фильтрация ссылок VLESS with Reality."""

import base64
import functools
import re
import urllib.parse




@functools.lru_cache(maxsize=4096)
def _is_valid_reality_public_key(s: str) -> bool:
    """Проверяет валидность public_key для reality."""
    if not s:
        return False
    # Проверяем что это не служебное слово
    if s.lower() in ("enabled", "none", "null", "true", "false"):
        return False
    # X25519 public key в base64url всегда 43 символа (+ padding =)
    # 32 байта -> base64url = ceil(32/3)*4 = 44 символа, но обычно без padding = 43
    if len(s) not in (43, 44):
        return False
    # Конвертируем base64url в base64
    normalized = s.replace('-', '+').replace('_', '/')
    # Добавляем padding если нужно
    padded = normalized + '=' * (-len(normalized) % 4)
    # Строгая валидация base64
    try:
        decoded = base64.b64decode(padded, validate=True)
        return len(decoded) == 32  # X25519 public key = 32 байта
    except Exception:
        return False


UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


@functools.lru_cache(maxsize=4096)
def _is_valid_hex(s: str) -> bool:
    """Проверяет, является ли строка валидным hex."""
    if not s:
        return True  # short_id может быть пустым
    return bool(re.fullmatch(r'[0-9a-fA-F]+', s)) and len(s) <= 16


VALID_FINGERPRINTS = (
    "chrome", "firefox", "safari", "ios", "android",
    "edge", "360", "qq", "random", "randomized"
)


def parse_proxy_link(link: str) -> dict | None:
    """Парсит ссылки формата VLESS with Reality."""
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

    # Фильтр: Только VLESS
    if scheme != "vless":
        return None

    params = urllib.parse.parse_qs(parsed.query)

    # 1. Обработка портов
    try:
        port = parsed.port
    except ValueError:
        return None

    # 2. Извлечение UUID (пароля для VLESS)
    uuid = parsed.username

    if not uuid:
        return None

    # Валидация UUID (V2Ray стандарт: 8-4-4-4-12)
    if not UUID_PATTERN.match(uuid):
        return None

    tag = (
        urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS-Node"
    )

    # 3. Обработка SNI (serverName)
    sni_param = params.get("sni", [None])[0]
    sni = sni_param.strip() if sni_param else None

    # SNI обязателен для TLS
    if not sni:
        return None

    # 4. Сборка TLS options для reality
    pbk = params.get("pbk", [None])[0]
    sid = params.get("sid", [None])[0] or ""
    spider_x = params.get("spiderX", [None])[0] or ""
    flow = params.get("flow", [None])[0] or ""

    # Универсальная валидация полей reality
    if not pbk or not _is_valid_reality_public_key(pbk):
        return None
    if not _is_valid_hex(sid):
        return None

    # Читаем fp (fingerprint) из URL
    fp = params.get("fp", [None])[0]
    if not fp:
        return None

    # Валидация fingerprint
    if fp.lower() not in VALID_FINGERPRINTS:
        return None

    # Проверяем что security = reality
    security = params.get("security", [None])[0]
    if security and security.lower() != "reality":
        return None

    tls_opts = {
        "enabled": True,
        "server_name": sni,
        "utls": {
            "enabled": True,
            "fingerprint": fp
        },
        "reality": {
            "enabled": True,
            "public_key": pbk,
            "short_id": sid,
        }
    }

    # spider_x обязателен для sing-box reality
    if spider_x:
        tls_opts["reality"]["spider_x"] = spider_x

    # 5. Обработка транспорта (network)
    network = params.get("type", [None])[0] or params.get("network", [None])[0]
    if not network or network.lower() != "tcp":
        return None

    # 6. Сборка объекта outbound для sing-box
    outbound: dict = {
        "type": "vless",
        "tag": tag,
        "server": hostname,
        "server_port": port,
        "uuid": urllib.parse.unquote(uuid),
        "tls": tls_opts,
    }

    # flow (например, xtls-rprx-vision) — поле уровня vless, а не tls.reality
    if flow:
        outbound["flow"] = flow

    return outbound


def clean_outbound(outbound: dict) -> dict:
    """Очистка и приведение VLESS ноды к спецификации sing-box."""
    if not outbound or outbound.get("type") != "vless":
        return outbound

    tls_opts = outbound.get("tls", {})
    if tls_opts and tls_opts.get("enabled"):
        reality_opts = tls_opts.get("reality", {})
        # Очищаем пустой short_id если не указан
        if reality_opts and not reality_opts.get("short_id"):
            reality_opts.pop("short_id", None)

    return outbound



