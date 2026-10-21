"""Универсальный оркестратор pipeline для сборки прокси-конфигов."""

import importlib
import json
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.common import (
    country_code_to_flag,
    fetch_subscription,
    resolve_domain,
    resolve_server,
    should_accept_outbound,
)
from src.filters.rkn_filter import load_rkn_list, check_rkn_blocked
from src.filters.geoip_filter import lookup_geoip, open_geoip_reader
from src.filters.blacklist import load_blacklist, is_blacklisted


SOURCES_JSON_PATH = "./sub_urls.json"


def _format_proxy_types(formats: dict) -> str:
    """Форматирует словарь proxy_formats в строку для лога."""
    if not formats:
        return "0 types"
    parts = []
    for name, count in sorted(formats.items(), key=lambda x: x[1], reverse=True):
        parts.append(f"{name}={count}")
    return ", ".join(parts)


def _fetch_links(sub_urls: list[tuple[str, str]], prefix: str = "") -> list[tuple[str, str]]:
    """Параллельно скачивает все подписки.

    Returns:
        list of (sub_id, link) tuples.
    """
    links: list[tuple[str, str]] = []
    results: list[dict] = []
    max_workers = min(10, len(sub_urls))
    print(f"{prefix}Fetching {len(sub_urls)} subscriptions with {max_workers} workers...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(fetch_subscription, url): (sid, url)
            for sid, url in sub_urls
        }
        for future in as_completed(future_to_url):
            try:
                result = future.result()
                results.append(result)
                if result.get("valid"):
                    sub_id, url = future_to_url[future]
                    for line in result.get("lines", []):
                        links.append((sub_id, line))
                else:
                    err = result.get("error", "unknown")
                    print(f"{prefix}  [SKIP] {result['url']} — {err}")
            except Exception as e:
                url = future_to_url[future][1]
                print(f"{prefix}  [ERROR] {url} — {e}")
    valid = sum(1 for r in results if r.get("valid"))
    print(f"{prefix}Subscriptions: {valid}/{len(results)} valid")
    for r in sorted(results, key=lambda x: x.get("link_count", 0), reverse=True):
        if r.get("valid"):
            fmt = r.get("format", "?")
            pf = _format_proxy_types(r.get("proxy_formats", {}))
            print(f"{prefix}  [OK]   {r['url']} — {fmt} — {r['link_count']} links — {pf}")
    print(f"{prefix}Total raw lines collected: {len(links)}")
    # Sort for deterministic deduplication order across runs
    links.sort(key=lambda x: x[1])
    return links


def _parse_and_deduplicate(
    links: list[tuple[str, str]],
    parse_proxy_link: Callable,
    clean_outbound: Callable,
    extra_filter: Callable[[dict], bool] | None,
    parse_kwargs: dict | None,
    protocol: str = "generic",
    tls_required: bool = False,
    port_whitelist: tuple[int, ...] | None = None,
    reality: bool = False,
    prefix: str = "",
) -> list[dict]:
    """Парсинг, быстрая фильтрация, DNS-резолвинг (параллельный), дедупликация по IP:port и дополнительные фильтры.

    Каждая нода получает поле _sub_ids — множество ID подписок, в которых она встречается.
    """
    kw = parse_kwargs or {}

    print(f"{prefix}Parsing {len(links)} links...")
    # 1. Парсинг + быстрая фильтрация + очистка — без DNS
    # parsed: list of (sub_id, outbound)
    parsed: list[tuple[str, dict]] = []
    seen_fps: set[str] = set()
    for sub_id, link in links:
        outbound = parse_proxy_link(link, **kw)
        if not outbound:
            continue
        if not should_accept_outbound(
            outbound, seen_fps,
            protocol=protocol,
            tls_required=tls_required,
            port_whitelist=port_whitelist,
            reality=reality,
        ):
            continue
        outbound = clean_outbound(outbound)
        if not outbound:
            continue
        if extra_filter and not extra_filter(outbound):
            continue
        parsed.append((sub_id, outbound))

    print(f"{prefix}Parsed {len(parsed)} valid links, resolving {len(set(o.get('server', '') for _, o in parsed))} unique servers...")

    # 2. Параллельный DNS-резолвинг уникальных серверов (сортировка для детерминизма)
    unique_servers: dict[str, str | None] = {}
    servers = sorted(set(o.get("server", "").strip("[]").lower() for _, o in parsed))

    num_workers = min(16, len(servers))
    print(f"{prefix}Resolving {len(servers)} unique servers with {num_workers} workers...")
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_server = {
            executor.submit(resolve_server, server): server
            for server in servers
        }
        for future in as_completed(future_to_server):
            server = future_to_server[future]
            try:
                unique_servers[server] = future.result()
            except Exception:
                unique_servers[server] = None

    # 3. Сборка outbounds с дедупликацией по резолвнутому IP + сбор sub_ids
    seen: set[str] = set()
    outbounds: list[dict] = []
    for sub_id, outbound in parsed:
        server = str(outbound.get("server", "")).strip("[]").lower()
        port = outbound.get("server_port", "")
        resolved_ip = unique_servers.get(server)

        if not resolved_ip:
            continue

        dedup_key = outbound.get("_dedup_key", "")
        if dedup_key in seen:
            # Нода уже есть — добавляем sub_id в существующую
            for o in outbounds:
                o_ip = str(o.get("server", "")).strip("[]").lower()
                o_port = o.get("server_port", "")
                o_dedup = o.get("_dedup_key", f"{o_ip}:{o_port}:{o.get('uuid', '')}")
                if o_dedup == dedup_key:
                    o.setdefault("_sub_ids", set()).add(sub_id)
                    break
            continue
        seen.add(dedup_key)

        outbound.setdefault("_sub_ids", set()).add(sub_id)
        outbounds.append(outbound)

    return outbounds


def _check_rkn(server: str, blocked_networks) -> bool:
    """Проверяет ноду по RKN списку.

    Returns:
        True если нода заблокирована RKN, False иначе.
    """
    return check_rkn_blocked(server, blocked_networks) is True


def _rkn_filter(
    outbounds: list[dict],
    prefix: str = "",
    skip_rkn: bool = False,
) -> list[dict]:
    """RKN фильтрация через check_rkn_blocked.

    Args:
        outbounds: список нод для фильтрации.
        prefix: префикс для логов.
        skip_rkn: если True — пропускает проверку RKN.
    """
    from src.common import session

    if skip_rkn:
        print(f"{prefix}RKN filtering is SKIPPED.")
        return outbounds

    blocked_networks = load_rkn_list(session)
    num_workers = min(8, len(outbounds))
    print(f"{prefix}Filtering {len(outbounds)} nodes by RKN with {num_workers} workers...")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {
            executor.submit(_check_rkn, o.get("server", "").strip("[]"), blocked_networks): idx
            for idx, o in enumerate(outbounds)
        }

        rkn_blocked: list[dict] = []
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                if future.result():
                    rkn_blocked.append(outbounds[idx])
            except Exception:
                pass

    filtered = [o for o in outbounds if o not in rkn_blocked]
    removed_count = len(rkn_blocked)

    if removed_count:
        print(f"{prefix}Filtered out {removed_count} node(s) by RKN ({len(filtered)} remaining).")
        for node in rkn_blocked:
            print(f"{prefix}  [RKN] {node.get('server')}:{node.get('server_port')}")
    else:
        print(f"{prefix}No nodes filtered by RKN ({len(filtered)} remaining).")

    return filtered


def _geoip_block(
    outbounds: list[dict],
    prefix: str = "",
    geoip_block_countries: tuple[str, ...] | None = None,
) -> list[dict]:
    """Блокирует ноды по GeoIP для указанных стран.

    Args:
        outbounds: список нод для обработки.
        prefix: префикс для логов.
        geoip_block_countries: кортеж ISO-кодов стран для блокировки (например ("ru", "ir")).
            Если None или пустой — блокировка отключена.
    """
    if not geoip_block_countries:
        print(f"{prefix}GeoIP blocking is SKIPPED (no countries to block).")
        return outbounds

    reader = open_geoip_reader()
    if not reader:
        print(f"{prefix}GeoIP database not available, skipping GeoIP blocking.")
        return outbounds

    print(f"{prefix}GeoIP database loaded for blocking (block: {', '.join(geoip_block_countries)}).")
    num_workers = min(8, len(outbounds))
    print(f"{prefix}Blocking {len(outbounds)} nodes by GeoIP ({', '.join(geoip_block_countries)}) with {num_workers} workers...")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {
            executor.submit(
                lookup_geoip,
                o.get("server", "").strip("[]"),
                reader,
                geoip_block_countries,
            ): idx
            for idx, o in enumerate(outbounds)
        }

        results: list[dict | str | None] = [None] * len(outbounds)
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None

    filtered: list[dict] = []
    removed_geo: dict[str, list[dict]] = {}
    for idx, check_result in enumerate(results):
        if check_result is not None:
            if isinstance(check_result, str):
                # Это ISO-код страны — блокировка
                removed_geo.setdefault(check_result, []).append(outbounds[idx])
                continue
            node = outbounds[idx]
            country = check_result.get("country")
            if country:
                node["_country"] = country
            filtered.append(node)
        else:
            # GeoIP база недоступна или IP не найден — пропускаем
            filtered.append(outbounds[idx])

    removed_geo_count = sum(len(nodes) for nodes in removed_geo.values())

    if removed_geo_count:
        print(f"{prefix}Blocked {removed_geo_count} node(s) by GeoIP ({len(filtered)} remaining).")
        for country_code, nodes in sorted(removed_geo.items()):
            for node in nodes:
                print(f"{prefix}  [{country_code.upper()}] {node.get('server')}:{node.get('server_port')}")
    else:
        print(f"{prefix}No nodes blocked by GeoIP ({len(filtered)} remaining).")

    reader.close()
    return filtered


def _sort_and_tag(outbounds: list[dict], *, keep_country: bool = False) -> None:
    """Сортировка по стране и сквозная нумерация с флагами.
    
    Args:
        outbounds: список нод для сортировки и нумерации.
        keep_country: если True — не удаляет _country из нод (для сохранения в working).
    """
    outbounds.sort(key=lambda o: (o.get("_country", ""), o.get("server", "")))
    for idx, outbound in enumerate(outbounds, start=1):
        outbound.pop("_latency_ms", None)  # internal — не экспортируем
        if not keep_country:
            country = outbound.pop("_country", None)
        else:
            country = outbound.get("_country")
        flag = country_code_to_flag(country) if country else ""
        outbound["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"


def run_pipeline(
    parser_module: str,
    *,
    exporter: str = "tun",
    output_file: str = "output.json",
    extra_filter: Callable[[dict], bool] | None = None,
    parse_kwargs: dict | None = None,
    export_func: Callable | None = None,
    post_process: Callable[[list[dict]], None] | None = None,
    protocol: str = "generic",
    tls_required: bool = False,
    port_whitelist: tuple[int, ...] | None = None,
    tester_func: Callable | None = None,
    test_timeout: int = 5,
    reality: bool = False,
    geoip_block_countries: tuple[str, ...] | None = None,
    skip_rkn: bool = False,
) -> None:
    """Запускает полный pipeline сборки конфига.

    Args:
        parser_module: dotted path к модулю парсера (например "src.parsers.hy2_parser").
        exporter: "tun" или "v2ray" или "router". Используется по умолчанию, если export_func не указан.
        output_file: имя выходного файла.
        extra_filter: дополнительная функция фильтрации (возвращает True/False).
        parse_kwargs: дополнительные аргументы для parse_proxy_link.
        export_func: кастомная функция экспорта. Если None — используется exporter.
        post_process: функция для постобработки перед экспортом.
        protocol: тип протокола для быстрой фильтрации ("hy2", "vless", "vmess").
        tls_required: если True — требует TLS + server_name.
        port_whitelist: если указан — разрешены только эти порты.
        tester_func: функция тестирования нод (accepts list[dict], timeout, prefix -> list[dict]).
            Если None — тестирование пропускается.
        test_timeout: таймаут проверки каждой ноды в секундах.
        reality: если True — для reality-протоколов не фильтрует SNI по FAKE_DOMAINS.
        geoip_filter_countries: кортеж ISO-кодов стран для фильтрации (например ("ru", "ir")).
            Если None или пустой — фильтрация по странам отключена.
        skip_rkn: если True — пропускает проверку RKN.
    """
    print(f"[{output_file}] Starting pipeline (exporter={exporter})...")

    prefix = f"[{output_file}] "

    # 1. Загрузка подписок
    sub_urls_path = os.path.join(os.path.dirname(__file__), SOURCES_JSON_PATH)
    with open(sub_urls_path, "r", encoding="utf-8") as f:
        sub_urls_data = json.load(f)
    if isinstance(sub_urls_data, dict):
        sub_urls = list(sub_urls_data.items())  # [(key, url), ...]
    else:
        sub_urls = [(str(i), url) for i, url in enumerate(sub_urls_data, 1)]
    if not sub_urls:
        return

    links = _fetch_links(sub_urls, prefix=prefix)
    if not links:
        return

    # 2. Импорт парсера
    mod = importlib.import_module(parser_module)
    parse_proxy_link = mod.parse_proxy_link
    clean_outbound = mod.clean_outbound

    # 3. Парсинг + быстрая фильтрация + дедупликация
    outbounds = _parse_and_deduplicate(
        links,
        parse_proxy_link,
        clean_outbound,
        extra_filter,
        parse_kwargs,
        protocol=protocol,
        tls_required=tls_required,
        port_whitelist=port_whitelist,
        reality=reality,
        prefix=prefix,
    )

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after parsing!")
        return

    # 4. RKN фильтрация
    outbounds = _rkn_filter(outbounds, prefix=prefix, skip_rkn=skip_rkn)

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after RKN filtration!")
        return

    # 4.1. GeoIP блокировка
    outbounds = _geoip_block(outbounds, prefix=prefix, geoip_block_countries=geoip_block_countries)

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after GeoIP filtration!")
        return

    # 4.5. Blacklist фильтрация
    blacklist = load_blacklist()
    blacklist_proto = protocol if protocol in ("vless_xhttp", "vless_tcp", "hy2", "vless_grpc") else None
    if blacklist_proto and blacklist.get(blacklist_proto):
        blacklisted = [o for o in outbounds if is_blacklisted(o, blacklist, blacklist_proto)]
        if blacklisted:
            print(f"{prefix}Filtered out {len(blacklisted)} node(s) from blacklist.")
        outbounds = [o for o in outbounds if not is_blacklisted(o, blacklist, blacklist_proto)]

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after all filters!")
        return

    # 4.6. Connectivity test (если указан tester_func)
    if tester_func:
        outbounds = tester_func(
            outbounds,
            timeout=test_timeout,
            prefix=prefix,
        )

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after all filters!")
        return

    print(f"[{output_file}] Total {len(outbounds)} nodes passed all filters.")

    # 5. Сортировка + нумерация
    _sort_and_tag(outbounds, keep_country=bool(export_func))

    # 6. Постобработка
    if post_process:
        post_process(outbounds)

    # 7. Экспорт
    if export_func:
        export_func(outbounds, output_file)
    elif exporter == "v2ray":
        from src.exporters.v2ray_exporter import export_v2ray_by_type
        export_v2ray_by_type(outbounds, output_file)
    elif exporter == "router":
            from src.exporters.singbox_exporter import export_router
            export_router(outbounds, output_file)
    else:
        from src.exporters.singbox_exporter import export_tun
        export_tun(outbounds, output_file)