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
    should_accept_outbound,
)
from src.rkn_filter import (
    download_geoip,
    load_rkn_list,
    open_geoip_reader,
    resolve_and_check,
)
from src.testers.hy2_node_tester import test_hy2_connectivity


SOURCES_JSON_PATH = "./sub_urls.json"


def _fetch_links(sub_urls: list[str], prefix: str = "") -> list[str]:
    """Параллельно скачивает все подписки."""
    links: list[str] = []
    max_workers = min(10, len(sub_urls))
    print(f"{prefix}Fetching {len(sub_urls)} subscriptions with {max_workers} workers...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(fetch_subscription, url): url
            for url in sub_urls
        }
        for future in as_completed(future_to_url):
            try:
                links.extend(future.result())
            except Exception as e:
                url = future_to_url[future]
                print(f"{prefix}Error fetching {url}: {e}")
    print(f"{prefix}Total raw lines collected: {len(links)}")
    # Sort for deterministic deduplication order across runs
    links.sort()
    return links


def _resolve_outbound_server(server: str) -> str | None:
    """Резолвит домен в IP, если это не IP-адрес. Возвращает None при неудаче."""
    from src.common import is_valid_ip

    clean = server.strip("[]")
    if is_valid_ip(clean):
        return clean
    resolved = resolve_domain(clean)
    return resolved


def _parse_and_deduplicate(
    links: list[str],
    parse_proxy_link: Callable,
    clean_outbound: Callable,
    extra_filter: Callable[[dict], bool] | None,
    parse_kwargs: dict | None,
    protocol: str = "generic",
    tls_required: bool = False,
    port_whitelist: tuple[int, ...] | None = None,
    prefix: str = "",
) -> list[dict]:
    """Парсинг, быстрая фильтрация, DNS-резолвинг (параллельный), дедупликация по IP:port и дополнительные фильтры."""
    kw = parse_kwargs or {}

    print(f"{prefix}Parsing {len(links)} links...")
    # 1. Парсинг + быстрая фильтрация + очистка — без DNS
    parsed: list[tuple[int, dict]] = []
    seen_fps: set[str] = set()
    for idx, link in enumerate(links):
        outbound = parse_proxy_link(link, **kw)
        if not outbound:
            continue
        if not should_accept_outbound(
            outbound, seen_fps,
            protocol=protocol,
            tls_required=tls_required,
            port_whitelist=port_whitelist,
        ):
            continue
        outbound = clean_outbound(outbound)
        if not outbound:
            continue
        if extra_filter and not extra_filter(outbound):
            continue
        parsed.append((idx, outbound))

    print(f"{prefix}Parsed {len(parsed)} valid links, resolving {len(set(o.get('server', '') for _, o in parsed))} unique servers...")

    # 2. Параллельный DNS-резолвинг уникальных серверов (сортировка для детерминизма)
    unique_servers: dict[str, str | None] = {}
    servers = sorted(set(o.get("server", "").strip("[]").lower() for _, o in parsed))

    num_workers = min(16, len(servers))
    print(f"{prefix}Resolving {len(servers)} unique servers with {num_workers} workers...")
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_server = {
            executor.submit(_resolve_outbound_server, server): server
            for server in servers
        }
        for future in as_completed(future_to_server):
            server = future_to_server[future]
            try:
                unique_servers[server] = future.result()
            except Exception:
                unique_servers[server] = None

    # 3. Сборка outbounds с дедупликацией по резолвнутому IP
    seen: set[str] = set()
    outbounds: list[dict] = []
    for _idx, outbound in parsed:
        server = str(outbound.get("server", "")).strip("[]").lower()
        port = outbound.get("server_port", "")
        resolved_ip = unique_servers.get(server)

        if not resolved_ip:
            continue

        dedup_val = f"{resolved_ip}:{port}"
        if dedup_val in seen:
            continue
        seen.add(dedup_val)

        outbounds.append(outbound)

    return outbounds


def _rkn_geoip_filter(
    outbounds: list[dict],
    prefix: str = "",
) -> list[dict]:
    """RKN + GeoIP фильтрация через resolve_and_check."""
    from src.common import session

    download_geoip(session)
    blocked_networks = load_rkn_list(session)
    reader = open_geoip_reader()

    if reader:
        print(f"{prefix}GeoIP database loaded for geolocation filtering.")

    num_workers = min(8, len(outbounds))
    print(f"{prefix}Filtering {len(outbounds)} nodes with {num_workers} workers...")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_idx = {
            executor.submit(
                resolve_and_check,
                o.get("server", "").strip("[]"),
                blocked_networks,
                reader,
            ): idx
            for idx, o in enumerate(outbounds)
        }

        results: list[dict | None] = [None] * len(outbounds)
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None

    filtered: list[dict] = []
    for idx, check_result in enumerate(results):
        if check_result is not None:
            node = outbounds[idx]
            country = check_result.get("country")
            if country:
                node["_country"] = country
            filtered.append(node)

    removed = len(outbounds) - len(filtered)
    if removed:
        print(f"{prefix}Filtered out {removed} nodes by RKN/GeoIP ({len(filtered)} remaining).")

    if reader:
        reader.close()

    return filtered


def _sort_and_tag(outbounds: list[dict]) -> None:
    """Сортировка по стране и сквозная нумерация с флагами."""
    outbounds.sort(key=lambda o: (o.get("_country", ""), o.get("server", "")))
    for idx, outbound in enumerate(outbounds, start=1):
        outbound.pop("_latency_ms", None)  # internal — не экспортируем
        country = outbound.pop("_country", None)
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
    hy2_test: bool | None = None,
    hy2_test_timeout: int = 5,
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
        hy2_test: если True — запускает проверку работоспособности hy2 нод через hy2 CLI.
            По умолчанию True для protocol="hy2", False для остальных.
        hy2_test_timeout: таймаут проверки каждой hy2 ноды в секундах.
    """
    print(f"[{output_file}] Starting pipeline (exporter={exporter})...")

    prefix = f"[{output_file}] "

    # Default hy2_test: True for hy2 protocol, False otherwise
    if hy2_test is None:
        hy2_test = protocol == "hy2"

    # 1. Загрузка подписок
    sub_urls_path = os.path.join(os.path.dirname(__file__), SOURCES_JSON_PATH)
    with open(sub_urls_path, "r", encoding="utf-8") as f:
        sub_urls_data = json.load(f)
    sub_urls = list(sub_urls_data.values()) if isinstance(sub_urls_data, dict) else sub_urls_data
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
        prefix=prefix,
    )

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after parsing!")
        return

    # 4. RKN + GeoIP фильтрация
    outbounds = _rkn_geoip_filter(outbounds, prefix=prefix)

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after RKN+GeoIP filtration!")
        return

    # 4.5. Hysteria 2 connectivity test (pipeline-integrated)
    if protocol == "hy2" and hy2_test:
        outbounds = test_hy2_connectivity(
            outbounds,
            timeout=hy2_test_timeout,
            prefix=prefix,
        )

    if not outbounds:
        print(f"{prefix}Error: No valid proxy nodes left after all filters!")
        return

    print(f"[{output_file}] Total {len(outbounds)} nodes passed all filters.")

    # 5. Сортировка + нумерация
    _sort_and_tag(outbounds)

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
