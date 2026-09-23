"""CLI-менеджер для управления рабочими нодами Hysteria2.

Команды:
  test    — протестировать все ноды из hy2_working.json, удалить нерабочие
  merge   — подтянуть новые ноды из подписок, добавить в hy2_working.json
  export  — сгенерировать sing-box конфиг из hy2_working.json
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

# Добавляем python/ в sys.path
PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PYTHON_DIR)

from src.hy2_working import (
    load_working_nodes,
    save_working_nodes,
    remove_stale_nodes,
    dedup_nodes,
    merge_new_nodes,
    _WORKING_FILE,
)
from src.testers.hy2_node_tester import test_hy2_connectivity
from src.exporters.singbox_exporter import export_tun, export_router
from src.common import country_code_to_flag


def cmd_test(args):
    """Тестирование всех нод из hy2_working.json."""
    print(f"Loading {len(load_working_nodes())} nodes from hy2_working.json...")
    nodes = load_working_nodes()
    if not nodes:
        print("No nodes found. Run 'merge' first.")
        return

    # Запускаем тестирование через существующий tester
    working = test_hy2_connectivity(
        nodes,
        timeout=args.timeout,
        prefix="",
    )

    # Обновляем _last_ok_ts для рабочих нод
    now_ts = datetime.now(timezone.utc).timestamp()
    for node in working:
        node["_last_ok_ts"] = now_ts

    # Удаляем устаревшие
    working = remove_stale_nodes(working, stale_days=args.stale_days)

    # Сохраняем
    save_working_nodes(working)
    print(f"\nSaved {len(working)} working nodes to hy2_working.json")


def cmd_merge(args):
    """Подтягивает новые ноды из подписок и добавляет в hy2_working.json."""
    from src.orchestrator import run_pipeline

    # Сначала запускаем pipeline для сбора новых нод
    print("Fetching subscriptions and parsing new nodes...")

    # Используем run_pipeline с кастомным export_func для сбора кандидатов
    from src.parsers.hy2_parser import parse_proxy_link, clean_outbound
    from src.common import fetch_subscription, should_accept_outbound, resolve_domain, is_valid_ip
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import importlib

    # Загрузка подписок
    sub_urls_path = os.path.join(PYTHON_DIR, "src", "sub_urls.json")
    with open(sub_urls_path, "r", encoding="utf-8") as f:
        sub_urls_data = json.load(f)
    sub_urls = list(sub_urls_data.values()) if isinstance(sub_urls_data, dict) else sub_urls_data

    # Скачиваем все подписки
    links = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {
            executor.submit(fetch_subscription, url): url
            for url in sub_urls
        }
        for future in as_completed(future_to_url):
            try:
                links.extend(future.result())
            except Exception as e:
                print(f"Error fetching: {e}")

    print(f"Collected {len(links)} raw lines")

    # Парсим
    seen_fps = set()
    parsed = []
    for link in links:
        outbound = parse_proxy_link(link)
        if not outbound:
            continue
        if not should_accept_outbound(
            outbound, seen_fps,
            protocol="hy2",
            tls_required=True,
            port_whitelist=args.port_whitelist,
        ):
            continue
        outbound = clean_outbound(outbound)
        if not outbound:
            continue
        parsed.append(outbound)

    print(f"Parsed {len(parsed)} valid nodes")

    # Резолвим DNS
    unique_servers = {}
    servers = sorted(set(o.get("server", "").strip("[]").lower() for o in parsed))
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_server = {
            executor.submit(_resolve_server, server): server
            for server in servers
        }
        for future in as_completed(future_to_server):
            server = future_to_server[future]
            try:
                unique_servers[server] = future.result()
            except Exception:
                unique_servers[server] = None

    seen_ips = set()
    outbounds = []
    for o in parsed:
        server = str(o.get("server", "")).strip("[]").lower()
        port = o.get("server_port", "")
        resolved_ip = unique_servers.get(server)
        if not resolved_ip:
            continue
        dedup_val = f"{resolved_ip}:{port}"
        if dedup_val in seen_ips:
            continue
        seen_ips.add(dedup_val)
        outbounds.append(o)

    print(f"After DNS + dedup: {len(outbounds)} nodes")

    if not outbounds:
        print("No new nodes found.")
        return

    # Загружаем существующие
    existing = load_working_nodes()
    merged, added = merge_new_nodes(existing, outbounds)

    if added == 0:
        print("No new nodes to add.")
    else:
        print(f"Added {added} new nodes (total: {len(merged)}).")

    save_working_nodes(merged)


def cmd_export(args):
    """Генерирует sing-box конфиг из hy2_working.json."""
    nodes = load_working_nodes()
    if not nodes:
        print("No nodes found. Run 'test' or 'merge' first.")
        return

    # Сортируем и нумеруем
    nodes.sort(key=lambda o: (o.get("server", ""), o.get("server_port", 0)))
    for idx, node in enumerate(nodes, start=1):
        # Определяем страну по latency или серверу
        flag = ""
        tag = f"node-{idx}"

        # Простая эвристика: по серверу определяем флаг
        server = node.get("server", "").lower()
        if "de" in server or "germany" in server or "berlin" in server:
            flag = "🇩🇪"
        elif "dk" in server or "denmark" in server or "copenhagen" in server:
            flag = "🇩🇰"
        elif "kr" in server or "korea" in server or "seoul" in server:
            flag = "🇰🇷"
        elif "ro" in server or "romania" in server or "bucharest" in server:
            flag = "🇷🇴"
        elif "us" in server or "america" in server or "newyork" in server or "losangeles" in server:
            flag = "🇺🇸"
        elif "nl" in server or "netherlands" in server or "amsterdam" in server:
            flag = "🇳🇱"
        elif "fr" in server or "france" in server or "paris" in server:
            flag = "🇫🇷"
        elif "se" in server or "sweden" in server or "stockholm" in server:
            flag = "🇸🇪"
        elif "pl" in server or "poland" in server or "warsaw" in server:
            flag = "🇵🇱"
        elif "uk" in server or "london" in server or "gb" in server:
            flag = "🇬🇧"
        elif "jp" in server or "japan" in server or "tokyo" in server:
            flag = "🇯🇵"

        node["tag"] = f"{flag}{tag}" if flag else tag

    # Очистка внутренних полей
    for node in nodes:
        node.pop("_latency_ms", None)
        node.pop("_last_ok_ts", None)
        node.pop("_country", None)

    # Экспорт
    if args.type == "tun":
        export_tun(nodes, args.output)
    elif args.type == "router":
        export_router(nodes, args.output)
    else:
        print(f"Unknown export type: {args.type}")


def _resolve_server(server: str) -> str | None:
    """Резолвит домен в IP."""
    import socket
    from src.common import is_valid_ip

    clean = server.strip("[]")
    if is_valid_ip(clean):
        return clean
    try:
        return socket.gethostbyname(clean)
    except socket.gaierror:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Manage Hysteria2 working nodes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hy2_manage.py test              Test all nodes
  python hy2_manage.py merge             Fetch new nodes from subscriptions
  python hy2_manage.py export --type tun --output hy2_tun.json
  python hy2_manage.py test --timeout 10 --stale-days 30
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # test
    test_parser = subparsers.add_parser("test", help="Test all nodes and remove dead ones")
    test_parser.add_argument("--timeout", type=int, default=5, help="Test timeout per node (seconds)")
    test_parser.add_argument("--stale-days", type=int, default=14, help="Remove nodes older than N days")

    # merge
    merge_parser = subparsers.add_parser("merge", help="Fetch new nodes from subscriptions")
    merge_parser.add_argument("--ports", type=str, default="443,8443,2053,2083,2087,2096,4433",
                              help="Comma-separated port whitelist")

    # export
    export_parser = subparsers.add_parser("export", help="Export working nodes to sing-box config")
    export_parser.add_argument("--type", choices=["tun", "router"], default="tun", help="Export type")
    export_parser.add_argument("--output", default="hy2_tun.json", help="Output file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "test":
        cmd_test(args)
    elif args.command == "merge":
        port_whitelist = tuple(int(p) for p in args.ports.split(","))
        cmd_merge(args)
    elif args.command == "export":
        cmd_export(args)


if __name__ == "__main__":
    main()
