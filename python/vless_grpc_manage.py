"""CLI-менеджер для управления рабочими нодами VLESS gRPC.

Команды:
  run     — полный pipeline: merge → export (по умолчанию)
  merge   — подтянуть новые ноды из подписок, добавить в vless_grpc_working.json
  export  — сгенерировать sing-box конфиг из vless_grpc_working.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PYTHON_DIR)

from src.vless_grpc_working import (
    load_working_nodes,
    save_working_nodes,
    merge_new_nodes,
    _cache_key,
)
from src.pending import (
    load_pending_nodes,
    save_pending_nodes,
    merge_pending_nodes,
    remove_nodes_by_keys,
)
from src.common import (
    clean_internal_fields,
    resolve_server,
    country_code_to_flag,
)
from src.testers.asn_resolver import resolve_asn
from src.filters.geoip_filter import resolve_country
from src.testers.vless_grpc_node_tester import test_vless_grpc_connectivity
from src.filters.blacklist import add_to_blacklist
from src.filters.whitelist import load_whitelist, is_whitelisted, add_to_whitelist, get_whitelist_nodes

_PENDING_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "src",
    "vless_grpc_pending.json",
)


def cmd_merge(args):
    """Подтягивает новые ноды из подписок и добавляет в vless_grpc_working.json.

    Использует run_pipeline() для fetch → parse → filter → DNS → dedup,
    затем сохраняет результат в vless_grpc_working.json (без нумерации тэгов).
    """
    from src.orchestrator import run_pipeline

    port_whitelist = tuple(int(p) for p in args.ports.split(",")) if args.ports else None
    geoip_filter_countries = tuple(c.strip().lower() for c in args.geoip_filter.split(",")) if args.geoip_filter else None
    skip_rkn = args.rkn_filter == 0

    # Кастомный export_func: сохраняет ноды в vless_grpc_working.json без нумерации
    def _save_to_working(outbounds, _output_file):
        existing = load_working_nodes()
        # Исключаем ноды, которые уже есть в pending
        pending = load_pending_nodes(_PENDING_FILE)
        pending_keys = {_cache_key(n) for n in pending}
        candidates = [n for n in outbounds if _cache_key(n) not in pending_keys]
        merged, added = merge_new_nodes(existing, candidates)
        print(f"Merge result: added {added} new nodes (total: {len(merged)})")
        save_working_nodes(merged)

    run_pipeline(
        parser_module="src.parsers.vless_grpc_parser",
        exporter="tun",
        output_file="vless_grpc_working.json",
        export_func=_save_to_working,
        protocol="vless",
        tls_required=True,
        port_whitelist=port_whitelist,
        reality=False,
        tester_func=None,
        geoip_filter_countries=geoip_filter_countries,
        skip_rkn=skip_rkn,
    )


def _readd_whitelisted():
    """Восстанавливает узлы из whitelist в working (полная конфигурация)."""
    whitelist = load_whitelist()
    whitelist_nodes = get_whitelist_nodes("vless_grpc", whitelist)
    if not whitelist_nodes:
        print("  Whitelist is empty, skipping.")
        return

    existing = load_working_nodes()
    existing_keys = {_cache_key(n) for n in existing}

    new_nodes = [n for n in whitelist_nodes if _cache_key(n) not in existing_keys]

    if not new_nodes:
        print(f"  All {len(whitelist_nodes)} whitelisted node(s) already in working.")
        return

    merged, added = merge_new_nodes(existing, new_nodes)
    if added:
        save_working_nodes(merged)
        print(f"  Re-added {added} whitelisted node(s) to working (total: {len(merged)})")
    else:
        print(f"  All {len(whitelist_nodes)} whitelisted node(s) already in working.")


def cmd_test(args):
    """Тестирование всех нод из vless_grpc_working.json и vless_grpc_pending.json.

    Логика:
      - Working + passed → обновить _last_ok_ts
      - Working + failed → перенести в pending.json
      - Pending + passed → перенести в working.json (удалить из pending)
      - Pending + failed + timeout → blacklist (удалить из pending)
      - Pending + failed + no timeout → оставить в pending
    """
    print("Loading nodes from vless_grpc_working.json...")
    working = load_working_nodes()
    print("Loading nodes from vless_grpc_pending.json...")
    pending = load_pending_nodes(_PENDING_FILE)

    if not working and not pending:
        print("No nodes found. Run 'merge' first.")
        return

    now_ts = datetime.now(timezone.utc).timestamp()
    STALE_THRESHOLD = 24 * 3600  # 24 часа
    WHITELIST_PROMOTION_THRESHOLD = args.whitelist_timeout * 24 * 3600

    whitelist = load_whitelist()

    # 1. Удаляем ноды с просроченным _last_ok_ts (> 24 часов) из working
    fresh_working = []
    for node in working:
        last_ok = node.get("_last_ok_ts")
        if last_ok and (now_ts - last_ok) > STALE_THRESHOLD:
            print(f"  Removing stale node (24h+): {node.get('server')}:{node.get('server_port')}")
        else:
            fresh_working.append(node)

    stale_count = len(working) - len(fresh_working)
    if stale_count:
        print(f"  Removed {stale_count} stale node(s)")
    working = fresh_working

    print(f"Working: {len(working)}, Pending: {len(pending)}")

    all_to_test = working + pending
    tested_working, failed, sub_ids_summary = test_vless_grpc_connectivity(
        all_to_test,
        timeout=args.test_timeout,
        prefix="",
    )

    working_keys = {_cache_key(w) for w in tested_working}
    new_working = []
    new_pending = []
    whitelist_promoted = 0

    PENDING_REMOVAL_THRESHOLD = args.blacklist_timeout * 24 * 3600

    # 1. Обработка working: прошедшие тест остаются в working
    for node in working:
        key = _cache_key(node)
        if key in working_keys:
            node["_last_ok_ts"] = now_ts
            new_working.append(node)
            if not is_whitelisted(node, whitelist, "vless_grpc"):
                whitelist_promoted += 1
        else:
            # Working провалил тест → в pending
            node["_pending_since"] = now_ts
            new_pending.append(node)

    # 2. Обработка pending: прошедшие тест → в working, провалившие → blacklist или оставить
    for node in pending:
        key = _cache_key(node)
        if key in working_keys:
            # Pending прошёл тест → в working
            node["_last_ok_ts"] = now_ts
            node.pop("_pending_since", None)
            new_working.append(node)
            if not is_whitelisted(node, whitelist, "vless_grpc"):
                whitelist_promoted += 1
        else:
            # Pending провалил тест → проверяем таймаут
            pending_since = node.get("_pending_since", 0)
            if (now_ts - pending_since) > PENDING_REMOVAL_THRESHOLD:
                print(f"  Adding failed pending node to blacklist: {node.get('server')}:{node.get('server_port')}")
                add_to_blacklist(node, "vless_grpc")
            else:
                new_pending.append(node)

    # Сохраняем промоут в whitelist
    if whitelist_promoted:
        for w in new_working:
            if not is_whitelisted(w, whitelist, "vless_grpc"):
                add_to_whitelist(w, "vless_grpc")
        print(f"  Promoted {whitelist_promoted} node(s) to whitelist")

    if failed:
        print()
        print(f"VLESS gRPC connectivity: {len(tested_working)} working / {failed} failed ({len(all_to_test)} total){sub_ids_summary}.")

    save_working_nodes(new_working)
    save_pending_nodes(new_pending, _PENDING_FILE)
    print(f"\nSaved {len(new_working)} working to vless_grpc_working.json")
    print(f"Saved {len(new_pending)} pending to vless_grpc_pending.json")


def cmd_run(args):
    """Полный pipeline: merge -> whitelist re-add -> test -> export."""
    print("=" * 60)
    print("STEP 1: Merge new nodes from subscriptions")
    print("=" * 60)
    cmd_merge(args)

    print("\n" + "=" * 60)
    print("STEP 1.5: Re-add whitelisted nodes to working")
    print("=" * 60)
    _readd_whitelisted()

    print("\n" + "=" * 60)
    print("STEP 2: Test all working nodes")
    print("=" * 60)
    cmd_test(args)

    print("\n" + "=" * 60)
    print("STEP 3: Export configs")
    print("=" * 60)
    cmd_export(argparse.Namespace(export=args.export, output="vless_grpc_tun.json"))


def cmd_export(args):
    """Экспортирует конфиги из vless_grpc_working.json.

    На экспорт идут только active ноды из working файла.
    Pending ноды остаются в vless_grpc_pending.json.
    """
    all_nodes = load_working_nodes()
    if not all_nodes:
        print("No active nodes found in vless_grpc_working.json.")
        all_nodes = []

    active_nodes = all_nodes
    pending_nodes = load_pending_nodes(_PENDING_FILE)

    if not active_nodes:
        print("No active nodes to export.")

    active_nodes = renumber_nodes(active_nodes)
    save_working_nodes(active_nodes)
    save_pending_nodes(pending_nodes, _PENDING_FILE)

    if pending_nodes:
        print(f"Exporting {len(active_nodes)} active nodes ({len(pending_nodes)} pending in vless_grpc_pending.json)")
    else:
        print(f"Exporting {len(active_nodes)} nodes")

    for node in active_nodes:
        asn = resolve_asn(node.get("server", ""))
        sub_ids = node.get("_sub_ids", set())
        sub_ids_str = f" [{','.join(sorted(sub_ids))}]" if sub_ids else ""
        print(f"  [Node] {node.get('tag')} {node.get('server')}:{node.get('server_port')} {asn}{sub_ids_str}")

    export_formats = [f.strip() for f in args.export.split(",")] if args.export else []

    if "tun" in export_formats:
        _export_tun(active_nodes, args.output)
    if "xray" in export_formats:
        _export_v2ray(active_nodes)


def renumber_nodes(nodes: list[dict]) -> list[dict]:
    """Определяет страну, сортирует по флагу, назначает тэги node-1, node-2, ..."""
    for node in nodes:
        country = resolve_country(node.get("server", ""))
        node["_country"] = country

    nodes.sort(key=lambda o: (
        country_code_to_flag(o.get("_country", "")) or "",
        o.get("server", ""),
        o.get("server_port", 0),
    ))

    for idx, node in enumerate(nodes, start=1):
        country = node.pop("_country", None)
        node.pop("_latency_ms", None)
        flag = country_code_to_flag(country) if country else ""
        node["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"
    return nodes


def _resolve_output(output_file: str) -> str:
    """Решает абсолютный путь для выходного файла относительно корня проекта."""
    if os.path.isabs(output_file):
        return output_file
    root_dir = Path(PYTHON_DIR).parent
    return str((root_dir / output_file).resolve())


def _export_tun(nodes, output_file):
    """Экспорт в sing-box TUN конфиг."""
    from src.exporters.singbox_exporter import export_tun
    for n in nodes:
        clean_internal_fields(n)
    output_file = _resolve_output(output_file)
    export_tun(nodes, output_file)


def _export_v2ray(nodes, output_file=None):
    """Экспорт в V2Ray-ссылки (vless_grpc.txt в корне проекта)."""
    from src.exporters.v2ray_exporter import _generate_vless_grpc_links
    if output_file is None:
        output_file = os.path.join(os.path.dirname(PYTHON_DIR), "vless_grpc.txt")
    links = _generate_vless_grpc_links(nodes)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"Exported {len(links)} VLESS gRPC nodes to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Manage VLESS gRPC working nodes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vless_grpc_manage.py run                              Full pipeline (merge+test+export)
  python vless_grpc_manage.py merge                            Fetch new nodes from subscriptions
  python vless_grpc_manage.py test                             Test all nodes
  python vless_grpc_manage.py export --export tun,xray         Export all formats
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # run (default)
    run_parser = subparsers.add_parser("run", help="Full pipeline: merge -> test -> export")
    run_parser.add_argument("--ports", type=str, default=None,
                            help="Comma-separated port whitelist (default: all ports)")
    run_parser.add_argument("--test-timeout", type=int, default=10, help="Test timeout per node (seconds)")
    run_parser.add_argument("--export", type=str, default="tun,xray",
                            help="Export formats (default: tun,xray): tun,xray,router")
    run_parser.add_argument("--geoip-filter", type=str, default=None,
                            help="Comma-separated list of country codes to filter (e.g. 'ru,ir')")
    run_parser.add_argument("--rkn-filter", type=int, choices=[0, 1], default=0,
                            help="RKN filter: 0 = skip filtering, 1 = apply filtering (default: 1)")
    run_parser.add_argument("--blacklist-timeout", type=int, default=3,
                            help="Days in pending before adding to blacklist (default: 3)")
    run_parser.add_argument("--whitelist-timeout", type=int, default=3,
                            help="Days in working before promoting to whitelist (default: 3)")

    # merge
    merge_parser = subparsers.add_parser("merge", help="Fetch new nodes from subscriptions")
    merge_parser.add_argument("--ports", type=str, default=None,
                              help="Comma-separated port whitelist (default: all ports)")
    merge_parser.add_argument("--geoip-filter", type=str, nargs='*', default=None,
                              help="Country codes to filter (e.g. --geoip-filter ru ir or --geoip-filter ru,ir)")
    merge_parser.add_argument("--rkn-filter", type=int, choices=[0, 1], default=0,
                              help="RKN filter: 0 = skip filtering, 1 = apply filtering (default: 1)")

    # test
    test_parser = subparsers.add_parser("test", help="Test all nodes and remove dead ones")
    test_parser.add_argument("--test-timeout", type=int, default=5, help="Test timeout per node (seconds)")

    # export
    export_parser = subparsers.add_parser("export", help="Export working nodes to sing-box config")
    export_parser.add_argument("--export", type=str, default="tun",
                               help="Export formats (default: tun): tun,xray,router")
    export_parser.add_argument("--output", default="vless_grpc_tun.json", help="Output file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "run":
        cmd_run(args)
    elif args.command == "merge":
        cmd_merge(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "export":
        cmd_export(args)


if __name__ == "__main__":
   main()
