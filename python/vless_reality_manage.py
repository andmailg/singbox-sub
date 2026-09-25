"""CLI-менеджер для управления рабочими нодами VLESS Reality.

Команды:
  run     — полный pipeline: merge → export (по умолчанию)
  merge   — подтянуть новые ноды из подписок, добавить в vless_reality_working.json
  export  — сгенерировать sing-box конфиг из vless_reality_working.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PYTHON_DIR)

from src.vless_working import (
    load_working_nodes,
    save_working_nodes,
    merge_new_nodes,
    _cache_key,
)
from src.common import (
    INTERNAL_FIELDS,
    clean_internal_fields,
    resolve_server,
    country_code_to_flag,
)
from src.rkn_filter import resolve_country
from src.testers.vless_node_tester import test_vless_connectivity


def cmd_merge(args):
    """Подтягивает новые ноды из подписок и добавляет в vless_reality_working.json.

    Использует run_pipeline() для fetch → parse → filter → DNS → dedup,
    затем сохраняет результат в vless_reality_working.json (без нумерации тэгов).
    """
    from src.orchestrator import run_pipeline

    port_whitelist = tuple(int(p) for p in args.ports.split(",")) if args.ports else None

    # Кастомный export_func: сохраняет ноды в vless_reality_working.json без нумерации
    def _save_to_working(outbounds, _output_file):
        existing = load_working_nodes()
        merged, added = merge_new_nodes(existing, outbounds)
        print(f"Merge result: added {added} new nodes (total: {len(merged)})")
        save_working_nodes(merged)

    run_pipeline(
        parser_module="src.parsers.vless_tcp_parser",
        exporter="tun",
        output_file="vless_tcp_working.json",
        export_func=_save_to_working,
        protocol="vless",
        tls_required=True,
        port_whitelist=port_whitelist,
        reality=True,
        tester_func=None,  # тестирование отдельно через cmd_test (если нужно)
    )


def cmd_test(args):
    """Тестирование всех нод из vless_reality_working.json."""
    print("Loading nodes from vless_reality_working.json...")
    nodes = load_working_nodes()
    if not nodes:
        print("No nodes found. Run 'merge' first.")
        return

    now_ts = datetime.now(timezone.utc).timestamp()
    STALE_THRESHOLD = 24 * 3600  # 24 часа

    # 1. Удаляем ноды с просроченным _last_ok_ts (> 24 часов)
    fresh_nodes = []
    for node in nodes:
        last_ok = node.get("_last_ok_ts")
        if last_ok and (now_ts - last_ok) > STALE_THRESHOLD:
            print(f"  Removing stale node (24h+): {node.get('server')}:{node.get('server_port')}")
        else:
            fresh_nodes.append(node)

    stale_count = len(nodes) - len(fresh_nodes)
    if stale_count:
        print(f"  Removed {stale_count} stale node(s)")
    nodes = fresh_nodes

    pending_nodes = [n for n in nodes if "_pending_since" in n]
    active_nodes = [n for n in nodes if "_pending_since" not in n]

    print(f"Active: {len(active_nodes)}, Pending: {len(pending_nodes)}")

    all_to_test = active_nodes + pending_nodes
    working = test_vless_connectivity(
        all_to_test,
        timeout=args.timeout,
        prefix="",
    )

    # Обновляем статусы
    working_keys = {_cache_key(w) for w in working}
    new_working = []
    new_pending = []

    for node in nodes:
        key = _cache_key(node)
        if key in working_keys:
            node["_last_ok_ts"] = now_ts
            node.pop("_pending_since", None)
            new_working.append(node)
        elif "_pending_since" in node:
            print(f"  Removing failed pending node: {node.get('server')}:{node.get('server_port')}")
        else:
            node["_pending_since"] = now_ts
            new_pending.append(node)

    save_working_nodes(new_working + new_pending)
    print(f"\nSaved {len(new_working)} working, {len(new_pending)} pending nodes to vless_tcp_working.json")


def cmd_run(args):
    """Полный pipeline: merge -> test -> export."""
    # Step 1: Merge
    print("=" * 60)
    print("STEP 1: Merge new nodes from subscriptions")
    print("=" * 60)
    cmd_merge(args)

    # Step 2: Test
    print("\n" + "=" * 60)
    print("STEP 2: Test all working nodes")
    print("=" * 60)
    cmd_test(args)

    # Step 3: Export
    print("\n" + "=" * 60)
    print("STEP 3: Export configs")
    print("=" * 60)
    cmd_export(argparse.Namespace(type="all", output="vless_tcp_tun.json"))


def cmd_export(args):
    """Генерирует sing-box конфиг из vless_tcp_working.json.

    На экспорт идут только active ноды (без _pending_since).
    Pending ноды остаются в vless_tcp_working.json для повторного тестирования.
    """
    all_nodes = load_working_nodes()
    if not all_nodes:
        print("No nodes found.")
        return

    # Разделяем на active и pending
    active_nodes = [n for n in all_nodes if "_pending_since" not in n]
    pending_nodes = [n for n in all_nodes if "_pending_since" in n]

    if not active_nodes:
        print("No active nodes to export.")
        return

    # Нумеруем только active ноды
    active_nodes = renumber_nodes(active_nodes)

    # Сохраняем все ноды (active + pending)
    save_working_nodes(active_nodes + pending_nodes)

    if pending_nodes:
        print(f"Exporting {len(active_nodes)} active nodes ({len(pending_nodes)} pending kept)")
    else:
        print(f"Exporting {len(active_nodes)} nodes")

    # Экспорт только active
    if args.type == "tun":
        _export_tun(active_nodes, args.output)
    elif args.type == "router":
        _export_router(active_nodes, args.output)
    elif args.type == "all":
        _export_tun(active_nodes, args.output)
        _export_router(active_nodes, "config.json")
        _export_v2ray(active_nodes)
    else:
        print(f"Unknown export type: {args.type}")


def renumber_nodes(nodes: list[dict]) -> list[dict]:
    """Определяет страну, сортирует по флагу, назначает тэги node-1, node-2, ..."""
    # 1. Определяем страны для всех нод
    for node in nodes:
        country = resolve_country(node.get("server", ""))
        node["_country"] = country

    # 2. Сортируем по стране (флагу), затем по server:port
    nodes.sort(key=lambda o: (
        country_code_to_flag(o.get("_country", "")) or "",
        o.get("server", ""),
        o.get("server_port", 0),
    ))

    # 3. Нумерация
    for idx, node in enumerate(nodes, start=1):
        country = node.pop("_country", None)
        node.pop("_latency_ms", None)
        flag = country_code_to_flag(country) if country else ""
        node["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"
    return nodes


def _export_tun(nodes, output_file):
    """Экспорт в sing-box TUN конфиг."""
    from src.exporters.singbox_exporter import export_tun
    for n in nodes:
        clean_internal_fields(n)
    output_file = _resolve_output(output_file)
    export_tun(nodes, output_file)


def _export_router(nodes, output_file):
    """Экспорт в sing-box router конфиг."""
    from src.exporters.singbox_exporter import export_router
    for n in nodes:
        clean_internal_fields(n)
    output_file = _resolve_output(output_file)
    export_router(nodes, output_file)


def _resolve_output(output_file: str) -> str:
    """Решает абсолютный путь для выходного файла относительно корня проекта."""
    if os.path.isabs(output_file):
        return output_file
    root_dir = Path(PYTHON_DIR).parent
    return str((root_dir / output_file).resolve())


def _export_v2ray(nodes, output_file=None):
    """Экспорт в V2Ray-ссылки (vless_reality.txt в корне проекта)."""
    from src.exporters.v2ray_exporter import _generate_vless_reality_links
    if output_file is None:
        output_file = os.path.join(os.path.dirname(PYTHON_DIR), "vless_reality.txt")
    links = _generate_vless_reality_links(nodes)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"Exported {len(links)} VLESS nodes to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Manage VLESS Reality working nodes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vless_reality_manage.py run                     Full pipeline (merge+test+export)
  python vless_reality_manage.py merge                   Fetch new nodes from subscriptions
  python vless_reality_manage.py test                    Test all nodes
  python vless_reality_manage.py export --type all       Export only
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # run (default)
    run_parser = subparsers.add_parser("run", help="Full pipeline: merge -> test -> export")
    run_parser.add_argument("--ports", type=str, default=None,
                            help="Comma-separated port whitelist (default: all ports)")
    run_parser.add_argument("--timeout", type=int, default=10, help="Test timeout per node (seconds)")

    # merge
    merge_parser = subparsers.add_parser("merge", help="Fetch new nodes from subscriptions")
    merge_parser.add_argument("--ports", type=str, default=None,
                              help="Comma-separated port whitelist (default: all ports)")

    # test
    test_parser = subparsers.add_parser("test", help="Test all nodes and remove dead ones")
    test_parser.add_argument("--timeout", type=int, default=5, help="Test timeout per node (seconds)")

    # export
    export_parser = subparsers.add_parser("export", help="Export working nodes to sing-box config")
    export_parser.add_argument("--type", choices=["tun", "router", "all"], default="all", help="Export type")
    export_parser.add_argument("--output", default="vless_tcp_tun.json", help="Output file")

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
    main    