"""CLI-менеджер для управления рабочими нодами Hysteria2.

Команды:
  run     — полный pipeline: merge → test → export (по умолчанию)
  merge   — подтянуть новые ноды из подписок, добавить в hy2_working.json
  test    — протестировать все ноды из hy2_working.json, удалить нерабочие
  export  — сгенерировать sing-box конфиг из hy2_working.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PYTHON_DIR)

from src.hy2_working import (
    load_working_nodes,
    save_working_nodes,
    merge_new_nodes,
)
from src.common import (
    INTERNAL_FIELDS,
    clean_internal_fields,
    resolve_server,
    country_code_to_flag,
)
from src.rkn_filter import resolve_country


def cmd_merge(args):
    """Подтягивает новые ноды из подписок и добавляет в hy2_working.json.

    Использует run_pipeline() для fetch → parse → filter → DNS → dedup,
    затем сохраняет результат в hy2_working.json (без нумерации тэгов).
    """
    from src.orchestrator import run_pipeline
    from src.parsers import hy2_parser

    port_whitelist = tuple(int(p) for p in args.ports.split(","))

    # Кастомный export_func: сохраняет ноды в hy2_working.json без нумерации
    def _save_to_working(outbounds, _output_file):
        existing = load_working_nodes()
        merged, added = merge_new_nodes(existing, outbounds)
        print(f"Merge result: added {added} new nodes (total: {len(merged)})")
        save_working_nodes(merged)

    run_pipeline(
        parser_module="src.parsers.hy2_parser",
        exporter="tun",
        output_file="hy2_working.json",
        export_func=_save_to_working,
        protocol="hy2",
        tls_required=True,
        port_whitelist=port_whitelist,
        hy2_test=False,  # тестирование отдельно через cmd_test
    )


def cmd_test(args):
    """Тестирование всех нод из hy2_working.json."""
    from src.testers.hy2_node_tester import test_hy2_connectivity

    print("Loading nodes from hy2_working.json...")
    nodes = load_working_nodes()
    if not nodes:
        print("No nodes found. Run 'merge' first.")
        return

    now_ts = datetime.now(timezone.utc).timestamp()
    pending_nodes = [n for n in nodes if n.get("_status") == "pending"]
    active_nodes = [n for n in nodes if n.get("_status") != "pending"]

    print(f"Active: {len(active_nodes)}, Pending: {len(pending_nodes)}")

    all_to_test = active_nodes + pending_nodes
    working = test_hy2_connectivity(
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
            node.pop("_status", None)
            node.pop("_pending_since", None)
            new_working.append(node)
        elif node.get("_status") == "pending":
            print(f"  Removing failed pending node: {node.get('server')}:{node.get('server_port')}")
        else:
            node["_status"] = "pending"
            node["_pending_since"] = now_ts
            new_pending.append(node)

    save_working_nodes(new_working + new_pending)
    print(f"\nSaved {len(new_working)} working, {len(new_pending)} pending nodes to hy2_working.json")


def renumber_nodes(nodes: list[dict]) -> list[dict]:
    """Сортирует ноды по server:port и назначает тэги с флагом страны node-1, node-2, ..."""
    nodes.sort(key=lambda o: (o.get("server", ""), o.get("server_port", 0)))
    for idx, node in enumerate(nodes, start=1):
        node.pop("_country", None)
        node.pop("_latency_ms", None)
        # Определяем страну сервера
        country = resolve_country(node.get("server", ""))
        flag = country_code_to_flag(country) if country else ""
        node["tag"] = f"{flag}node-{idx}" if flag else f"node-{idx}"
    return nodes


def cmd_run(args):
    """Полный pipeline: merge -> test -> export."""
    port_whitelist = tuple(int(p) for p in args.ports.split(","))

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
    cmd_export(argparse.Namespace(type="all"))


def cmd_export(args):
    """Генерирует sing-box конфиг из hy2_working.json.

    Нумерация тэгов (node-1, node-2, ...) выполняется ОДИН РАЗ и сохраняется
    обратно в hy2_working.json — последующие экспортеры используют уже
    нумерованные ноды.
    """
    nodes = load_working_nodes()
    if not nodes:
        print("No working nodes found. Run 'test' or 'merge' first.")
        return

    # Единая нумерация — один раз
    nodes = renumber_nodes(nodes)
    save_working_nodes(nodes)

    # Экспорт
    if args.type == "tun":
        _export_tun(nodes, args.output)
    elif args.type == "router":
        _export_router(nodes, args.output)
    elif args.type == "all":
        _export_tun(nodes, args.output)
        _export_router(nodes, "config.json")
        _export_v2ray(nodes)
    else:
        print(f"Unknown export type: {args.type}")


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
    """Экспорт в V2Ray-ссылки (hy2.txt в корне проекта)."""
    from src.exporters.v2ray_exporter import _generate_hy2_links
    if output_file is None:
        output_file = os.path.join(os.path.dirname(PYTHON_DIR), "hy2.txt")
    links = _generate_hy2_links(nodes)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"Exported {len(links)} Hysteria2 nodes to {output_file}")


def _cache_key(node: dict) -> str:
    """Уникальный ключ для ноды: server:port:password."""
    return f"{node.get('server')}:{node.get('server_port')}:{node.get('password')}"


def main():
    parser = argparse.ArgumentParser(
        description="Manage Hysteria2 working nodes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hy2_manage.py run                     Full pipeline (merge+test+export)
  python hy2_manage.py merge                   Fetch new nodes from subscriptions
  python hy2_manage.py test                    Test all nodes
  python hy2_manage.py export --type all       Export only
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # run (default)
    run_parser = subparsers.add_parser("run", help="Full pipeline: merge -> test -> export")
    run_parser.add_argument("--ports", type=str, default="443,8443,2053,2083,2087,2096,4433",
                            help="Comma-separated port whitelist")
    run_parser.add_argument("--timeout", type=int, default=10, help="Test timeout per node (seconds)")

    # merge
    merge_parser = subparsers.add_parser("merge", help="Fetch new nodes from subscriptions")
    merge_parser.add_argument("--ports", type=str, default="443,8443,2053,2083,2087,2096,4433",
                              help="Comma-separated port whitelist")

    # test
    test_parser = subparsers.add_parser("test", help="Test all nodes and remove dead ones")
    test_parser.add_argument("--timeout", type=int, default=5, help="Test timeout per node (seconds)")

    # export
    export_parser = subparsers.add_parser("export", help="Export working nodes to sing-box config")
    export_parser.add_argument("--type", choices=["tun", "router", "all"], default="all", help="Export type")
    export_parser.add_argument("--output", default="hy2_tun.json", help="Output file")

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
