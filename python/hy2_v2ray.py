"""Модуль экспорта Hysteria2 нод в формат V2Ray (ссылки) из рабочих нод."""

import sys
import os

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(PYTHON_DIR)
sys.path.insert(0, PYTHON_DIR)

from src.hy2_working import load_working_nodes
from src.exporters.v2ray_exporter import _generate_hy2_links


if __name__ == "__main__":
    nodes = load_working_nodes()
    if not nodes:
        print("No working nodes found. Run 'python hy2_manage.py test' or 'python hy2_manage.py merge' first.")
        sys.exit(1)

    # Очистка внутренних полей
    _INTERNAL_FIELDS = {"_latency_ms", "_last_ok_ts", "_country", "_status", "_pending_since"}
    for node in nodes:
        for key in _INTERNAL_FIELDS:
            node.pop(key, None)

    links = _generate_hy2_links(nodes)
    output_path = os.path.join(ROOT_DIR, "hy2.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"Exported {len(links)} Hysteria2 nodes to {output_path}")
