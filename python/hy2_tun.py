"""Модуль сборки конфига Sing-box (TUN) из рабочих нод hy2_working.json."""

import sys
import os

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PYTHON_DIR)

from src.hy2_working import load_working_nodes
from src.exporters.singbox_exporter import export_tun


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

    export_tun(nodes, "hy2_tun.json")
