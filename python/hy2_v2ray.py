"""Модуль экспорта Hysteria2 нод в формат V2Ray (ссылки) из рабочих нод."""

import sys
import os

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PYTHON_DIR)

from src.hy2_working import load_working_nodes
from src.exporters.v2ray_exporter import export_v2ray_by_type


if __name__ == "__main__":
    nodes = load_working_nodes()
    if not nodes:
        print("No working nodes found. Run 'python hy2_manage.py test' or 'python hy2_manage.py merge' first.")
        sys.exit(1)

    # Очистка внутренних полей
    for node in nodes:
        node.pop("_latency_ms", None)
        node.pop("_last_ok_ts", None)
        node.pop("_country", None)

    export_v2ray_by_type(nodes, "hy2")
