"""Экспорт sing-box JSON (мобильный и роутер конфиги)."""

import json
from collections.abc import Callable

from .tun_config_builder import build_tun_config
from .router_config_builder import build_router_config


def export_tun(outbounds: list[dict], output_file: str = "output.json") -> int:
    """Экспортирует ноды в мобильный конфиг sing-box (tun)."""
    return _export(outbounds, output_file, build_tun_config, 20)


def export_router(outbounds: list[dict], output_file: str = "config.json") -> int:
    """Экспортирует ноды в роутер-конфиг sing-box."""
    return _export(outbounds, output_file, build_router_config, 100)


def _for_singbox(o: dict) -> dict:
    """Копия ноды в схеме sing-box: без внутренних `_`-полей и без полей, которых в sing-box нет
    (tls.reality.spider_x нужен только для ссылок/Xray — sing-box отвергает конфиг с ним)."""
    node = {k: v for k, v in o.items() if not k.startswith("_")}
    tls = node.get("tls")
    if isinstance(tls, dict) and isinstance(tls.get("reality"), dict) and "spider_x" in tls["reality"]:
        node["tls"] = {
            **tls,
            "reality": {k: v for k, v in tls["reality"].items() if k != "spider_x"},
        }
    return node


def _export(
    outbounds: list[dict],
    output_file: str,
    build_fn: Callable[[list[dict]], dict],
    speed_mbps: int = 20,
) -> int:
    """Общий экспорт: копии нод → speed settings → билд → запись на диск.

    Работаем с копиями: раньше ноды мутировались, и скорость первого экспорта (tun, 20)
    «залипала» в узлах, из-за чего router-конфиг получал 20 вместо 100, а ссылки — лишние поля.
    """
    nodes = [_for_singbox(o) for o in outbounds]
    for o in nodes:
        if o.get("type") == "hysteria2":
            o.setdefault("up_mbps", speed_mbps)
            o.setdefault("down_mbps", speed_mbps)

    singbox_config = build_fn(nodes)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)
    print(f"OK Successfully generated {output_file} with {len(nodes)} nodes.")
    return len(nodes)
