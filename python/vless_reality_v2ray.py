"""Модуль экспорта VLESS reality нод в формат V2Ray (ссылки)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_tcp_reality_parser",
        protocol="vless",
        exporter="v2ray",
        output_file="vless_reality.txt",
    )
