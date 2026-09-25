"""Модуль экспорта VLESS reality нод в формат V2Ray (ссылки)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_tcp_parser",
        protocol="vless",
        tls_required=True,
        reality=True,
        exporter="v2ray",
        output_file="vless_tcp.txt",
    )
