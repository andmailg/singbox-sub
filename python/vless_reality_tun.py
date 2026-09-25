"""Модуль сборки и экспорта конфига Sing-box для VLESS reality нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_tcp_parser",
        protocol="vless",
        tls_required=True,
        reality=True,
        exporter="tun",
        output_file="vless_reality_tun.json",
    )
