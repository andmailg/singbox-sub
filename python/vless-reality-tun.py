"""Модуль сборки и экспорта конфига Sing-box для VLESS reality нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_tcp_reality_parser",
        protocol="vless",
        exporter="tun",
        output_file="vless-reality-tun.json",
    )
