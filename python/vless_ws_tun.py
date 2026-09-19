"""Модуль сборки и экспорта конфига Sing-box для VLESS WS (RKN+GeoIP)."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.vless_ws_parser",
        protocol="vless",
        exporter="tun",
        output_file="vless_ws_tun.json",
    )
