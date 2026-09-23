"""Модуль сборки и экспорта конфига Sing-box для Trojan нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.trojan_parser",
        protocol="trojan",
        exporter="tun",
        output_file="trojan_tun.json",
        port_whitelist=(80, 8080, 2053, 2083, 2087, 2096, 4433),
    )
