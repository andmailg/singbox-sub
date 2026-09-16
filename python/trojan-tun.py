"""Модуль сборки и экспорта конфига Sing-box для Trojan нод."""

from src.orchestrator import run_pipeline


if __name__ == "__main__":
    run_pipeline(
        parser_module="src.parsers.trojan_parser",
        protocol="hy2",
        exporter="tun",
        output_file="trojan-tun.json",
    )
