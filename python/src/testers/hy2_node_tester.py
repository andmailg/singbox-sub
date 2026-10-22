"""Hysteria 2 connectivity test functions for pipeline integration."""

import os
import tempfile

from src.testers._proc import Child, probe_socks, release_port, reserve_port, run_connectivity




def _hy2_build_yaml(node: dict, local_port: int) -> str:
    """Генерирует YAML-конфигурацию для Hysteria 2 client на основе ноды."""
    server = node["server"]
    port = node["server_port"]
    password = node["password"]
    sni = node.get("tls", {}).get("server_name", "")
    tls_cfg = node.get("tls", {})
    obfs_cfg = node.get("obfs", {})

    def _esc(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    lines = [
        "server: " + _esc(f"{server}:{port}"),
        "auth: " + _esc(password),
        "tls:",
    ]

    if sni:
        lines.append("  sni: " + _esc(sni))

    if "pinSHA256" not in tls_cfg:
        lines.append("  insecure: true")

    if obfs_cfg and obfs_cfg.get("type"):
        obfs_type = obfs_cfg["type"]
        lines.append("obfs:")
        if obfs_type == "salamander":
            lines.append("  type: salamander")
            lines.append("  salamander:")
            lines.append("    password: " + _esc(obfs_cfg.get("password", "")))
        elif obfs_type == "gecko":
            lines.append("  type: gecko")
            lines.append("  gecko:")
            lines.append("    password: " + _esc(obfs_cfg.get("password", "")))
            min_pkt = obfs_cfg.get("min_packet_size")
            max_pkt = obfs_cfg.get("max_packet_size")
            if min_pkt is not None:
                lines.append("    min_packet_size: " + str(min_pkt))
            if max_pkt is not None:
                lines.append("    max_packet_size: " + str(max_pkt))

    up = node.get("up_mbps")
    down = node.get("down_mbps")
    if up is not None or down is not None:
        lines.append("bandwidth:")
        if up is not None:
            lines.append("  up: " + str(up) + " mbps")
        if down is not None:
            lines.append("  down: " + str(down) + " mbps")

    lines.append("socks5:")
    lines.append("  listen: 127.0.0.1:" + str(local_port))
    lines.append("log:")
    lines.append("  level: error")

    return "\n".join(lines) + "\n"


def test_hy2_node(node: dict, timeout: int = 5) -> dict | str | None:
    """
    Тестирует одну Hysteria2 ноду на работоспособность.
    Возвращает node с полем "_latency_ms" при успехе, иначе строку с причиной провала.
    """
    local_port = reserve_port()
    config_path = None
    child = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as cf:
            cf.write(_hy2_build_yaml(node, local_port))
            config_path = cf.name

        child = Child(["hy2", "client", "-c", config_path])
        # hy2 открывает SOCKS5-порт только после подключения к серверу, поэтому окно больше
        error = child.wait_ready(local_port, timeout=15.0, label="hy2 client")
        if error:
            return error
        return probe_socks(local_port, timeout, node)
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        if child:
            child.close()
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass
        release_port(local_port)


def test_hy2_connectivity(
    outbounds: list[dict],
    timeout: int = 5,
    prefix: str = "",
) -> tuple[list[dict], int, str]:
    """Проверяет работоспособность Hysteria2 нод через hy2 CLI + curl (только рабочие ноды)."""
    return run_connectivity(outbounds, test_hy2_node, "hy2", "hy2", timeout, prefix)
