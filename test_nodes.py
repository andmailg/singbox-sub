import json
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Force UTF-8 encoding for Windows console
if sys.platform == "win32":
    os.environ["PYTHONUTF8"] = "1"
    import io
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")


def load_nodes(config_path: str) -> list[dict]:
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    nodes = []
    for outbound in config.get("outbounds", []):
        if outbound.get("type") == "hysteria2" and "server" in outbound:
            nodes.append(outbound)
    return nodes


def test_node_hy2cli(node: dict, timeout: int = 10) -> dict:
    """Test using hysteria CLI (hy2 client)."""
    server = node["server"]
    port = node["server_port"]
    password = node["password"]
    sni = node.get("tls", {}).get("server_name", "")
    tag = node.get("tag", f"{server}:{port}")

    cmd = [
        "hy2", "connect",
        f"{server}:{port}",
        "--protocol", "hy2",
        "--password", password,
        "--server-name", sni,
        "--timeout", str(timeout),
    ]

    start = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5
        )
        elapsed = time.time() - start
        success = result.returncode == 0
        output = (result.stdout or "") + (result.stderr or "")
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "OK" if success else "FAIL",
            "latency_ms": round(elapsed * 1000),
            "details": output.strip()[:200],
        }
    except subprocess.TimeoutExpired:
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "TIMEOUT",
            "latency_ms": timeout * 1000,
            "details": "Connection timed out",
        }
    except FileNotFoundError:
        return None  # hy2 not found


def test_node_tcp(node: dict, timeout: int = 5) -> dict:
    """Basic TCP connect test."""
    server = node["server"]
    port = node["server_port"]
    tag = node.get("tag", f"{server}:{port}")

    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.close()
        elapsed = time.time() - start
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "TCP-OPEN",
            "latency_ms": round(elapsed * 1000),
            "details": "TCP port open",
        }
    except socket.timeout:
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "TIMEOUT",
            "latency_ms": timeout * 1000,
            "details": "Connection timed out",
        }
    except ConnectionRefusedError:
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "REFUSED",
            "latency_ms": round((time.time() - start) * 1000),
            "details": "Connection refused",
        }
    except OSError as e:
        return {
            "tag": tag,
            "server": server,
            "port": port,
            "status": "ERROR",
            "latency_ms": round((time.time() - start) * 1000),
            "details": str(e),
        }


def format_table(results: list[dict]) -> str:
    lines = []
    header = f"{'Tag':<20} {'Server':<18} {'Port':<6} {'Status':<10} {'Latency':<10}"
    lines.append(header)
    lines.append("-" * len(header))
    for r in results:
        lines.append(
            f"{r['tag']:<20} {r['server']:<18} {r['port']:<6} {r['status']:<10} {r['latency_ms']}ms"
        )
    return "\n".join(lines)


def find_hy2() -> str | None:
    """Find hy2 CLI in common locations."""
    candidates = ["hy2", "hy2.exe"]
    # Check PATH
    for c in candidates:
        try:
            subprocess.run([c, "--version"], capture_output=True, timeout=5)
            return c
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check common local paths
    import os
    local_paths = [
        os.path.expanduser("~\\hy2.exe"),
        os.path.expanduser("~\\.hy2\\hy2.exe"),
        os.path.join(os.getcwd(), "hy2.exe"),
    ]
    for p in local_paths:
        if os.path.isfile(p):
            return p
    return None


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "hy2-tun.json"
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    print(f"Loading nodes from {config_path}...")
    nodes = load_nodes(config_path)
    print(f"Found {len(nodes)} Hysteria2 nodes")

    if not nodes:
        print("No Hysteria2 nodes found!")
        sys.exit(1)

    # Detect test method
    hy2_path = find_hy2()
    if hy2_path:
        print(f"Using hy2 CLI: {hy2_path}\n")
        test_fn = lambda n: test_node_hy2cli(n)
    else:
        print("hy2 CLI not found — using TCP connect test\n")
        test_fn = test_node_tcp

    # Parallel testing
    results = []
    start_all = time.time()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(test_fn, node): node for node in nodes}
        for i, future in enumerate(as_completed(futures), 1):
            node = futures[future]
            tag = node.get("tag", f"node-{i}")
            try:
                res = future.result()
                if res:
                    results.append(res)
                    status_icon = "✓" if res["status"] in ("OK", "TCP-OPEN") else "✗"
                    print(f"[{i}/{len(nodes)}] {tag}: {status_icon} {res['status']} — {res['latency_ms']}ms")
            except Exception as e:
                print(f"[{i}/{len(nodes)}] {tag}: ✗ ERROR — {e}")

    total = time.time() - start_all

    print(f"\n{'='*70}")
    print(format_table(results))

    # Summary
    ok = sum(1 for r in results if r["status"] in ("OK", "TCP-OPEN"))
    fail = len(results) - ok
    print(f"\nSummary: {ok} OK / {fail} FAIL — Total: {len(results)} — Time: {total:.1f}s")

    # Save results
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"node_test_{ts}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Results saved to {out_file}")


if __name__ == "__main__":
    main()
