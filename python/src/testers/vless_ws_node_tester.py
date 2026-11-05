"""VLESS WebSocket connectivity test functions for pipeline integration (Xray based).

Uses the shared Xray config builders from vless_node_tester: WebSocket transport
(network="ws", wsSettings.path/headers.Host) and TLS are already handled in
_build_stream_settings.
"""

from src.testers.vless_node_tester import (
    test_vless_node as test_vless_ws_node,
    test_vless_connectivity as test_vless_ws_connectivity,
)

__all__ = ["test_vless_ws_node", "test_vless_ws_connectivity"]
