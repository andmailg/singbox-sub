"""VLESS gRPC connectivity test functions for pipeline integration (Xray based).

Uses the shared Xray config builders from vless_node_tester since gRPC
transport is already handled in _build_stream_settings (network="grpc").
"""

from src.testers.vless_node_tester import (
    test_vless_node as test_vless_grpc_node,
    test_vless_connectivity as test_vless_grpc_connectivity,
)

__all__ = ["test_vless_grpc_node", "test_vless_grpc_connectivity"]
