"""OSINT MCP package for counterparty intelligence and risk scoring."""

__all__ = ["main"]


def main() -> None:
    from osint_mcp.server import main as run_server

    run_server()
