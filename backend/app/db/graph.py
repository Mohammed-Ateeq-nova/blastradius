from __future__ import annotations

from typing import Any


def _literal(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def cypher_prefix(params: dict[str, Any] | None) -> str:
    if not params:
        return ""
    assigned = " ".join(f"{key}={_literal(value)}" for key, value in params.items())
    return f"CYPHER {assigned} "


def parse_query_result(raw: Any) -> list[dict[str, Any]]:
    """Parse FalkorDB GRAPH.QUERY payload: [header, [rows...], stats]."""
    if not raw or not isinstance(raw, list) or len(raw) < 2:
        return []
    header = raw[0]
    records = raw[1]
    if not isinstance(header, list) or not isinstance(records, list):
        return []
    if records and not isinstance(records[0], list):
        return []
    return [
        {str(header[i]): row[i] if i < len(row) else None for i in range(len(header))}
        for row in records
        if isinstance(row, list)
    ]


class FalkorGraph:
    """Direct FalkorDB GRAPH.QUERY access. Not MCP."""

    def __init__(self, client, graph_name: str):
        self.client = client
        self.graph_name = graph_name

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        full = cypher_prefix(params) + cypher
        raw = self.client.execute_command("GRAPH.QUERY", self.graph_name, full)
        return parse_query_result(raw)

    def delete(self) -> None:
        try:
            self.client.execute_command("GRAPH.DELETE", self.graph_name)
        except Exception:
            pass
