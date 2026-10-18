"""FalkorDB connectivity is probed over Redis GRAPH commands, not MCP."""

from app.db.falkordb import probe_falkordb


class _FakeRedis:
    def __init__(self, ping_ok=True, graph_list=None, ping_error=None, graph_error=None):
        self._ping_ok = ping_ok
        self._graph_list = graph_list if graph_list is not None else ["social"]
        self._ping_error = ping_error
        self._graph_error = graph_error

    def ping(self):
        if self._ping_error:
            raise self._ping_error
        return self._ping_ok

    def execute_command(self, *args):
        if self._graph_error:
            raise self._graph_error
        if args and args[0] == "GRAPH.LIST":
            return list(self._graph_list)
        raise AssertionError(f"unexpected command: {args}")


def test_probe_connected_when_ping_and_graph_list_succeed():
    result = probe_falkordb(_FakeRedis(graph_list=["social", "advanced"]))
    assert result.connected is True
    assert result.error is None
    assert "social" in result.graphs


def test_probe_disconnected_when_ping_fails():
    result = probe_falkordb(
        _FakeRedis(ping_error=ConnectionError("refused")),
    )
    assert result.connected is False
    assert result.error == "falkordb_unavailable"
    assert result.detail is not None
    assert "password" not in result.detail.lower()


def test_probe_disconnected_when_graph_commands_fail():
    result = probe_falkordb(
        _FakeRedis(graph_error=ResponseError("unknown command")),
    )
    assert result.connected is False
    assert result.error == "falkordb_unavailable"


class ResponseError(Exception):
    pass
