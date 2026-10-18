from app.db.graph import parse_query_result


def test_parse_header_rows_stats_shape():
    raw = [
        ["n"],
        [[1]],
        ["Cached execution: 0", "Query internal execution time: 0.1 milliseconds"],
    ]
    assert parse_query_result(raw) == [{"n": 1}]


def test_parse_named_columns():
    raw = [["k"], [["npm:lodash@4.17.21"]], ["Nodes created: 1"]]
    assert parse_query_result(raw) == [{"k": "npm:lodash@4.17.21"}]
