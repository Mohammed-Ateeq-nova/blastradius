from app.services.graph_ids import entry_key, file_key, package_key, vuln_key


def test_package_key_is_ecosystem_name_version():
    assert package_key("npm", "lodash", "4.17.21") == "npm:lodash@4.17.21"


def test_file_key_normalizes_separators_and_dots():
    assert file_key("demo-app", r"src\index.js") == "demo-app:src/index.js"
    assert file_key("demo-app", "./src/index.js") == "demo-app:src/index.js"


def test_file_key_rejects_parent_segments():
    raised = False
    try:
        file_key("demo-app", "../etc/passwd")
    except ValueError:
        raised = True
    assert raised


def test_vuln_and_entry_keys_are_stable():
    assert vuln_key("FIXTURE-LODASH-PROTOTYPE") == "vuln:FIXTURE-LODASH-PROTOTYPE"
    assert entry_key("demo-app", "src/index.js") == "demo-app:entry:src/index.js"
