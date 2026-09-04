"""Tests for the Security Engine and Detection Rules.

Two layers:
1. Rule-level unit tests against synthetic context dicts (fast, isolated).
2. Genuine engine-level tests that create REAL temporary directories with
   REAL package.json / requirements.txt manifests and REAL .js/.py source
   files on disk, then run the REAL ScanEngine (no mocking of the engine).
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import (
    normalize,
    rule_unused_runtime_dependency,
    rule_unused_dev_dependency,
    rule_dependency_in_both_categories,
    rule_undeclared_import_used,
    rule_dependency_bloat_ratio,
    rule_no_manifest_found,
)


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_normalize_folds_dashes_and_dots():
    assert normalize("Foo-Bar") == "foo_bar"
    assert normalize("some.pkg") == "some_pkg"
    assert normalize(" Mixed-Case.Name ") == "mixed_case_name"
    assert normalize("") == ""


def test_rule_unused_runtime_dependency_flags_unimported():
    ctx = {
        "declared_runtime": {"lodash", "unused-pkg"},
        "declared_dev": set(),
        "imported_names": {"lodash"},
    }
    findings = rule_unused_runtime_dependency(ctx)
    ids = {f["package_name"] for f in findings}
    assert ids == {"unused-pkg"}
    assert findings[0]["rule_id"] == "UDD-001"
    assert findings[0]["severity"] == "medium"


def test_rule_unused_runtime_dependency_no_findings_when_all_used():
    ctx = {"declared_runtime": {"axios"}, "declared_dev": set(), "imported_names": {"axios"}}
    assert rule_unused_runtime_dependency(ctx) == []


def test_rule_unused_dev_dependency_flags_unreferenced():
    ctx = {
        "declared_dev": {"eslint", "unused-dev-tool"},
        "imported_names": set(),
        "scripts_text": "eslint . --fix",
    }
    findings = rule_unused_dev_dependency(ctx)
    names = {f["package_name"] for f in findings}
    assert names == {"unused-dev-tool"}
    assert findings[0]["rule_id"] == "UDD-002"


def test_rule_unused_dev_dependency_credits_script_reference():
    ctx = {"declared_dev": {"jest"}, "imported_names": set(), "scripts_text": "jest --coverage"}
    assert rule_unused_dev_dependency(ctx) == []


def test_rule_dependency_in_both_categories():
    ctx = {"declared_runtime": {"lodash"}, "declared_dev": {"lodash", "eslint"}}
    findings = rule_dependency_in_both_categories(ctx)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "UDD-003"
    assert findings[0]["package_name"] == "lodash"


def test_rule_undeclared_import_used_flags_phantom_dependency():
    ctx = {
        "ecosystem": "javascript",
        "declared_runtime": {"axios"},
        "declared_dev": set(),
        "imported_names": {"axios", "left-pad"},
    }
    findings = rule_undeclared_import_used(ctx)
    names = {f["package_name"] for f in findings}
    assert names == {"left-pad"}
    assert findings[0]["rule_id"] == "UDD-004"


def test_rule_undeclared_import_used_ignores_builtins():
    ctx = {
        "ecosystem": "python",
        "declared_runtime": set(),
        "declared_dev": set(),
        "imported_names": {"os", "sys", "json"},
    }
    assert rule_undeclared_import_used(ctx) == []


def test_rule_dependency_bloat_ratio_triggers_over_threshold():
    ctx = {
        "declared_runtime": {"a", "b", "c", "d", "e", "f"},
        "declared_dev": set(),
        "imported_names": {"a"},
    }
    findings = rule_dependency_bloat_ratio(ctx)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "UDD-005"


def test_rule_dependency_bloat_ratio_no_finding_when_balanced():
    ctx = {"declared_runtime": {"a", "b"}, "declared_dev": set(), "imported_names": {"a", "b"}}
    assert rule_dependency_bloat_ratio(ctx) == []


def test_rule_no_manifest_found():
    assert rule_no_manifest_found({"ecosystem": "none"}) != []
    assert rule_no_manifest_found({"ecosystem": "javascript"}) == []


# ---------------------------------------------------------------------------
# Genuine engine-level tests — real temp dirs, real files, real ScanEngine
# ---------------------------------------------------------------------------

def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def test_js_project_flags_unused_runtime_dependency_and_not_used_ones():
    tmpdir = tempfile.mkdtemp()
    try:
        _write(os.path.join(tmpdir, "package.json"), json.dumps({
            "name": "demo",
            "dependencies": {"lodash": "^4.0.0", "axios": "^1.0.0", "unused-pkg": "^1.0.0"},
            "devDependencies": {"eslint": "^8.0.0"},
            "scripts": {"lint": "eslint ."},
        }))
        _write(os.path.join(tmpdir, "src", "index.js"), (
            "const _ = require('lodash');\n"
            "import axios from 'axios';\n"
            "console.log(_.isEmpty, axios);\n"
        ))

        engine = ScanEngine(tmpdir, max_depth=4)
        result = engine.run()

        rule_ids = {(f["rule_id"], f.get("permissions_octal")) for f in result["findings"]}
        assert ("UDD-001", "unused-pkg") in rule_ids
        assert not any(fid == "UDD-001" and pkg == "lodash" for fid, pkg in rule_ids)
        assert not any(fid == "UDD-001" and pkg == "axios" for fid, pkg in rule_ids)
        assert result["files_scanned"] >= 2  # package.json + index.js
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_js_project_flags_undeclared_import_and_dev_dependency_dup():
    tmpdir = tempfile.mkdtemp()
    try:
        _write(os.path.join(tmpdir, "package.json"), json.dumps({
            "dependencies": {"lodash": "^4.0.0"},
            "devDependencies": {"lodash": "^4.0.0"},
        }))
        _write(os.path.join(tmpdir, "src", "app.js"), "import lodash from 'lodash';\nimport leftpad from 'left-pad';\n")

        engine = ScanEngine(tmpdir, max_depth=4)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "UDD-003" in rule_ids  # lodash declared in both categories
        assert "UDD-004" in rule_ids  # left-pad imported but undeclared
    finally:
        shutil.rmtree(tmpdir)


def test_python_project_flags_unused_requirement():
    tmpdir = tempfile.mkdtemp()
    try:
        _write(os.path.join(tmpdir, "requirements.txt"), "requests==2.31.0\nunused-lib>=1.0\n")
        _write(os.path.join(tmpdir, "app.py"), "import requests\n\nrequests.get('http://example.com')\n")

        engine = ScanEngine(tmpdir, max_depth=4)
        result = engine.run()
        rule_ids = {(f["rule_id"], f.get("permissions_octal")) for f in result["findings"]}
        assert ("UDD-001", "unused-lib") in rule_ids
        assert not any(fid == "UDD-001" and pkg == "requests" for fid, pkg in rule_ids)
    finally:
        shutil.rmtree(tmpdir)


def test_no_manifest_produces_udd_006_and_no_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        _write(os.path.join(tmpdir, "notes.txt"), "just some notes")
        engine = ScanEngine(tmpdir, max_depth=4)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "UDD-006" in rule_ids
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_node_modules_excluded_from_source_walk():
    tmpdir = tempfile.mkdtemp()
    try:
        _write(os.path.join(tmpdir, "package.json"), json.dumps({"dependencies": {"lodash": "^4.0.0"}}))
        _write(os.path.join(tmpdir, "node_modules", "somepkg", "index.js"), "require('should-not-count');\n")
        _write(os.path.join(tmpdir, "src", "index.js"), "require('lodash');\n")

        engine = ScanEngine(tmpdir, max_depth=6)
        result = engine.run()
        # 'should-not-count' must never appear as an import since node_modules is excluded
        assert not any(
            f.get("permissions_octal") == "should-not-count" for f in result["findings"]
        )
    finally:
        shutil.rmtree(tmpdir)


def test_malformed_package_json_counts_as_error_not_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        _write(os.path.join(tmpdir, "package.json"), "{ this is not valid json ")
        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        assert result["errors_count"] >= 1
        assert isinstance(result["findings"], list)
    finally:
        shutil.rmtree(tmpdir)
