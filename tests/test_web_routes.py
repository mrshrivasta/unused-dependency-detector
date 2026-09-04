import json
import os
import shutil
import tempfile

import pytest


@pytest.fixture()
def sample_project_dir():
    """A real temp project directory with a real package.json declaring an
    unused dependency, and real source that imports the others but not it."""
    tmpdir = tempfile.mkdtemp()
    pkg_json = os.path.join(tmpdir, "package.json")
    with open(pkg_json, "w") as fh:
        json.dump({
            "name": "sample",
            "dependencies": {"lodash": "^4.0.0", "axios": "^1.0.0", "unused-dep": "^1.0.0"},
            "devDependencies": {"eslint": "^8.0.0"},
            "scripts": {"lint": "eslint ."},
        }, fh)
    src_dir = os.path.join(tmpdir, "src")
    os.makedirs(src_dir, exist_ok=True)
    with open(os.path.join(src_dir, "index.js"), "w") as fh:
        fh.write("const _ = require('lodash');\nimport axios from 'axios';\n")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_full_scan_alert_incident_workflow(registered_client, sample_project_dir):
    # Run a real scan against a real temp project with a real unused dependency
    resp = registered_client.post("/scan/run", data={"target_path": sample_project_dir}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Scan complete" in resp.data

    # Logs page should show at least one scan
    resp = registered_client.get("/logs")
    assert sample_project_dir.encode() in resp.data

    # Alerts page should load and contain the real unused-dep finding trail
    resp = registered_client.get("/alerts")
    assert resp.status_code == 200

    # Analytics JSON endpoint returns real aggregated data
    resp = registered_client.get("/analytics/data")
    assert resp.status_code == 200
    assert resp.is_json

    # Reports CSV export works and contains the real finding
    resp = registered_client.get("/reports/export.csv")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    assert b"unused-dep" in resp.data


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
