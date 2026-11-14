import pytest

from webvault.audit import audit_archives
from webvault.index.sqlite_index import record_audit, search_records
from webvault.web.app import create_app


@pytest.fixture
def client(built):
    report = audit_archives([built["archive"]], [built["cdx"]])
    record_audit(built["db"], report.to_dict())
    app = create_app(built["db"])
    app.config.update(TESTING=True)
    return app.test_client(), built


def test_archive_and_audit_pages(client):
    test_client, built = client
    response = test_client.get("/archives")
    assert response.status_code == 200
    assert b"archive.warc.gz" in response.data
    assert built["data"].info.sha256.encode()[:16] in response.data
    audit_page = test_client.get("/audit")
    assert audit_page.status_code == 200
    assert b"pass" in audit_page.data


def test_record_search_and_detail_preview(client):
    test_client, built = client
    page = test_client.get("/records?url=https://site-a.test/index.html")
    assert page.status_code == 200
    assert b"site-a.test/index.html" in page.data
    rows, _ = search_records(built["db"], url="https://site-a.test/index.html")
    detail = test_client.get(f"/records/{rows[0]['id']}")
    assert detail.status_code == 200
    assert b"HTTP response headers" in detail.data
    assert b"Body preview" in detail.data
    assert b"fixture" in detail.data
    assert test_client.get("/records/999999").status_code == 404


def test_bad_status_is_a_rendered_error(client):
    test_client, _ = client
    response = test_client.get("/records?status=oops")
    assert response.status_code == 200
    assert b"invalid literal" in response.data


def test_host_whitelist_and_read_only_endpoints(client):
    test_client, _ = client
    assert test_client.get("/archives", headers={"Host": "evil.test"}).status_code == 403
    assert test_client.get("/archives", headers={"Host": "localhost:5077"}).status_code == 200
    assert test_client.post("/records").status_code == 405
    assert test_client.get("/static/style.css").status_code == 200
    assert b"http://" not in test_client.get("/static/style.css").data


def test_home_redirects_to_archives(client):
    test_client, _ = client
    response = test_client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/archives")
