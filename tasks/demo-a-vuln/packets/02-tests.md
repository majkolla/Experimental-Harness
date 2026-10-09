## Existing test coverage for this module

tests/api/test_reports.py, current contents relevant to sorting.

def test_list_default_sort(client):
    r = client.get("/reports")
    assert r.status_code == 200

def test_list_rejects_unknown_sort(client):
    r = client.get("/reports?sort=owner_id;--")
    assert r.status_code == 400

def test_export_returns_csv(client):
    r = client.get("/reports/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")

There is no test that passes a `sort` parameter to the export endpoint. The
suite runs green on both the parent revision and the patched revision. Coverage
for app/api/reports.py is reported as 91% of lines.
