## Call sites reaching the modified function

Search for consumers of the reports query builder in release 4.2.1.

app/api/reports.py:24   list_reports()      ORDER BY {sort}
app/api/reports.py:47   export_reports()    ORDER BY {sort}
app/jobs/digest.py:81   nightly_digest()    ORDER BY created_at    (constant)
app/admin/views.py:150  admin_report_list() ORDER BY {sort}        (admin-only)

Both `list_reports` and `export_reports` are reachable by any authenticated
user. `export_reports` is registered at GET /reports/export and takes the same
query string parameters as the listing endpoint; the two handlers were split in
3.9 and have drifted since. `admin_report_list` is behind a role check.

The nightly digest job passes a hard-coded column and is not attacker
influenced.
