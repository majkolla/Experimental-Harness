## Adjacent module that shares the same sink

app/admin/views.py, the adjacent consumer of the same sink.

@bp.get("/admin/reports")
@require_role("admin")
def admin_report_list():
    sort = request.args.get("sort", "created_at")
    if sort not in ALLOWED_SORTS:
        sort = "created_at"
    rows = session.execute(
        f"SELECT id, title, owner_id FROM reports ORDER BY {sort}"
    ).fetchall()
    return render("admin/reports.html", rows=rows)

ALLOWED_SORTS is defined in app/admin/constants.py as a frozenset of four
column names. This handler predates the reported issue and uses a fallback
rather than a 400. It is behind a role check, so the maintainers consider it out
of scope for the reported issue, but it is the closest existing example of the
project's preferred style for this validation.
