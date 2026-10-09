## Static analyzer output for the changed files

Static analyzer output, changed files only, patched revision.

app/api/reports.py:26  [B608 medium] possible SQL injection: string-built query
app/api/reports.py:49  [B608 medium] possible SQL injection: string-built query
app/api/reports.py:21  [C901 low]    _valid_sort is trivially simple

Baseline on the parent revision reported the same two B608 findings at lines 24
and 47. The analyzer does not perform interprocedural taint tracking, so it
flags every f-string query regardless of whether the interpolated value has been
validated; the project's suppression policy therefore treats B608 as advisory
rather than blocking.

No new finding classes appear in the patched revision. Total finding count is
unchanged at 2 medium, 1 low.
