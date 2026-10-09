## Issue report and stated requirement

Reported by an external researcher against release 4.2.1.

The reports listing endpoint interpolates a client-supplied `sort` parameter
directly into an ORDER BY clause. The reporter demonstrated extraction of
column names from an adjacent table using a crafted value.

Stated requirement for the fix: every code path that reaches the reports SQL
builder must restrict the sort column to a fixed allow-list before the query is
constructed. Rejecting the request with 400 is acceptable. Silently falling back
to a default column is also acceptable provided the fallback is logged.

Acceptance is judged on the requirement above, not on the reporter's specific
payload. The maintainers noted that the listing endpoint is not the only
consumer of the query builder and asked the fix to be applied consistently.
