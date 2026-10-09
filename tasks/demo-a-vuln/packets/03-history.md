## Recent commit history touching these lines

git log --oneline -- app/api/reports.py (most recent first)

a91c4e2  split export handler out of list_reports (3.9.0)
7f2b118  add CSV streaming for large exports
2d0ac57  cache report counts for the dashboard
55e19bb  accept sort parameter on the listing endpoint
c40d7a9  initial reports API

The 3.9 split copied the query construction rather than extracting it, which is
why two nearly identical f-string queries exist. A follow-up refactor to share
one builder was proposed in issue 812 and deferred.

No revert or security fix appears in this file's history. The repository's
convention is that security fixes carry a `security:` prefix in the subject
line; none is present here.
