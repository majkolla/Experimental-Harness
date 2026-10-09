## Recent commit history touching these lines

git log --oneline -- svc/files/download.go (most recent first)

3c8f0aa  stream large files instead of buffering
b17d492  return 404 rather than 500 on missing file
e05a731  add download handler

svc/files/paths.go was added in commit 9d2c114 ("add safeJoin helper for
preview") and is used by preview.go and svc/admin/fetch.go. The download handler
predates that helper and was not migrated.

Issue 431 ("unify path resolution across file handlers") is open and references
both files. No security-prefixed commit appears in this file's history. The
project convention is that security fixes are tagged in the subject line.
