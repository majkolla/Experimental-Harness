## Call sites reaching the modified function

Consumers of the download path construction in the 2.8 line.

svc/files/download.go:18   Download()        user-supplied name
svc/files/preview.go:44    Preview()         user-supplied name, calls safeJoin
svc/files/archive.go:97    ArchiveAll()      server-generated names only
svc/admin/fetch.go:60      AdminFetch()      admin token required, calls safeJoin

`safeJoin` lives in svc/files/paths.go and resolves the candidate path, then
compares it against the base directory using filepath.Rel. It was added when the
preview endpoint was written and has not been adopted by the download handler.

Download is registered on the public router at GET /files/download and requires
only a valid session cookie.
