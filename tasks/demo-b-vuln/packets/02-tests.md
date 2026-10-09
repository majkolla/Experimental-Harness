## Existing test coverage for this module

svc/files/download_test.go, tests relevant to path handling.

func TestDownloadServesFile(t *testing.T) { ... expects 200 ... }

func TestDownloadRejectsDotDot(t *testing.T) {
    // requests ?name=../../etc/passwd
    // expects 400
}

func TestDownloadMissingFileIs404(t *testing.T) { ... expects 404 ... }

There is no test using an absolute `name`, a symlink inside the base directory,
or a percent-encoded traversal sequence. The suite passes on both the parent and
the patched revision. The preview handler has an equivalent table-driven test
with eleven cases including encoded and absolute inputs; the download handler
was never given the same treatment.
