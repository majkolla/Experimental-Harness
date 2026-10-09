## Static analyzer output for the changed files

Static analyzer output, changed files only, patched revision.

svc/files/download.go:19  [G304 medium] file inclusion via variable
svc/files/download.go:14  [imports]     "strings" added, used once

Baseline on the parent revision reported the same G304 finding at line 15. The
analyzer flags any os.Open whose argument is not a constant and does not model
the guard that precedes it, so this finding is advisory under the project's
suppression policy rather than blocking.

The build succeeds and `go vet` is clean on the patched revision. No new finding
classes appear. Total finding count is unchanged at 1 medium.
