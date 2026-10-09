## Adjacent module that shares the same sink

svc/files/paths.go, the helper the other handlers use.

func safeJoin(base, name string) (string, error) {
    full := filepath.Clean(filepath.Join(base, name))
    rel, err := filepath.Rel(base, full)
    if err != nil {
        return "", err
    }
    if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
        return "", errOutsideBase
    }
    if filepath.IsAbs(rel) {
        return "", errOutsideBase
    }
    return full, nil
}

This is the project's established containment check: resolve first, then prove
the resolved path is under the base. preview.go and svc/admin/fetch.go both call
it. It is the closest existing example of the maintainers' preferred style.
