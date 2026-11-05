package unifiedbundle

// RequiredFiles returns a defensive copy of the required component allowlist.
// External callers cannot mutate the canonical list used for verification.
func RequiredFiles() map[string]string {
    files := make(map[string]string, len(requiredComponents))
    for id, name := range requiredComponents { files[id] = name }
    return files
}
