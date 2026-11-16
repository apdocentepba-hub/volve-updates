package motorupdate

import (
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const maxLegacyPEAuditBytes = 80 << 20

// ReadLegacyPEStaticImports lists DLL names recorded in a PE import table.
// It does not resolve DLL search paths, inspect LoadLibrary/GetProcAddress,
// COM activation, script references, or certify a dependency closure.
func ReadLegacyPEStaticImports(input io.ReaderAt, size int64) ([]string, error) {
	if input == nil {
		return nil, errors.New("PE reader is missing")
	}
	if size < 64 || size > maxLegacyPEAuditBytes {
		return nil, fmt.Errorf("PE size outside audit bounds: %d", size)
	}

	bounded := io.NewSectionReader(input, 0, size)
	image, err := pe.NewFile(bounded)
	if err != nil {
		return nil, fmt.Errorf("invalid PE image: %w", err)
	}
	defer image.Close()

	imports, err := image.ImportedLibraries()
	if err != nil {
		return nil, fmt.Errorf("PE import table is invalid: %w", err)
	}
	unique := make(map[string]struct{}, len(imports))
	for _, name := range imports {
		if name == "" || strings.ContainsAny(name, "/\\") ||
			filepath.Base(name) != name || !strings.EqualFold(filepath.Ext(name), ".dll") {
			return nil, fmt.Errorf("unsafe or unsupported PE import name %q", name)
		}
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("control character in PE import name")
			}
		}
		unique[strings.ToLower(name)] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for name := range unique {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}
