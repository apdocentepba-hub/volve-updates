package motorupdate

import (
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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



const maxLegacyPEClosureFiles = 256

type LegacyPEStaticImportFile struct {
	Path    string
	Size    int64
	SHA256  string
	Imports []string
}

type LegacyPEUnresolvedImport struct {
	Importer string
	DLL      string
	Reason   string
}

type LegacyPEStaticImportClosure struct {
	Files                         []LegacyPEStaticImportFile
	Unresolved                    []LegacyPEUnresolvedImport
	StaticImportClosureComplete   bool
	RuntimeDependenciesCertified  bool
}

// LegacyPEImportResolver must resolve only within explicitly approved roots and
// reject reparse points, unsafe search-order locations, and ambiguous matches.
// The scanner rechecks the resolved path as a regular local file before reading.
type LegacyPEImportResolver func(importerPath, dllName string) (string, error)

// AuditLegacyPEStaticImportClosure walks the imports recorded in each PE file.
// A complete result means only that every statically declared import resolved
// through the supplied resolver. RuntimeDependenciesCertified is always false:
// dynamic loading and non-PE references require separate analysis.
func AuditLegacyPEStaticImportClosure(
	ctx context.Context,
	entryPath string,
	resolve LegacyPEImportResolver,
) (LegacyPEStaticImportClosure, error) {
	var result LegacyPEStaticImportClosure
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !filepath.IsAbs(entryPath) || filepath.Clean(entryPath) != entryPath {
		return result, errors.New("PE entry path must be canonical and absolute")
	}
	if resolve == nil {
		return result, errors.New("PE import resolver is required")
	}

	type pendingImage struct {
		path string
		entry bool
	}
	queue := []pendingImage{{path: entryPath, entry: true}}
	seen := make(map[string]struct{})
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return LegacyPEStaticImportClosure{}, err
		}
		current := queue[0]
		queue = queue[1:]
		key := strings.ToLower(filepath.Clean(current.path))
		if _, ok := seen[key]; ok {
			continue
		}
		if len(seen) >= maxLegacyPEClosureFiles {
			return LegacyPEStaticImportClosure{}, errors.New("PE static import closure exceeds file limit")
		}
		seen[key] = struct{}{}

		info, err := os.Lstat(current.path)
		if err != nil {
			if current.entry {
				return LegacyPEStaticImportClosure{}, fmt.Errorf("PE entry unavailable: %w", err)
			}
			result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
				Importer: filepath.Dir(current.path),
				DLL:      filepath.Base(current.path),
				Reason:   "resolved file could not be opened",
			})
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() < 64 || info.Size() > maxLegacyPEAuditBytes {
			if current.entry {
				return LegacyPEStaticImportClosure{}, errors.New("PE entry is not a bounded regular file")
			}
			result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
				Importer: filepath.Dir(current.path),
				DLL:      filepath.Base(current.path),
				Reason:   "resolved file is not a bounded regular file",
			})
			continue
		}

		file, err := os.Open(current.path)
		if err != nil {
			if current.entry {
				return LegacyPEStaticImportClosure{}, fmt.Errorf("PE entry open failed: %w", err)
			}
			result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
				Importer: filepath.Dir(current.path),
				DLL:      filepath.Base(current.path),
				Reason:   "resolved file open failed",
			})
			continue
		}
		before, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return LegacyPEStaticImportClosure{}, statErr
		}
		imports, parseErr := ReadLegacyPEStaticImports(file, info.Size())
		if parseErr != nil {
			file.Close()
			if current.entry {
				return LegacyPEStaticImportClosure{}, parseErr
			}
			result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
				Importer: filepath.Dir(current.path),
				DLL:      filepath.Base(current.path),
				Reason:   "resolved file is not a valid PE image",
			})
			continue
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, io.LimitReader(file, maxLegacyPEAuditBytes+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || afterErr != nil || closeErr != nil ||
			n != info.Size() || before.Size() != info.Size() || n > maxLegacyPEAuditBytes ||
			before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			if current.entry {
				return LegacyPEStaticImportClosure{}, errors.New("PE entry changed during dependency audit")
			}
			result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
				Importer: filepath.Dir(current.path),
				DLL:      filepath.Base(current.path),
				Reason:   "resolved file changed during dependency audit",
			})
			continue
		}
		result.Files = append(result.Files, LegacyPEStaticImportFile{
			Path: current.path, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil)), Imports: imports,
		})
		for _, dll := range imports {
			if err := ctx.Err(); err != nil {
				return LegacyPEStaticImportClosure{}, err
			}
			resolved, resolveErr := resolve(current.path, dll)
			if resolveErr != nil {
				result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
					Importer: current.path, DLL: dll, Reason: "resolver could not prove a unique safe path",
				})
				continue
			}
			if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
				result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
					Importer: current.path, DLL: dll, Reason: "resolver returned a non-canonical path",
				})
				continue
			}
			queue = append(queue, pendingImage{path: resolved})
		}
	}
	sort.Slice(result.Files, func(i, j int) bool {
		return strings.ToLower(result.Files[i].Path) < strings.ToLower(result.Files[j].Path)
	})
	sort.Slice(result.Unresolved, func(i, j int) bool {
		a, b := result.Unresolved[i], result.Unresolved[j]
		if strings.ToLower(a.Importer) != strings.ToLower(b.Importer) {
			return strings.ToLower(a.Importer) < strings.ToLower(b.Importer)
		}
		return strings.ToLower(a.DLL) < strings.ToLower(b.DLL)
	})
	result.StaticImportClosureComplete = len(result.Files) > 0 && len(result.Unresolved) == 0
	result.RuntimeDependenciesCertified = false
	return result, nil
}
