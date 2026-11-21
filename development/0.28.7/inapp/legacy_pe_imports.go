package motorupdate

import (
	"context"
	"encoding/binary"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"path/filepath"
	"sort"
	"strings"
)

const maxLegacyPEAuditBytes = 80 << 20

// ReadLegacyPEStaticImports lists DLL names recorded in the standard PE
// IMAGE_DIRECTORY_ENTRY_IMPORT table only. It does not parse the separate
// delay-load import directory (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT), resolve
// DLL search paths, inspect LoadLibrary/GetProcAddress, COM activation, script
// references, or certify a runtime dependency closure. A successful result
// therefore covers only regular imports, not every static PE dependency.
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

	var directories []pe.DataDirectory
	switch header := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		directories = header.DataDirectory[:]
	case *pe.OptionalHeader64:
		directories = header.DataDirectory[:]
	default:
		return nil, errors.New("unsupported PE optional header")
	}
	if len(directories) <= 1 {
		return []string{}, nil
	}
	dir := directories[1]
	if dir.VirtualAddress == 0 && dir.Size == 0 {
		return []string{}, nil
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 || dir.Size%20 != 0 {
		return nil, errors.New("malformed PE import directory bounds")
	}
	dirOffset, _, ok := legacyPERVAToFileRange(image.Sections, dir.VirtualAddress, dir.Size)
	if !ok || int64(dirOffset)+int64(dir.Size) > size {
		return nil, errors.New("PE import directory is outside section raw data")
	}

	unique := make(map[string]struct{})
	terminated := false
	for off := uint32(0); off < dir.Size; off += 20 {
		var descriptor [20]byte
		if _, err := input.ReadAt(descriptor[:], int64(dirOffset)+int64(off)); err != nil {
			return nil, fmt.Errorf("read PE import descriptor: %w", err)
		}
		zero := true
		for _, b := range descriptor {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			terminated = true
			break
		}
		nameRVA := binary.LittleEndian.Uint32(descriptor[12:16])
		if nameRVA == 0 {
			return nil, errors.New("PE import descriptor has no DLL name")
		}
		fileOffset, available, ok := legacyPERVAToFileRange(image.Sections, nameRVA, 1)
		if !ok || int64(fileOffset) >= size {
			return nil, errors.New("PE import DLL name is outside section raw data")
		}
		if available > 256 {
			available = 256
		}
		if int64(fileOffset)+int64(available) > size {
			available = uint32(size - int64(fileOffset))
		}
		nameBytes := make([]byte, available)
		n, readErr := input.ReadAt(nameBytes, int64(fileOffset))
		if readErr != nil && readErr != io.EOF {
			return nil, fmt.Errorf("read PE import DLL name: %w", readErr)
		}
		if n == 0 {
			return nil, errors.New("empty PE import DLL name")
		}
		nameBytes = nameBytes[:n]
		end := -1
		for i, b := range nameBytes {
			if b == 0 {
				end = i
				break
			}
			if b > 0x7e || b < 0x20 {
				return nil, errors.New("PE import DLL name is not printable ASCII")
			}
		}
		if end < 1 {
			return nil, errors.New("PE import DLL name is empty or unterminated")
		}
		name := string(nameBytes[:end])
		if strings.ContainsAny(name, "/\\") || filepath.Base(name) != name ||
			!strings.EqualFold(filepath.Ext(name), ".dll") {
			return nil, fmt.Errorf("unsafe or unsupported PE import name %q", name)
		}
		unique[strings.ToLower(name)] = struct{}{}
	}
	if !terminated {
		return nil, errors.New("PE import directory lacks a null descriptor")
	}
	result := make([]string, 0, len(unique))
	for name := range unique {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

// ReadLegacyPEDelayImports lists DLLs from IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
// (data directory 13). It accepts both modern RVA descriptors (Attributes=1)
// and the legacy VA form (Attributes=0), using the image base for conversion.
// This inventories DLL names only: it does not validate thunks, function
// exports, API-set/SxS forwarding, or runtime LoadLibrary/GetProcAddress.
// A malformed or unsupported directory fails closed.
func ReadLegacyPEDelayImports(input io.ReaderAt, size int64) ([]string, error) {
	if input == nil {
		return nil, errors.New("PE reader is missing")
	}
	if size < 64 || size > maxLegacyPEAuditBytes {
		return nil, fmt.Errorf("PE size outside audit bounds: %d", size)
	}
	image, err := pe.NewFile(io.NewSectionReader(input, 0, size))
	if err != nil {
		return nil, fmt.Errorf("invalid PE image: %w", err)
	}
	defer image.Close()

	var directory pe.DataDirectory
	var imageBase uint64
	var declaredDirs uint32
	switch header := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		directory = header.DataDirectory[13]
		imageBase = uint64(header.ImageBase)
		declaredDirs = header.NumberOfRvaAndSizes
	case *pe.OptionalHeader64:
		directory = header.DataDirectory[13]
		imageBase = header.ImageBase
		declaredDirs = header.NumberOfRvaAndSizes
	default:
		return nil, errors.New("unsupported PE optional header")
	}
	if declaredDirs <= 13 {
		if directory.VirtualAddress != 0 || directory.Size != 0 {
			return nil, errors.New("delay-import directory is not declared by PE header")
		}
		return []string{}, nil
	}
	if directory.VirtualAddress == 0 && directory.Size == 0 {
		return []string{}, nil
	}
	const descriptorBytes = 32
	const maxDescriptors = 4096
	if directory.VirtualAddress == 0 || directory.Size == 0 ||
		directory.Size%descriptorBytes != 0 ||
		directory.Size > (maxDescriptors+1)*descriptorBytes {
		return nil, errors.New("malformed PE delay-import directory bounds")
	}
	offset, _, ok := legacyPERVAToFileRange(image.Sections, directory.VirtualAddress, directory.Size)
	if !ok || uint64(offset)+uint64(directory.Size) > uint64(size) {
		return nil, errors.New("PE delay-import directory is outside section raw data")
	}

	unique := make(map[string]struct{})
	terminated := false
	for pos := uint32(0); pos < directory.Size; pos += descriptorBytes {
		var entry [descriptorBytes]byte
		n, readErr := input.ReadAt(entry[:], int64(offset)+int64(pos))
		if n != len(entry) || readErr != nil {
			return nil, fmt.Errorf("read PE delay-import descriptor: %v", readErr)
		}
		zero := true
		for _, b := range entry {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			terminated = true
			continue
		}
		if terminated {
			return nil, errors.New("PE delay-import directory has data after terminator")
		}
		attributes := binary.LittleEndian.Uint32(entry[0:4])
		if attributes &^ uint32(1) != 0 {
			return nil, errors.New("PE delay-import descriptor has reserved attribute bits")
		}
		nameAddress := uint64(binary.LittleEndian.Uint32(entry[4:8]))
		if nameAddress == 0 {
			return nil, errors.New("PE delay-import descriptor has no DLL name")
		}
		if attributes == 0 {
			if nameAddress < imageBase {
				return nil, errors.New("PE delay-import VA is below image base")
			}
			nameAddress -= imageBase
		}
		if nameAddress == 0 || nameAddress > uint64(^uint32(0)) {
			return nil, errors.New("PE delay-import DLL name RVA overflow")
		}
		nameOffset, available, ok := legacyPERVAToFileRange(image.Sections, uint32(nameAddress), 1)
		if !ok || int64(nameOffset) >= size {
			return nil, errors.New("PE delay-import DLL name is outside section raw data")
		}
		if available > 256 {
			available = 256
		}
		if int64(nameOffset)+int64(available) > size {
			available = uint32(size - int64(nameOffset))
		}
		rawName := make([]byte, available)
		n, readErr = input.ReadAt(rawName, int64(nameOffset))
		if n != len(rawName) || readErr != nil {
			return nil, fmt.Errorf("read PE delay-import DLL name: %v", readErr)
		}
		end := -1
		for i, b := range rawName {
			if b == 0 {
				end = i
				break
			}
			if b < 0x20 || b > 0x7e {
				return nil, errors.New("PE delay-import DLL name is not printable ASCII")
			}
		}
		if end < 1 {
			return nil, errors.New("PE delay-import DLL name is empty or unterminated")
		}
		name := string(rawName[:end])
		if strings.ContainsAny(name, "/\\") || filepath.Base(name) != name ||
			!strings.EqualFold(filepath.Ext(name), ".dll") {
			return nil, fmt.Errorf("unsafe or unsupported PE delay-import DLL name %q", name)
		}
		unique[strings.ToLower(name)] = struct{}{}
	}
	if !terminated {
		return nil, errors.New("PE delay-import directory lacks a null descriptor")
	}
	result := make([]string, 0, len(unique))
	for name := range unique {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

// legacyPERVAToFileRange maps an RVA range wholly contained in one section's
// raw bytes to a file offset. Virtual-only bytes are never treated as file data.
func legacyPERVAToFileRange(sections []*pe.Section, rva, length uint32) (uint32, uint32, bool) {
	if length == 0 {
		return 0, 0, false
	}
	for _, section := range sections {
		header := section.SectionHeader
		if rva < header.VirtualAddress {
			continue
		}
		delta := rva - header.VirtualAddress
		if delta >= header.Size || length > header.Size-delta {
			continue
		}
		offset64 := uint64(header.Offset) + uint64(delta)
		if offset64 > uint64(^uint32(0)) {
			return 0, 0, false
		}
		return uint32(offset64), header.Size - delta, true
	}
	return 0, 0, false
}

// NewLegacyPEAllowlistedResolver resolves each DLL only by a direct child
// lookup in caller-approved roots. It rejects ambiguous matches, symlinked
// roots/candidates, and roots whose resolved path differs from the supplied
// path. It deliberately does not emulate Windows search order or API-set
// forwarding; unresolved imports remain blockers for certification.
func NewLegacyPEAllowlistedResolver(roots []string) (LegacyPEImportResolver, error) {
	if len(roots) == 0 {
		return nil, errors.New("at least one approved PE dependency root is required")
	}
	approved := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return nil, fmt.Errorf("dependency root must be canonical and absolute: %q", root)
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("dependency root is not a trusted directory: %q", root)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil || !legacyPEPathEqual(root, resolved, info) {
			return nil, fmt.Errorf("dependency root traverses a link or alias: %q", root)
		}
		key := root
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate dependency root: %q", root)
		}
		seen[key] = struct{}{}
		approved = append(approved, root)
	}
	return func(importerPath, dllName string) (string, error) {
		if dllName == "" || strings.ContainsAny(dllName, "/\\") ||
			filepath.Base(dllName) != dllName ||
			!strings.EqualFold(filepath.Ext(dllName), ".dll") {
			return "", errors.New("invalid DLL name")
		}
		var matches []string
		for _, root := range approved {
			rootInfo, err := os.Lstat(root)
			if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("approved dependency root changed: %q", root)
			}
			resolvedRoot, err := filepath.EvalSymlinks(root)
			if err != nil || !legacyPEPathEqual(root, resolvedRoot, rootInfo) {
				return "", fmt.Errorf("approved dependency root now traverses a link: %q", root)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				return "", fmt.Errorf("read approved dependency root: %w", err)
			}
			for _, entry := range entries {
				if !strings.EqualFold(entry.Name(), dllName) {
					continue
				}
				candidate := filepath.Join(root, entry.Name())
				info, err := os.Lstat(candidate)
				if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
					return "", fmt.Errorf("DLL candidate is not a regular file: %q", candidate)
				}
				resolved, err := filepath.EvalSymlinks(candidate)
				if err != nil || !legacyPEPathEqual(candidate, resolved, info) {
					return "", fmt.Errorf("DLL candidate traverses a link or alias: %q", candidate)
				}
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 {
			return "", fmt.Errorf("expected one approved match for %q, found %d", dllName, len(matches))
		}
		return matches[0], nil
	}, nil
}

func legacyPEPathEqual(path, resolved string, info os.FileInfo) bool {
	// EvalSymlinks on Windows may expand a harmless 8.3 path (for example
	// RUNNER~1) to its long spelling. Compare filesystem identity there while
	// independently rejecting symlinks/reparse-like path components.
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		part, err := os.Lstat(current)
		if err != nil || part.Mode()&os.ModeSymlink != 0 {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil || !os.SameFile(info, resolvedInfo) {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return filepath.Clean(path) == filepath.Clean(resolved)
}

const maxLegacyPEClosureFiles = 256

type LegacyPEStaticImportFile struct {
	Path    string
	Size    int64
	SHA256  string
	Imports []string
	DelayImports []string
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

// AuditLegacyPEStaticImportClosure walks both regular imports (directory 1)
// and delay-load imports (directory 13) from each PE file. A complete result
// covers only these two declared DLL tables through the supplied resolver.
// RuntimeDependenciesCertified is always false: dynamic loading, API-set/SxS
// resolution, imports by function and non-PE references remain unverified.
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
		var delayed []string
		if parseErr == nil {
			delayed, parseErr = ReadLegacyPEDelayImports(file, info.Size())
		}
		if parseErr != nil {
			file.Close()
			if current.entry {
				return LegacyPEStaticImportClosure{}, parseErr
			}
			result.Unresolved = append(result.Unresolved, LegacyPEUnresolvedImport{
				Importer: filepath.Dir(current.path),
				DLL:      filepath.Base(current.path),
				Reason:   "resolved file contains malformed or unsupported PE imports",
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
			Path: current.path, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil)), Imports: imports, DelayImports: delayed,
		})
		// Both directory types participate in the dependency closure. Duplicates
		// within an image are resolved once, regardless of loading mode.
		declared := make(map[string]struct{}, len(imports)+len(delayed))
		for _, dll := range append(append([]string{}, imports...), delayed...) {
			if _, exists := declared[dll]; exists {
				continue
			}
			declared[dll] = struct{}{}
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
