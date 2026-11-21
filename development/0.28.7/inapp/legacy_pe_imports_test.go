package motorupdate

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func makeLegacyPEImportFixture(names ...string) []byte {
	const (
		peOffset = 0x80
		optStart = peOffset + 4 + 20
		optSize  = 224
		section  = optStart + optSize
		rawStart = 0x200
		rawSize  = 0x400
	)
	image := make([]byte, rawStart+rawSize)
	copy(image[:2], "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:], peOffset)
	copy(image[peOffset:peOffset+4], "PE\x00\x00")
	coff := peOffset + 4
	binary.LittleEndian.PutUint16(image[coff:], 0x14c)
	binary.LittleEndian.PutUint16(image[coff+2:], 1)
	binary.LittleEndian.PutUint16(image[coff+16:], optSize)
	binary.LittleEndian.PutUint16(image[coff+18:], 0x0102)
	binary.LittleEndian.PutUint16(image[optStart:], 0x10b)
	binary.LittleEndian.PutUint32(image[optStart+92:], 16)
	binary.LittleEndian.PutUint32(image[optStart+104:], 0x1000)
	binary.LittleEndian.PutUint32(image[optStart+108:], uint32((len(names)+1)*20))
	copy(image[section:section+8], ".rdata")
	binary.LittleEndian.PutUint32(image[section+8:], rawSize)
	binary.LittleEndian.PutUint32(image[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(image[section+16:], rawSize)
	binary.LittleEndian.PutUint32(image[section+20:], rawStart)

	nameOffset := rawStart + 0x80
	for i, name := range names {
		desc := rawStart + i*20
		binary.LittleEndian.PutUint32(image[desc+12:], uint32(0x1000+nameOffset-rawStart))
		copy(image[nameOffset:], append([]byte(name), 0))
		nameOffset += len(name) + 1
	}
	return image
}

func TestReadLegacyPEStaticImportsReturnsSortedUniqueDLLNames(t *testing.T) {
	fixture := makeLegacyPEImportFixture("USER32.DLL", "kernel32.dll", "user32.dll")
	got, err := ReadLegacyPEStaticImports(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kernel32.dll", "user32.dll"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("imports = %v, want %v", got, want)
	}
}

func TestReadLegacyPEStaticImportsRejectsUnsafeNamesAndMalformedImages(t *testing.T) {
	for _, name := range []string{"../helper.dll", "C:\\temp\\helper.dll", "helper.exe"} {
		t.Run(name, func(t *testing.T) {
			fixture := makeLegacyPEImportFixture(name)
			if _, err := ReadLegacyPEStaticImports(bytes.NewReader(fixture), int64(len(fixture))); err == nil {
				t.Fatal("unsafe or unsupported import name was accepted")
			}
		})
	}
	if _, err := ReadLegacyPEStaticImports(bytes.NewReader([]byte("not a PE")), 8); err == nil {
		t.Fatal("malformed image was accepted")
	}
	if _, err := ReadLegacyPEStaticImports(bytes.NewReader(make([]byte, 64)), maxLegacyPEAuditBytes+1); err == nil {
		t.Fatal("oversized image was accepted")
	}
}

func TestReadLegacyPEStaticImportsBoundsReaderToDeclaredImageSize(t *testing.T) {
	fixture := makeLegacyPEImportFixture("kernel32.dll")
	declared := int64(64)
	if _, err := ReadLegacyPEStaticImports(bytes.NewReader(fixture), declared); err == nil {
		t.Fatal("image data beyond declared size was read")
	}
}


func TestAuditLegacyPEStaticImportClosureRecursesAndHashes(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "entry.exe")
	helper := filepath.Join(root, "helper.dll")
	base := filepath.Join(root, "base.dll")
	for path, imports := range map[string][]string{
		entry:  {"helper.dll"},
		helper: {"base.dll"},
		base:   {},
	} {
		if err := os.WriteFile(path, makeLegacyPEImportFixture(imports...), 0600); err != nil {
			t.Fatal(err)
		}
	}
	resolve := func(importer, dll string) (string, error) {
		return filepath.Join(filepath.Dir(importer), dll), nil
	}
	got, err := AuditLegacyPEStaticImportClosure(context.Background(), entry, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StaticImportClosureComplete || got.RuntimeDependenciesCertified || len(got.Files) != 3 || len(got.Unresolved) != 0 {
		t.Fatalf("unexpected static closure result: %+v", got)
	}
	for _, file := range got.Files {
		if file.Size == 0 || len(file.SHA256) != 64 {
			t.Fatalf("missing exact file identity: %+v", file)
		}
	}
}

func TestAuditLegacyPEStaticImportClosureFailsClosedOnUnresolvedDLL(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "entry.exe")
	if err := os.WriteFile(entry, makeLegacyPEImportFixture("missing.dll"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := AuditLegacyPEStaticImportClosure(context.Background(), entry, func(string, string) (string, error) {
		return "", os.ErrNotExist
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.StaticImportClosureComplete || got.RuntimeDependenciesCertified || len(got.Unresolved) != 1 ||
		got.Unresolved[0].DLL != "missing.dll" {
		t.Fatalf("unresolved import did not block static closure: %+v", got)
	}
}

func TestAuditLegacyPEStaticImportClosureRejectsResolverTraversal(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "entry.exe")
	if err := os.WriteFile(entry, makeLegacyPEImportFixture("helper.dll"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := AuditLegacyPEStaticImportClosure(context.Background(), entry, func(string, string) (string, error) {
		return "relative/helper.dll", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.StaticImportClosureComplete || len(got.Unresolved) != 1 {
		t.Fatalf("unsafe resolver output accepted: %+v", got)
	}
}

func TestAuditLegacyPEStaticImportClosureUsesAllowlistedResolver(t *testing.T) {
	root := t.TempDir()
	deps := filepath.Join(root, "approved")
	if err := os.Mkdir(deps, 0700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(root, "entry.exe")
	helper := filepath.Join(deps, "helper.dll")
	if err := os.WriteFile(entry, makeLegacyPEImportFixture("helper.dll"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, makeLegacyPEImportFixture(), 0600); err != nil {
		t.Fatal(err)
	}
	resolve, err := NewLegacyPEAllowlistedResolver([]string{deps})
	if err != nil {
		t.Fatal(err)
	}
	got, err := AuditLegacyPEStaticImportClosure(context.Background(), entry, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StaticImportClosureComplete || got.RuntimeDependenciesCertified ||
		len(got.Files) != 2 || len(got.Unresolved) != 0 {
		t.Fatalf("allowlisted closure result = %+v", got)
	}
}

func TestAuditLegacyPEStaticImportClosureRejectsAmbiguousAllowlistedDLL(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	entry := filepath.Join(root, "entry.exe")
	if err := os.WriteFile(entry, makeLegacyPEImportFixture("helper.dll"), 0600); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{
		filepath.Join(first, "helper.dll"): makeLegacyPEImportFixture(),
		filepath.Join(second, "HELPER.DLL"): makeLegacyPEImportFixture(),
	} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	resolve, err := NewLegacyPEAllowlistedResolver([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := AuditLegacyPEStaticImportClosure(context.Background(), entry, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if got.StaticImportClosureComplete || len(got.Unresolved) != 1 ||
		got.Unresolved[0].DLL != "helper.dll" {
		t.Fatalf("ambiguous DLL match did not block closure: %+v", got)
	}
}

func TestNewLegacyPEAllowlistedResolverRejectsLinkedRoot(t *testing.T) {
	root := t.TempDir()
	realRoot := filepath.Join(root, "real")
	if err := os.Mkdir(realRoot, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Skipf("symlink creation unavailable in this environment: %v", err)
	}
	if _, err := NewLegacyPEAllowlistedResolver([]string{link}); err == nil {
		t.Fatal("linked dependency root was accepted")
	}
}


// makeLegacyPEDelayFixture creates an isolated PE32/PE32+ fixture. The
// descriptors use the current RVA format and do not execute loaded code.
func makeLegacyPEDelayFixture(pe64 bool, names ...string) []byte {
	const (
		peOffset = 0x80
		optStart = peOffset + 4 + 20
		rawStart = 0x200
		rawSize = 0x400
	)
	optSize := 224
	magic := uint16(0x10b)
	directoryAt := optStart + 200
	imageBase := uint64(0x400000)
	if pe64 {
		optSize = 240
		magic = 0x20b
		directoryAt = optStart + 216
		imageBase = 0x140000000
	}
	image := make([]byte, rawStart+rawSize)
	copy(image[:2], "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:], peOffset)
	copy(image[peOffset:], "PE\x00\x00")
	coff := peOffset + 4
	binary.LittleEndian.PutUint16(image[coff:], 0x14c)
	if pe64 {
		binary.LittleEndian.PutUint16(image[coff:], 0x8664)
	}
	binary.LittleEndian.PutUint16(image[coff+2:], 1)
	binary.LittleEndian.PutUint16(image[coff+16:], uint16(optSize))
	binary.LittleEndian.PutUint16(image[coff+18:], 0x0102)
	binary.LittleEndian.PutUint16(image[optStart:], magic)
	if pe64 {
		binary.LittleEndian.PutUint64(image[optStart+24:], imageBase)
		binary.LittleEndian.PutUint32(image[optStart+108:], 16)
	} else {
		binary.LittleEndian.PutUint32(image[optStart+28:], uint32(imageBase))
		binary.LittleEndian.PutUint32(image[optStart+92:], 16)
	}
	binary.LittleEndian.PutUint32(image[directoryAt:], 0x1180)
	binary.LittleEndian.PutUint32(image[directoryAt+4:], uint32((len(names)+1)*32))
	section := optStart + optSize
	copy(image[section:], ".rdata")
	binary.LittleEndian.PutUint32(image[section+8:], rawSize)
	binary.LittleEndian.PutUint32(image[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(image[section+16:], rawSize)
	binary.LittleEndian.PutUint32(image[section+20:], rawStart)
	namePos := rawStart + 0x280
	for i, name := range names {
		desc := rawStart + 0x180 + i*32
		binary.LittleEndian.PutUint32(image[desc:], 1)
		binary.LittleEndian.PutUint32(image[desc+4:], uint32(0x1000+namePos-rawStart))
		copy(image[namePos:], append([]byte(name), 0))
		namePos += len(name)+1
	}
	return image
}

func TestReadLegacyPEDelayImportsPE32PE64AndCaseFold(t *testing.T) {
	for _, pe64 := range []bool{false, true} {
		t.Run(map[bool]string{false:"PE32", true:"PE32+"}[pe64], func(t *testing.T) {
			fixture := makeLegacyPEDelayFixture(pe64, "USER32.DLL", "kernel32.dll", "user32.dll")
			got, err := ReadLegacyPEDelayImports(bytes.NewReader(fixture), int64(len(fixture)))
			if err != nil { t.Fatal(err) }
			want := []string{"kernel32.dll", "user32.dll"}
			if !reflect.DeepEqual(got, want) { t.Fatalf("delay imports = %v, want %v", got, want) }
		})
	}
}

func TestReadLegacyPEDelayImportsLegacyVAAndOverflow(t *testing.T) {
	const (optStart = 0x80 + 4 + 20; desc = 0x200 + 0x180)
	fixture := makeLegacyPEDelayFixture(false, "helper.dll")
	binary.LittleEndian.PutUint32(fixture[desc:], 0) // old VA-based form
	binary.LittleEndian.PutUint32(fixture[desc+4:], 0x401280)
	got, err := ReadLegacyPEDelayImports(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil || !reflect.DeepEqual(got, []string{"helper.dll"}) {
		t.Fatalf("old VA delay import rejected: %v, %v", got, err)
	}
	binary.LittleEndian.PutUint32(fixture[optStart+28:], 0x500000)
	if _, err := ReadLegacyPEDelayImports(bytes.NewReader(fixture), int64(len(fixture))); err == nil {
		t.Fatal("VA below PE image base was accepted")
	}
}

func TestReadLegacyPEDelayImportsRejectsMalformedDescriptors(t *testing.T) {
	const (
		optStart = 0x80 + 4 + 20
		desc = 0x200 + 0x180
		dirAt = optStart + 200
	)
	cases := []struct{
		name string
		change func([]byte)
	}{
		{"reserved attribute bits", func(b []byte) { binary.LittleEndian.PutUint32(b[desc:], 3) }},
		{"missing name", func(b []byte) { binary.LittleEndian.PutUint32(b[desc+4:], 0) }},
		{"name RVA beyond raw section", func(b []byte) { binary.LittleEndian.PutUint32(b[desc+4:], 0x1fff) }},
		{"directory outside raw section", func(b []byte) { binary.LittleEndian.PutUint32(b[dirAt:], 0x1fff) }},
		{"directory size misaligned", func(b []byte) { binary.LittleEndian.PutUint32(b[dirAt+4:], 31) }},
		{"no null descriptor", func(b []byte) { binary.LittleEndian.PutUint32(b[dirAt+4:], 32) }},
		{"directory undeclared", func(b []byte) { binary.LittleEndian.PutUint32(b[optStart+92:], 13) }},
		{"oversized descriptor table", func(b []byte) { binary.LittleEndian.PutUint32(b[dirAt+4:], 4098*32) }},
		{"unsafe path", func(b []byte) { copy(b[0x200+0x280:], []byte("../bad.dll\x00")) }},
		{"unsupported extension", func(b []byte) { copy(b[0x200+0x280:], []byte("bad.exe\x00")) }},
		{"non ASCII name", func(b []byte) { b[0x200+0x280] = 0xff }},
		{"unterminated name", func(b []byte) {
			binary.LittleEndian.PutUint32(b[desc+4:], 0x13c0)
			for i := 0x200+0x3c0; i < len(b); i++ { b[i] = 'A' }
		}},
		{"data after null terminator", func(b []byte) {
			binary.LittleEndian.PutUint32(b[dirAt+4:], 96)
			binary.LittleEndian.PutUint32(b[desc+64:], 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := makeLegacyPEDelayFixture(false, "helper.dll")
			tc.change(fixture)
			if got, err := ReadLegacyPEDelayImports(bytes.NewReader(fixture), int64(len(fixture))); err == nil {
				t.Fatalf("malformed delay imports accepted: %v", got)
			}
		})
	}
	if _, err := ReadLegacyPEDelayImports(nil, 64); err == nil { t.Fatal("nil reader accepted") }
	if _, err := ReadLegacyPEDelayImports(bytes.NewReader(makeLegacyPEDelayFixture(false)), maxLegacyPEAuditBytes+1); err == nil {
		t.Fatal("oversized PE accepted")
	}
	fixture := makeLegacyPEDelayFixture(false, "helper.dll")
	if _, err := ReadLegacyPEDelayImports(bytes.NewReader(fixture), 64); err == nil {
		t.Fatal("PE directory beyond declared reader size was accepted")
	}
}

func TestAuditLegacyPEStaticImportClosureIncludesDelayedTransitiveDLLs(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root,"entry.exe")
	helper := filepath.Join(root,"helper.dll")
	base := filepath.Join(root,"base.dll")
	for name, data := range map[string][]byte{
		entry: makeLegacyPEDelayFixture(false, "helper.dll"),
		helper: makeLegacyPEImportFixture("base.dll"),
		base: makeLegacyPEImportFixture(),
	} {
		if err := os.WriteFile(name, data, 0600); err != nil { t.Fatal(err) }
	}
	resolve := func(importer, dll string) (string,error) {
		return filepath.Join(filepath.Dir(importer),dll),nil
	}
	got, err := AuditLegacyPEStaticImportClosure(context.Background(),entry,resolve)
	if err != nil { t.Fatal(err) }
	if !got.StaticImportClosureComplete || got.RuntimeDependenciesCertified || len(got.Files) != 3 || len(got.Unresolved) != 0 {
		t.Fatalf("delay-loaded transitive DLL not inventoried: %+v",got)
	}
	var entryFound bool
	for _, f := range got.Files {
		if f.Path == entry {
			entryFound = true
			if !reflect.DeepEqual(f.DelayImports, []string{"helper.dll"}) { t.Fatalf("missing delayed DLL: %+v",f) }
		}
	}
	if !entryFound { t.Fatal("entry PE not included in closure") }
}

func TestAuditLegacyPEStaticImportClosureFailsClosedOnDelayedDLL(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root,"entry.exe")
	if err := os.WriteFile(entry,makeLegacyPEDelayFixture(true,"missing.dll"),0600); err != nil { t.Fatal(err) }
	got, err := AuditLegacyPEStaticImportClosure(context.Background(),entry,
		func(string,string)(string,error){ return "",os.ErrNotExist })
	if err != nil { t.Fatal(err) }
	if got.StaticImportClosureComplete || got.RuntimeDependenciesCertified ||
		len(got.Unresolved) != 1 || got.Unresolved[0].DLL != "missing.dll" {
		t.Fatalf("missing delay DLL incorrectly certified: %+v",got)
	}
}
