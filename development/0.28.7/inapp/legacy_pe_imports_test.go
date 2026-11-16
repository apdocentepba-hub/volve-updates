package motorupdate

import (
	"bytes"
	"encoding/binary"
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
