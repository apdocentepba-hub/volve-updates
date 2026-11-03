//go:build windows

package singlefile

// This is a separate, fail-closed Authenticode publisher gate for a FUTURE
// installer. The existing synthetic --verify-bundle lab command does not use
// it. Production needs publisher certificate pinning AND a trusted signed
// manifest/permit AND an exclusive, protected destination transaction.
import (
	"context"
	"encoding/base64"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const windowsCertTypePKCS7 = 0x0002
const windowsCertRevision2 = 0x0200

// VerifyWindowsPublisherSignature validates an EMBEDDED Authenticode code
// signature using the native Windows trust policy exposed by PowerShell's
// Get-AuthenticodeSignature. It also pins SHA256 of the DER leaf certificate
// and the complete PE bytes; caller-provided pins must come from a separate
// trusted editorial release, NEVER from the bundle being checked.
//
// This is a READ-ONLY gate. Reverify exact bytes after copying to a protected
// Windows installer directory and before execution; otherwise TOCTOU is open.
func VerifyWindowsPublisherSignature(ctx context.Context, exe, trustedCertDER256, trustedFileSHA256 string) error {
	certPin, err := decodePinnedSHA256(trustedCertDER256)
	if err != nil {
		return fmt.Errorf("pinned publisher certificate required: %w", err)
	}
	filePin, err := decodePinnedSHA256(trustedFileSHA256)
	if err != nil {
		return fmt.Errorf("pinned release executable hash required: %w", err)
	}
	if ctx == nil {
		return errors.New("non-nil verification context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(exe) || filepath.Clean(exe) != exe {
		return errors.New("noncanonical absolute Windows PE path required")
	}
	first, err := sha256RegularFile(exe)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(first[:], filePin) != 1 {
		return errors.New("Windows PE does not match approved release SHA256")
	}
	if err := requireEmbeddedPKCS7(exe); err != nil {
		return err
	}
	// Use a fixed script; the untrusted path is passed only as an environment
	// value and consumed by -LiteralPath (no command interpolation).
	// Status=Valid invokes Windows Authenticode trust policy and certificate
	// chain checking; merely seeing a SignerCertificate is NOT sufficient.
	const script = `$ErrorActionPreference='Stop';` +
		`$path=$env:VOLVE_PUBLISHER_VERIFY_FILE;` +
		`if([string]::IsNullOrWhiteSpace($path)){throw 'missing target'};` +
		`$s=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop;` +
		`if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate){throw 'Windows Authenticode trust failed'};` +
		`$alg=[Security.Cryptography.SHA256]::Create();` +
		`try{$hash=$alg.ComputeHash($s.SignerCertificate.GetRawCertData())}finally{$alg.Dispose()};` +
		`Write-Output ('VOLVE_AUTHENTICODE_CERT_SHA256='+[BitConverter]::ToString($hash).Replace('-','').ToLowerInvariant())`
	timeoutCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// PowerShell.exe -Command through Win32 argument quoting can misparse
	// multi-statement scripts invoked by Go. -EncodedCommand accepts UTF-16LE
	// Base64 and keeps the fixed, non-interpolated command intact.
	units := utf16.Encode([]rune(script))
	encodedScript := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encodedScript[i*2:], unit)
	}
	// A Go child process launched from pwsh 7 can inherit pwsh-7 modules
	// and fail autoloading Microsoft.PowerShell.Security under powershell.exe 5.
	// Pin the native WindowsPowerShell module directory; never search an
	// arbitrary caller-supplied PSModulePath for the trust-policy cmdlet.
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" || !filepath.IsAbs(systemRoot) {
		return errors.New("Windows system directory unavailable for publisher verification")
	}
	windowsPowerShell := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	modulePath := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "Modules")
	if info, err := os.Stat(modulePath); err != nil || !info.IsDir() {
		return errors.New("canonical Windows PowerShell security modules unavailable")
	}
	cmd := exec.CommandContext(timeoutCtx, windowsPowerShell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encodedScript))
	cmd.Env = append(os.Environ(), "PSModulePath="+modulePath, "VOLVE_PUBLISHER_VERIFY_FILE="+exe)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Diagnostics never weaken trust acceptance. Only a disposable CI VM
		// may expose bounded subprocess stderr to identify test harness bugs.
		if os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" {
			trace := strings.TrimSpace(string(out))
			if len(trace) > 1200 {
				trace = trace[:1200]
			}
			return fmt.Errorf("Windows Authenticode trust unavailable or invalid: %w; hosted-CI diagnostic=%q", err, trace)
		}
		return fmt.Errorf("Windows Authenticode trust unavailable or invalid: %w", err)
	}
	if len(out) > 512 {
		return errors.New("unexpected Authenticode trust output length")
	}
	report := strings.TrimSpace(string(out))
	const prefix = "VOLVE_AUTHENTICODE_CERT_SHA256="
	if !strings.HasPrefix(report, prefix) || len(report) != len(prefix)+64 || strings.ContainsAny(report, "\r\n") {
		return errors.New("ambiguous Windows Authenticode certificate result")
	}
	actual, err := decodePinnedSHA256(strings.TrimPrefix(report, prefix))
	if err != nil || subtle.ConstantTimeCompare(actual, certPin) != 1 {
		return errors.New("Windows Authenticode signer certificate not pinned publisher")
	}
	after, err := sha256RegularFile(exe)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(after[:], filePin) != 1 {
		return errors.New("Windows PE changed during publisher verification")
	}
	return ctx.Err()
}

func decodePinnedSHA256(s string) ([]byte, error) {
	if len(s) != 64 || strings.ToLower(s) != s {
		return nil, errors.New("expected exact lowercase SHA256 hex pin")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("invalid SHA256 pin")
	}
	return b, nil
}

func sha256RegularFile(path string) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	st, err := os.Lstat(path)
	if err != nil {
		return empty, err
	}
	if !st.Mode().IsRegular() {
		return empty, errors.New("signed file is not regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return empty, errors.New("signed file changed while opening")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<30)); err != nil {
		return empty, err
	}
	final, err := f.Stat()
	if err != nil || !os.SameFile(st, final) || final.Size() > 1<<30 {
		return empty, errors.New("signed file identity changed")
	}
	copy(empty[:], h.Sum(nil))
	return empty, nil
}

// A catalog-signed unsigned Windows binary is not a substitute for an
// embedded Authenticode certificate in the VOLVE Setup PE. Require a
// syntactically valid PE security directory and a PKCS#7 WIN_CERTIFICATE.
func requireEmbeddedPKCS7(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() < 512 || st.Size() > 1<<30 {
		return errors.New("PE size out of bounds")
	}
	hdr := make([]byte, 64)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return err
	}
	if string(hdr[:2]) != "MZ" {
		return errors.New("not a PE image")
	}
	ntOff := int64(binary.LittleEndian.Uint32(hdr[0x3c:0x40]))
	if ntOff < 64 || ntOff > 1<<20 || ntOff+24+240 > st.Size() {
		return errors.New("PE header offset unsafe")
	}
	pe := make([]byte, 24+240)
	if _, err := f.ReadAt(pe, ntOff); err != nil {
		return err
	}
	if string(pe[:4]) != "PE\x00\x00" {
		return errors.New("PE signature missing")
	}
	optSize := int(binary.LittleEndian.Uint16(pe[20:22]))
	opt := pe[24:]
	var secOff int
	switch binary.LittleEndian.Uint16(opt[:2]) {
	case 0x20b:
		secOff = 112 + 4*8
	case 0x10b:
		secOff = 96 + 4*8
	default:
		return errors.New("unknown Windows PE optional header")
	}
	if optSize < secOff+8 {
		return errors.New("PE security directory absent")
	}
	certOff := int64(binary.LittleEndian.Uint32(opt[secOff : secOff+4]))
	certSize := int64(binary.LittleEndian.Uint32(opt[secOff+4 : secOff+8]))
	if certOff < 512 || certOff%8 != 0 || certSize < 8 || certSize > 32<<20 || certOff+certSize != st.Size() {
		return errors.New("embedded certificate missing or malformed")
	}
	certHeader := make([]byte, 8)
	if _, err := f.ReadAt(certHeader, certOff); err != nil {
		return err
	}
	length := int64(binary.LittleEndian.Uint32(certHeader[:4]))
	rev := binary.LittleEndian.Uint16(certHeader[4:6])
	typ := binary.LittleEndian.Uint16(certHeader[6:8])
	if length < 8 || length > certSize || rev != windowsCertRevision2 || typ != windowsCertTypePKCS7 {
		return errors.New("not an embedded PKCS#7 Authenticode signature")
	}
	return nil
}
