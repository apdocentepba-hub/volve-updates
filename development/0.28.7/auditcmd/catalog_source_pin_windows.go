//go:build windows

package main

// The initial VOLVE 0.28.6 Centro source ZIP is integrity-pinned in CI.
// The catalog motor embedded in THAT source has this exact SHA256. Matching
// it proves byte-for-byte equivalence to the pinned source, NOT an editor
// digital signature, active task owner, or DNS motor permission.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "io"
 "os"
 "path/filepath"
)

const sourceCatalogFilename="VOLVE_Motor_0210.exe"
const sourceCatalogSHA256="e296f8402af8b6b5e5f533bd8013df89027ca73adc7bc72e55f0174c72125a69"
const sourceCatalogArguments="--refresh"

type SourceCatalogStatus string
const (
 CatalogSourceNotInspected SourceCatalogStatus="NOT_INSPECTED"
 CatalogSourceMissing SourceCatalogStatus="FILE_MISSING"
 CatalogSourceUnknown SourceCatalogStatus="FILE_NOT_VERIFIABLE"
 CatalogSourceMismatch SourceCatalogStatus="DIFFERS_FROM_PINNED_0286_SOURCE"
 CatalogSourceMatched SourceCatalogStatus="EXACT_PINNED_0286_SOURCE_BYTES"
)

// verifyPinnedCatalogFileReadOnly never copies, launches or modifies the
// catalog motor. The path is derived solely from the Centro's trusted
// ProgramData root; it is NOT learned from the Task Scheduler action.
func verifyPinnedCatalogFileReadOnly(ctx context.Context,root string)(string,SourceCatalogStatus){
 if ctx.Err()!=nil{return "",CatalogSourceNotInspected}
 if root==""||!filepath.IsAbs(root)||filepath.Clean(root)!=root{return "",CatalogSourceUnknown}
 path:=filepath.Join(root,sourceCatalogFilename)
 before,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist){return "",CatalogSourceMissing}
 if err!=nil||!before.Mode().IsRegular()||before.Mode()&os.ModeSymlink!=0||
  before.Size()<128||before.Size()>128<<20{return "",CatalogSourceUnknown}
 f,err:=os.Open(path)
 if err!=nil{return "",CatalogSourceUnknown}
 h:=sha256.New()
 _,copyErr:=io.Copy(h,io.LimitReader(f,128<<20+1))
 closeErr:=f.Close()
 if copyErr!=nil||closeErr!=nil||ctx.Err()!=nil{return "",CatalogSourceUnknown}
 after,err:=os.Lstat(path)
 if err!=nil||!after.Mode().IsRegular()||after.Size()!=before.Size()||
  !after.ModTime().Equal(before.ModTime())||after.Mode()&os.ModeSymlink!=0{
  return "",CatalogSourceUnknown
 }
 if hex.EncodeToString(h.Sum(nil))!=sourceCatalogSHA256{return "",CatalogSourceMismatch}
 return path,CatalogSourceMatched
}
