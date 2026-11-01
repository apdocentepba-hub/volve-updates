//go:build windows

package motorupdate

// A conservative, read-only inventory of an EXISTING trusted installation
// root. The caller must get this root from its privileged installed-root
// resolver, never from the candidate installer, release metadata or a UI
// string. This is one preflight signal, NOT a signed identity attestation.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

type WindowsFreshMotorFileInventory struct {
 LegacyExecutablePresent bool
 VersionedMotorPresent bool
 InstalledEngineInventoryPresent bool
 MotorCandidates []string
 MotorSHA256 map[string]string
}

// lstatAllExistingParents rejects junction/symlink components before reading
// the installation. Rejects a missing root: absence of a trusted root is NOT
// proof of a clean Windows host.
func lstatAllExistingParents(root string) error {
 if root=="" || !filepath.IsAbs(root) || filepath.Clean(root)!=root ||
   filepath.VolumeName(root)==root || strings.Contains(root,"\x00") {
  return errors.New("installation root must be a canonical absolute directory")
 }
 volume:=filepath.VolumeName(root)
 first:=volume+string(os.PathSeparator)
 if volume=="" {return errors.New("installation root lacks Windows volume")}
 current:=first
 rest:=strings.TrimPrefix(root,first)
 if rest==root {return errors.New("invalid Windows drive root")}
 for _,name:=range strings.Split(rest,string(os.PathSeparator)){
  if name=="" {continue}
  current=filepath.Join(current,name)
  info,err:=os.Lstat(current)
  if err!=nil {return fmt.Errorf("installation ancestor cannot be inspected: %w",err)}
  if info.Mode()&os.ModeSymlink!=0 || !info.IsDir(){
   return errors.New("installation root/ancestor is linked, reparse-mapped or not directory")
  }
 }
 return nil
}

func scanFreshMotorFile(ctx context.Context,root,name string,result *WindowsFreshMotorFileInventory) error {
 if err:=ctx.Err();err!=nil{return err}
 if name=="" || name=="." || name==".." || filepath.Base(name)!=name ||
   strings.ContainsAny(name,"\x00/\\") {
  return errors.New("unsafe motor inventory filename")
 }
 path:=filepath.Join(root,name)
 stat,err:=os.Lstat(path)
 if err!=nil{return err}
 if stat.Mode()&os.ModeSymlink!=0 || !stat.Mode().IsRegular(){
  return errors.New("motor-like entry is linked or not a regular file")
 }
 if stat.Size()<1 || stat.Size()>1<<31 {
  return errors.New("motor-like executable has implausible size")
 }
 file,err:=os.Open(path);if err!=nil{return err}
 hash:=sha256.New()
 _,copyErr:=io.Copy(hash,file)
 closeErr:=file.Close()
 if copyErr!=nil{return copyErr}
 if closeErr!=nil{return closeErr}
 after,err:=os.Lstat(path)
 if err!=nil{return err}
 if !after.Mode().IsRegular() || after.Size()!=stat.Size() || !after.ModTime().Equal(stat.ModTime()) {
  return errors.New("motor executable changed while inventorying")
 }
 result.MotorCandidates=append(result.MotorCandidates,path)
 result.MotorSHA256[path]=hex.EncodeToString(hash.Sum(nil))
 return nil
}

// InspectWindowsFreshMotorFilesReadOnly does not trust an empty/missing file
// inventory, nor discover executable version from file names. Every direct
// VOLVE_DNS_*.exe, every engine folder and the legacy canonical executable
// counts as potential existing protection and prevents a clean install.
// This does not discover arbitrary copies outside the trusted install root;
// the independent task/service/port checks are mandatory as well.
func InspectWindowsFreshMotorFilesReadOnly(ctx context.Context,root string) (WindowsFreshMotorFileInventory,error) {
 var zero WindowsFreshMotorFileInventory
 if err:=ctx.Err();err!=nil{return zero,err}
 if err:=lstatAllExistingParents(root);err!=nil{return zero,err}
 entries,err:=os.ReadDir(root)
 if err!=nil{return zero,err}
 if len(entries)>8192{return zero,errors.New("installation root excessively large")}
 result:=WindowsFreshMotorFileInventory{MotorSHA256:map[string]string{}}
 seen:=map[string]bool{}
 for _,entry:=range entries{
  if err:=ctx.Err();err!=nil{return zero,err}
  name:=entry.Name()
  key:=strings.ToLower(name)
  if seen[key]{return zero,errors.New("ambiguous case-colliding installation entries")}
  seen[key]=true
  // Protect data roots even if they are empty: a stale receipt or pending
  // versioned engine may not yet contain an executable.
  if key=="installed-engines" {
   info,e:=os.Lstat(filepath.Join(root,name))
   if e!=nil || !info.IsDir() || info.Mode()&os.ModeSymlink!=0 {
    return zero,errors.New("installed-engine inventory is not a normal directory")
   }
   result.InstalledEngineInventoryPresent=true
   continue
  }
  if strings.HasPrefix(key,"motor-") {
   info,e:=os.Lstat(filepath.Join(root,name))
   if e!=nil || !info.IsDir() || info.Mode()&os.ModeSymlink!=0{
    return zero,errors.New("motor version directory is not safe")
   }
   result.VersionedMotorPresent=true
   continue
  }
  if strings.HasPrefix(key,"volve_dns_") && strings.HasSuffix(key,".exe") {
   if err:=scanFreshMotorFile(ctx,root,name,&result);err!=nil{return zero,err}
   if key=="volve_dns_server_0270.exe" || strings.HasPrefix(key,"volve_dns_server_") {
    result.LegacyExecutablePresent=true
   }else{
    result.VersionedMotorPresent=true
   }
  }
 }
 return result,nil
}
