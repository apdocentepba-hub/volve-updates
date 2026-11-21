//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

// The native adapter MUST really invoke the Windows SID-based owner+DACL
// verifier; tests don't provide substitute seal/protect callbacks.
func TestNativeDNSBackupUsesRealNTFSAndSurvivesIndependentReopen(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("requires disposable GitHub-hosted Windows NTFS runner")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),105*time.Second)
 defer cancel()
 parent,raw,pin:=makeStagedDNSFixture(t)
 if err:=sealDNSBackupLabNode(ctx,parent);err!=nil{t.Fatal(err)}
 report,err:=StoreDNSOriginalBackupNativeWindows(ctx,parent,raw,pin)
 if err!=nil{t.Fatal(err)}
 if !report.CreateOnly||!report.FileVerified||!report.NTFSACLVerified||
  report.PerformedDNSWrites||report.InstallAuthorized||report.RestoreAuthorized{
  t.Fatalf("native backup incorrectly authorized DNS mutation: %+v",report)
 }
 records,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,pin)
 if err!=nil||len(records)!=2{t.Fatalf("separate native backup read-back refused: %v",err)}
 if records[0].Original.Mode!=DNSStatic||len(records[0].Original.Servers)!=2||
  records[1].Original.Mode!=DNSAutomatic{
  t.Fatalf("native backup original IPv4/IPv6 configuration not preserved: %+v",records)
 }
 if _,err:=StoreDNSOriginalBackupNativeWindows(ctx,parent,raw,pin);err==nil{
  t.Fatal("native Windows adapter overwrote a sealed previous DNS backup")
 }
 // Weakening the real Windows ACL must invalidate even a correct hash.
 file:=filepath.Join(parent,DNSOriginalBackupDirectoryName,DNSOriginalBackupFileName)
 out,err:=exec.CommandContext(ctx,"icacls.exe",file,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("unable to test unsafe NTFS ACL: %v %s",err,string(out))}
 if _,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,pin);err==nil{
  t.Fatal("native Windows restore reader accepted a writable Everyone ACE")
 }
 t.Log("PASS VOLVE_NATIVE_DNS_BACKUP_REAL_WINDOWS_ACL_SEAL_REOPEN_NO_DNS_TASK_WRITES")
}

func TestNativeDNSBackupRejectsUnsealedParentBeforeWritingPrivateData(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("requires disposable GitHub-hosted Windows runner")
 }
 parent,raw,pin:=makeStagedDNSFixture(t)
 if _,err:=StoreDNSOriginalBackupNativeWindows(context.Background(),parent,raw,pin);err==nil{
  t.Fatal("native backup accepted inherited/unprotected Windows parent DACL")
 }
 stage:=filepath.Join(parent,DNSOriginalBackupDirectoryName)
 if _,err:=os.Lstat(stage);!errors.Is(err,os.ErrNotExist){
  t.Fatalf("native backup created stage before verifying recovery parent: %v",err)
 }
}

func TestNativeDNSBackupRejectsBadPinAndUnrelatedSealTargets(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("requires disposable GitHub-hosted Windows runner")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second)
 defer cancel()
 parent,raw,_:=makeStagedDNSFixture(t)
 if err:=sealDNSBackupLabNode(ctx,parent);err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupNativeWindows(ctx,parent,raw,strings.Repeat("f",64));err==nil{
  t.Fatal("native backup accepted untrusted external original DNS digest")
 }
 if _,err:=os.Lstat(filepath.Join(parent,DNSOriginalBackupDirectoryName));!errors.Is(err,os.ErrNotExist){
  t.Fatal("untrusted external hash created original DNS recovery stage")
 }
 unrelated:=filepath.Join(parent,"legacy-motor.exe")
 if err:=os.WriteFile(unrelated,[]byte("unchanged"),0600);err!=nil{t.Fatal(err)}
 if err:=nativeSealNewDNSOriginalNode(ctx,parent,unrelated);err==nil{
  t.Fatal("native backup sealer accepted unrelated original motor path")
 }
 contents,err:=os.ReadFile(unrelated)
 if err!=nil||string(contents)!="unchanged"{t.Fatal("unrelated original file mutated")}
}
