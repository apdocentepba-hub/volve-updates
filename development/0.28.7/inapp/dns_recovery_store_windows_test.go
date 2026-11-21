//go:build windows

package motorupdate

import (
 "bytes"
 "context"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func makeStagedDNSFixture(t *testing.T)(string,[]byte,string) {
 t.Helper()
 parent:=filepath.Join(t.TempDir(),"legacy-engine-recovery")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 const guid="{12345678-1234-1234-1234-123456789abc}"
 states:=[]DNSServerState{
  {InterfaceGUID:guid,Family:DNSIPv6,Mode:DNSAutomatic},
  {InterfaceGUID:guid,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
 }
 raw,pin,err:=BuildDNSOriginalJournal(context.Background(),states)
 if err!=nil{t.Fatal(err)}
 return parent,raw,pin
}
func noopDNSBackupACL(string)error{return nil}

func TestDNSStagedBackupCreateOnlyAndExactReadBack(t *testing.T){
 parent,raw,pin:=makeStagedDNSFixture(t)
 report,err:=StoreDNSOriginalBackupUnarmed(context.Background(),parent,raw,pin,noopDNSBackupACL,noopDNSBackupACL)
 if err!=nil{t.Fatal(err)}
 if !report.FileVerified||!report.NTFSACLVerified||!report.CreateOnly||
  report.PerformedDNSWrites||report.InstallAuthorized||report.RestoreAuthorized{
  t.Fatalf("staged backup incorrectly issued a write permit: %+v",report)
 }
 records,err:=ReadStagedDNSOriginalBackupUnarmed(context.Background(),parent,pin,noopDNSBackupACL)
 if err!=nil||len(records)!=2{t.Fatalf("staged original DNS data could not be reverified: %v",err)}
 path:=filepath.Join(parent,DNSOriginalBackupDirectoryName,DNSOriginalBackupFileName)
 original,err:=os.ReadFile(path)
 if err!=nil||!bytes.Equal(raw,original){t.Fatal("original data not preserved")}
 if _,err:=StoreDNSOriginalBackupUnarmed(context.Background(),parent,raw,pin,noopDNSBackupACL,noopDNSBackupACL);err==nil{
  t.Fatal("create-only stage overwrote or accepted an existing backup")
 }
 after,err:=os.ReadFile(path)
 if err!=nil||!bytes.Equal(after,raw){t.Fatal("failed duplicate stage altered the original recovery data")}
}

func TestDNSStagedBackupRejectsUntrustedInputsBeforeWriting(t *testing.T){
 for _,name:=range []string{"wrong-pin","missing-pin","missing-acl","bad-parent","cancelled"}{
  t.Run(name,func(t *testing.T){
   parent,raw,pin:=makeStagedDNSFixture(t)
   seal,verify:=noopDNSBackupACL,noopDNSBackupACL
   ctx:=context.Background()
   switch name{
   case "wrong-pin":pin=strings.Repeat("0",64)
   case "missing-pin":pin=""
   case "missing-acl":verify=func(string)error{return errors.New("not protected")}
   case "bad-parent":parent=filepath.Dir(parent)
   case "cancelled":c,cancel:=context.WithCancel(ctx);cancel();ctx=c
   }
   if _,err:=StoreDNSOriginalBackupUnarmed(ctx,parent,raw,pin,seal,verify);err==nil{
    t.Fatal("invalid recovery inputs created an apparently trusted staging result")
   }
   expectedParent:=parent
   if name=="bad-parent"{expectedParent=filepath.Join(parent,"legacy-engine-recovery")}
   if _,err:=os.Lstat(filepath.Join(expectedParent,DNSOriginalBackupDirectoryName));!errors.Is(err,os.ErrNotExist){
    t.Fatalf("invalid inputs created a recovery folder: %v",err)
   }
  })
 }
}

func TestDNSStagedBackupNeverWritesPrivateDataBeforeDirectorySeal(t *testing.T){
 parent,raw,pin:=makeStagedDNSFixture(t)
 refused:=func(path string)error{
  if filepath.Base(path)==DNSOriginalBackupDirectoryName{return errors.New("NTFS DACL denied")}
  return nil
 }
 if _,err:=StoreDNSOriginalBackupUnarmed(context.Background(),parent,raw,pin,refused,noopDNSBackupACL);err==nil{
  t.Fatal("failed to stop when backup directory was not protected")
 }
 stage:=filepath.Join(parent,DNSOriginalBackupDirectoryName)
 if _,err:=os.Lstat(filepath.Join(stage,DNSOriginalBackupFileName));!errors.Is(err,os.ErrNotExist){
  t.Fatal("private DNS IPs written before protecting the parent directory")
 }
 if _,err:=StoreDNSOriginalBackupUnarmed(context.Background(),parent,raw,pin,noopDNSBackupACL,noopDNSBackupACL);err==nil{
  t.Fatal("existing failed stage was reused or silently repaired")
 }
}

func TestDNSStagedBackupRejectsTamperAndUnexpectedFiles(t *testing.T){
 parent,raw,pin:=makeStagedDNSFixture(t)
 if _,err:=StoreDNSOriginalBackupUnarmed(context.Background(),parent,raw,pin,noopDNSBackupACL,noopDNSBackupACL);err!=nil{t.Fatal(err)}
 stage:=filepath.Join(parent,DNSOriginalBackupDirectoryName)
 file:=filepath.Join(stage,DNSOriginalBackupFileName)
 if err:=os.WriteFile(file,[]byte("changed"),0600);err!=nil{t.Fatal(err)}
 if _,err:=ReadStagedDNSOriginalBackupUnarmed(context.Background(),parent,pin,noopDNSBackupACL);err==nil{
  t.Fatal("tampered private original DNS journal accepted")
 }
 if err:=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(stage,"untrusted.txt"),[]byte("extra"),0600);err!=nil{t.Fatal(err)}
 if _,err:=ReadStagedDNSOriginalBackupUnarmed(context.Background(),parent,pin,noopDNSBackupACL);err==nil{
  t.Fatal("unexpected file accepted in sealed DNS backup stage")
 }
}

func sealDNSBackupLabNode(ctx context.Context,path string)error{
 quoted:="'"+strings.ReplaceAll(path,"'","''")+"'"
 script:=`$ErrorActionPreference='Stop';$p=`+quoted+`;`+
  `$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');`+
  `$a=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');`+
  `$full=[Security.AccessControl.FileSystemRights]::FullControl;`+
  `$allow=[Security.AccessControl.AccessControlType]::Allow;`+
  `if([IO.Directory]::Exists($p)){`+
  `$acl=New-Object Security.AccessControl.DirectorySecurity;`+
  `$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;`+
  `foreach($sid in @($s,$a)){$r=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$flags,[Security.AccessControl.PropagationFlags]::None,$allow);$acl.AddAccessRule($r)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);[IO.Directory]::SetAccessControl($p,$acl)`+
  `}else{`+
  `$acl=New-Object Security.AccessControl.FileSecurity;`+
  `foreach($sid in @($s,$a)){$r=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);$acl.AddAccessRule($r)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);[IO.File]::SetAccessControl($p,$acl)`+
  `};Write-Output 'VOLVE_CI_DNS_BACKUP_SEALED'`
 ps:=filepath.Join(os.Getenv("SystemRoot"),"System32","WindowsPowerShell","v1.0","powershell.exe")
 output,err:=exec.CommandContext(ctx,ps,"-NoProfile","-NonInteractive","-Command",script).CombinedOutput()
 if err!=nil||strings.TrimSpace(string(output))!="VOLVE_CI_DNS_BACKUP_SEALED"{
  return errors.New("Windows native CI SYSTEM/Admin NTFS sealing failed")
 }
 return nil
}

func TestNativeWindowsDNSOriginalBackupRealNTFSAndCorruptedACL(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("only disposable GitHub-hosted Windows runner")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
 defer cancel()
 parent,raw,pin:=makeStagedDNSFixture(t)
 if err:=sealDNSBackupLabNode(ctx,parent);err!=nil{t.Fatal(err)}
 verify:=func(path string)error{
  token,err:=DefaultWindowsDNSProtectedACLInspect(ctx,path)
  if err!=nil{return err}
  if token!=windowsDNSProtectedACLToken{return errors.New("native owner/DACL not approved")}
  return nil
 }
 report,err:=StoreDNSOriginalBackupUnarmed(ctx,parent,raw,pin,
  func(path string)error{return sealDNSBackupLabNode(ctx,path)},verify)
 if err!=nil{t.Fatal(err)}
 if !report.FileVerified||!report.NTFSACLVerified||report.PerformedDNSWrites{
  t.Fatalf("native NTFS backup not verified: %+v",report)
 }
 if records,err:=ReadStagedDNSOriginalBackupUnarmed(ctx,parent,pin,verify);err!=nil||len(records)!=2{
  t.Fatalf("native sealed backup not independently readable: %v",err)
 }
 file:=filepath.Join(parent,DNSOriginalBackupDirectoryName,DNSOriginalBackupFileName)
 output,err:=exec.CommandContext(ctx,"icacls.exe",file,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("cannot weaken disposable Windows CI ACL: %v %s",err,string(output))}
 if _,err:=ReadStagedDNSOriginalBackupUnarmed(ctx,parent,pin,verify);err==nil{
  t.Fatal("original DNS backup accepted writable Everyone ACL after sealing")
 }
 t.Log("PASS VOLVE_NATIVE_NTFS_ORIGINAL_DNS_BACKUP_SEAL_AND_TAMPER_NO_DNS_WRITES")
}
