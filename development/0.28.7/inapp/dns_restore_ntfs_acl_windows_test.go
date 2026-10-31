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

func fixtureWindowsDNSProtectedACL(t *testing.T)(string,string) {
 t.Helper()
 root:=t.TempDir()
 parent:=filepath.Join(root,"legacy-engine-recovery")
 dir:=filepath.Join(parent,"motor-recovery-transaction")
 if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,ResidentIntentFile),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 snapshot:=filepath.Join(parent,WindowsDNSRecoverySnapshotName)
 if err:=os.WriteFile(snapshot,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 return dir,snapshot
}

func sealWindowsDNSFixtureACL(t *testing.T,dir,snapshot string){
 t.Helper()
 paths:=[]string{filepath.Dir(dir),dir,filepath.Join(dir,ResidentIntentFile),snapshot}
 quote:=func(s string)string{return "'"+strings.ReplaceAll(s,"'","''")+"'"}
 literals:=make([]string,0,len(paths))
 for _,path:=range paths{literals=append(literals,quote(path))}
 script:=`$ErrorActionPreference='Stop';`+
  `$paths=@(`+strings.Join(literals,",")+`);`+
  `$a=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');`+
  `$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');`+
  `$full=[Security.AccessControl.FileSystemRights]::FullControl;`+
  `$allow=[Security.AccessControl.AccessControlType]::Allow;`+
  `foreach($p in $paths){`+
  `if([IO.Directory]::Exists($p)){`+
  `$acl=New-Object Security.AccessControl.DirectorySecurity;`+
  `$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;`+
  `foreach($sid in @($s,$a)){$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$flags,[Security.AccessControl.PropagationFlags]::None,$allow);$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);[IO.Directory]::SetAccessControl($p,$acl)`+
  `}else{`+
  `$acl=New-Object Security.AccessControl.FileSecurity;`+
  `foreach($sid in @($s,$a)){$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);[IO.File]::SetAccessControl($p,$acl)`+
  `}`+
  `};Write-Output 'CI_NTFS_SEALED'`
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
 defer cancel()
 out,err:=exec.CommandContext(ctx,"powershell.exe","-NoProfile","-NonInteractive","-Command",script).CombinedOutput()
 if err!=nil||strings.TrimSpace(string(out))!="CI_NTFS_SEALED"{
  t.Fatalf("could not construct isolated SYSTEM/Admin NTFS ACL fixture: %v, %q",err,string(out))
 }
}

func TestWindowsDNSNTFSVerifierPathsAndMissingSecurity(t *testing.T){
 dir,snapshot:=fixtureWindowsDNSProtectedACL(t)
 count:=0
 fake:=func(ctx context.Context,path string)(string,error){
  count++
  return windowsDNSProtectedACLToken,nil
 }
 gate,err:=NewWindowsDNSProtectedACLVerifier(context.Background(),dir,snapshot,fake)
 if err!=nil{t.Fatal(err)}
 for _,path:=range []string{filepath.Dir(dir),dir,filepath.Join(dir,ResidentIntentFile),snapshot}{
  if err:=gate(path);err!=nil{t.Fatalf("legitimate resident ACL path rejected: %v",err)}
 }
 if count!=4{t.Fatalf("inspector not invoked for every expected path, got %d",count)}
 for _,bad:=range []string{filepath.Join(dir,"not-allowed"),filepath.Dir(filepath.Dir(dir)),
  dir+string(filepath.Separator)+".."+string(filepath.Separator)+"dns-restore-snapshot.json",""}{
  if err:=gate(bad);err==nil{t.Fatalf("unrelated NTFS path allowed: %q",bad)}
 }
 if err:=gate(filepath.Join(dir,ResidentResultFile));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("absent terminal journal file unexpectedly trusted: %v",err)
 }
 if _,err:=NewWindowsDNSProtectedACLVerifier(context.Background(),
  filepath.Dir(dir),snapshot,fake);err==nil{t.Fatal("invalid resident journal tree accepted")}
 if _,err:=NewWindowsDNSProtectedACLVerifier(context.Background(),
  dir,filepath.Join(dir,"wrong.json"),fake);err==nil{t.Fatal("arbitrary DNS snapshot location accepted")}
 if _,err:=NewWindowsDNSProtectedACLVerifier(context.Background(),dir,snapshot,nil);err==nil{
  t.Fatal("missing NTFS security inspector accepted")
 }
 if err:=gate(dir);err!=nil{t.Fatal(err)}
 badGate,err:=NewWindowsDNSProtectedACLVerifier(context.Background(),dir,snapshot,
  func(context.Context,string)(string,error){return "ACL UNKNOWN",nil})
 if err!=nil{t.Fatal(err)}
 if err:=badGate(dir);err==nil{t.Fatal("unknown native ACL result trusted")}
}

func TestWindowsDNSRealNTFSProtectedACLReadOnly(t *testing.T){
 if os.Getenv("VOLVE_CI_READONLY_ADAPTER_INSPECTION")!="1"{t.Skip("only on ephemeral Windows CI runner")}
 dir,snapshot:=fixtureWindowsDNSProtectedACL(t)
 ctx,cancel:=context.WithTimeout(context.Background(),75*time.Second)
 defer cancel()
 gate,err:=NewWindowsDNSProtectedACLVerifier(ctx,dir,snapshot,DefaultWindowsDNSProtectedACLInspect)
 if err!=nil{t.Fatal(err)}
 if err:=gate(dir);err==nil{
  t.Fatal("inherited writable NTFS journal accepted before sealing")
 }
 sealWindowsDNSFixtureACL(t,dir,snapshot)
 for _,path:=range []string{filepath.Dir(dir),dir,filepath.Join(dir,ResidentIntentFile),snapshot}{
  if err:=gate(path);err!=nil{t.Fatalf("real Windows owner/DACL rejected approved sealed fixture %s: %v",filepath.Base(path),err)}
 }
 // A real user-created file inside the protected journal has inherited
 // ACL rules rather than its own protected DACL: fail closed.
 stray:=filepath.Join(dir,ResidentResultFile)
 if err:=os.WriteFile(stray,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if err:=gate(stray);err==nil{
  t.Fatal("unsealed terminal receipt inherited ACL and was accepted")
 }
}

func TestWindowsRealSYSTEMIdentityRequiredForDNSRecovery(t *testing.T){
 if os.Getenv("VOLVE_CI_READONLY_ADAPTER_INSPECTION")!="1"{t.Skip("CI read-only user SID check")}
 // GitHub interactive runner is administrator but not LocalSystem: admin
 // privileges alone must NEVER authorize the recovery controller.
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err==nil{
  t.Fatal("interactive Windows admin was mistaken for SYSTEM")
 }
}
