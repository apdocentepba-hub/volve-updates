//go:build windows && volveci

package main

// Actual NTFS test on a disposable hosted Windows runner. Uses the SAME
// production owner/DACL sealing and verification callbacks, but only within
// t.TempDir(), never ProgramData or a productive VOLVE installation.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func TestWindowsNativeProtectedMotorStagingRealNTFS(t *testing.T) {
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Fatal("actual NTFS ACL test restricted to disposable GitHub-hosted Windows")
 }
 if !isAdmin(){t.Fatal("native NTFS motor staging must run with elevated admin token")}
 temp:=t.TempDir()
 root:=filepath.Join(temp,"VOLVE-Browser-Filter-CI")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 inventory:=filepath.Join(root,"installed-engines")
 if err:=os.Mkdir(inventory,0700);err!=nil{t.Fatal(err)}
 // Only the disposable test root is sealed here. The production native
 // adapter never initializes an installed engine directory on its own.
 if err:=sealNewProtectedRecoveryNode(inventory);err!=nil{t.Fatalf("CI-only inventory root not sealed: %v",err)}
 target,acl,err:=nativeProtectedMotorTargetOpsForRoot(root)
 if err!=nil{t.Fatal(err)}
 if target!=inventory{t.Fatalf("native callback returned unexpected target: %q",target)}
 if err:=acl.VerifyProtected(target);err!=nil{t.Fatalf("actual NTFS DACL did not confirm SYSTEM+Admins-only: %v",err)}
 staged,pub:=prepareSignedLabCandidate(t,t.TempDir())
 dest,err:=motorupdate.PrepareProtectedVersionedMotor(context.Background(),staged,target,ed25519.PublicKey(pub),acl)
 if err!=nil{t.Fatalf("signed bundle could not be staged using actual native NTFS callbacks: %v",err)}
 if !strings.HasPrefix(strings.ToLower(dest),strings.ToLower(filepath.Join(inventory,"motor-0.28.7")+string(os.PathSeparator))){
  t.Fatalf("signed bundle escaped disposable native NTFS motor tree: %q",dest)
 }
 for _,p:=range []string{target,filepath.Dir(dest),dest,dest+".json",dest+".sig"}{
  if err:=acl.VerifyProtected(p);err!=nil{t.Fatalf("native SYSTEM/Administrators DACL not valid for %q: %v",p,err)}
 }
 manifest,err:=motorupdate.VerifyStaged(dest,pub)
 if err!=nil||manifest.Version!="0.28.7"||manifest.Component!="dns-engine"{
  t.Fatalf("signed installed copy authenticity invalid: %+v %v",manifest,err)
 }
 if _,err:=motorupdate.InspectInstalledEngine(target,pub);!errors.Is(err,motorupdate.ErrUnregisteredEngine){
  t.Fatalf("prepared-only NTFS copy falsely became an installed motor: %v",err)
 }
 if _,err:=motorupdate.PrepareProtectedVersionedMotor(context.Background(),staged,target,pub,acl);err==nil{
  t.Fatal("native staging silently overwrote a prior signed motor")
 }
 // The callbacks must never be reusable to seal an existing task or the
 // legacy motor or its recovery snapshot.
 for _,p:=range []string{root,filepath.Join(root,"VOLVE_DNS_Server_0270.exe"),
  filepath.Join(root,"legacy-engine-recovery","original-before-upgrade")}{
  if acl.SealNew(p)==nil{t.Fatalf("native DACL callback escaped allowlisted signed motor path: %q",p)}
 }
 t.Log("PASS: real WinNTFS DACL SYSTEM+Admins, publisher-signed create-only motor staging, no receipt/DNS/tasks, no overwrite")
}


func TestWindowsNativeProtectedMotorStageRootAndLease(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Fatal("protected motor installation root integration is restricted to hosted Windows CI")
 }
 if !isAdmin(){t.Fatal("protected motor staging requires an elevated Windows administrator")}
 root:=filepath.Join(t.TempDir(),"VOLVE-CI-Only-Installed-Root")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 signed,pub:=prepareSignedLabCandidate(t,t.TempDir())
 ctx:=context.Background()
 installed,err:=stageSignedMotorWithProtectedWindowsLease(ctx,root,signed,pub)
 if err!=nil{t.Fatalf("native signed motor stage failed to initialize protected root: %v",err)}
 inventory:=filepath.Join(root,"installed-engines")
 if _,err:=os.Lstat(inventory);err!=nil{t.Fatal(err)}
 _,acl,err:=nativeProtectedMotorTargetOpsForRoot(root);if err!=nil{t.Fatal(err)}
 for _,path:=range []string{inventory,filepath.Dir(installed),installed,installed+".json",installed+".sig"}{
  if err:=acl.VerifyProtected(path);err!=nil{
   t.Fatalf("new inventory or signed installed bundle ACL weak: path=%s error=%v",path,err)
  }
 }
 verified,err:=motorupdate.VerifyStaged(installed,pub)
 if err!=nil||verified.Version!="0.28.7"{t.Fatalf("signed native staged copy invalid: %+v %v",verified,err)}
 if _,err:=motorupdate.InspectInstalledEngine(inventory,pub);!errors.Is(err,motorupdate.ErrUnregisteredEngine){
  t.Fatalf("stage-only CLI helper falsely recorded motor as running/installed: %v",err)
 }
 if _,err:=stageSignedMotorWithProtectedWindowsLease(ctx,root,signed,pub);err==nil{
  t.Fatal("native duplicate signed stage overwrote existing motor")
 }
 // Fresh shared mutex availability after staging proves no OS lease leak.
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{t.Fatalf("native signed stage leaked protected kernel lease: %v",err)}
 release()
 badRoot:=filepath.Join(t.TempDir(),"VOLVE-CI-No-Signature")
 if err:=os.Mkdir(badRoot,0700);err!=nil{t.Fatal(err)}
 if _,err:=stageSignedMotorWithProtectedWindowsLease(ctx,badRoot,signed,make(ed25519.PublicKey,ed25519.PublicKeySize));err==nil{
  t.Fatal("untrusted publisher signing key was accepted for native root initialization")
 }
 if _,err:=os.Lstat(filepath.Join(badRoot,"installed-engines"));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("bad publisher signature created protected installed-engines root: %v",err)
 }
 weakRoot:=filepath.Join(t.TempDir(),"VOLVE-CI-Inherited-ACL")
 if err:=os.Mkdir(weakRoot,0700);err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(filepath.Join(weakRoot,"installed-engines"),0700);err!=nil{t.Fatal(err)}
 if _,err:=stageSignedMotorWithProtectedWindowsLease(ctx,weakRoot,signed,pub);err==nil{
  t.Fatal("unsealed preexisting inventory ACL incorrectly accepted")
 }
 if _,err:=os.Lstat(filepath.Join(weakRoot,"installed-engines","motor-0.28.7"));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("unsafe NTFS inventory created signed engine before ACL rejection: %v",err)
 }
 t.Log("PASS: native OS mutex and protected inventory create-only init, publisher signature mandatory, no engine receipt, no DNS/task operations")
}
