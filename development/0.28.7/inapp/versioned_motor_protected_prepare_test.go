package motorupdate

import (
 "context"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func protectedMotorTestRoot(t *testing.T)string{
 t.Helper()
 root:=filepath.Join(t.TempDir(),"installed-engines")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 return root
}
func protectedMotorTestOps()ProtectedTargetFileOps{
 validate:=func(path string)error{
  stat,err:=os.Lstat(path);if err!=nil{return err}
  if stat.Mode()&os.ModeSymlink!=0 ||(!stat.IsDir()&&!stat.Mode().IsRegular()){
   return errors.New("not an ordinary protected file or directory")
  }
  return nil
 }
 return ProtectedTargetFileOps{SealNew:validate,VerifyProtected:validate}
}

func TestProtectedMotorPreparedOnlySignedBundleAndNoActivation(t *testing.T){
 f:=newSignedBridge(t)
 root:=protectedMotorTestRoot(t)
 original,err:=os.ReadFile(f.candidate);if err!=nil{t.Fatal(err)}
 dest,err:=PrepareProtectedVersionedMotor(context.Background(),f.candidate,root,f.pub,protectedMotorTestOps())
 if err!=nil{t.Fatal(err)}
 if filepath.Dir(dest)!=filepath.Join(root,"motor-0.28.7"){t.Fatalf("unexpected protected motor destination: %q",dest)}
 for _,sidecar:=range []string{"",".json",".sig"}{
  info,err:=os.Lstat(dest+sidecar)
  if err!=nil||!info.Mode().IsRegular(){t.Fatalf("signed prepared bundle missing %s: %v",sidecar,err)}
 }
 signed,err:=VerifyStaged(dest,f.pub)
 if err!=nil||signed.Version!="0.28.7"||signed.Component!="dns-engine"{
  t.Fatalf("prepared signed motor no longer verifies: %+v %v",signed,err)
 }
 after,err:=os.ReadFile(f.candidate);if err!=nil{t.Fatal(err)}
 if string(original)!=string(after){t.Fatal("staging changed publisher candidate")}
 entries,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 if len(entries)!=1{t.Fatalf("prepare-only created unexpected installation nodes: %d",len(entries))}
 // A second staging MUST refuse overwrite even if the signed bytes match.
 if _,err:=PrepareProtectedVersionedMotor(context.Background(),f.candidate,root,f.pub,protectedMotorTestOps());err==nil{
  t.Fatal("create-only installer overwrote an existing signed motor version")
 }
}

func TestProtectedMotorPreparationFailsClosedBeforeAnyWrite(t *testing.T){
 for _,scenario:=range []string{"no-acl","invalid-acl","not-absolute","cancelled","bad-key","wrong-component","tampered-source","missing-sidecar","existing-target","unsafe-source-symlink"}{
  t.Run(scenario,func(t *testing.T){
   f:=newSignedBridge(t)
   root:=protectedMotorTestRoot(t)
   ops:=protectedMotorTestOps()
   source:=f.candidate
   key:=ed25519.PublicKey(f.pub)
   ctx:=context.Background()
   switch scenario{
   case "no-acl":ops.VerifyProtected=nil
   case "invalid-acl":ops.VerifyProtected=func(string)error{return os.ErrPermission}
   case "not-absolute":source="VOLVE_DNS_Motor_0_28_7.exe"
   case "cancelled":c,cancel:=context.WithCancel(ctx);cancel();ctx=c
   case "bad-key":key=make(ed25519.PublicKey,ed25519.PublicKeySize)
   case "wrong-component":
    // A valid cryptographic signature from the fixture is compulsory.
    // Unknown publisher component is rejected by the normal manifest
    // verifier rather than by inventing a synthetic signature.
    source=filepath.Join(t.TempDir(),"unknown-component.exe")
   case "tampered-source":if err:=os.WriteFile(source,[]byte("BAD-MOTOR"),0600);err!=nil{t.Fatal(err)}
   case "missing-sidecar":if err:=os.Remove(source+".sig");err!=nil{t.Fatal(err)}
   case "existing-target":
    if err:=os.Mkdir(filepath.Join(root,"motor-0.28.7"),0700);err!=nil{t.Fatal(err)}
   case "unsafe-source-symlink":
    link:=filepath.Join(t.TempDir(),"VOLVE_DNS_Motor_0_28_7.exe")
    if err:=os.Symlink(source,link);err!=nil{t.Skipf("symlink not supported on this runner: %v",err)}
    source=link
   }
   _,err:=PrepareProtectedVersionedMotor(ctx,source,root,key,ops)
   if err==nil{t.Fatalf("unsigned/untrusted preparation succeeded: %s",scenario)}
   if scenario!="existing-target"{
    entries,dirErr:=os.ReadDir(root);if dirErr!=nil{t.Fatal(dirErr)}
    if len(entries)!=0{t.Fatalf("unsafe package %s wrote installed files before failed guard",scenario)}
   }
  })
 }
}

func TestProtectedMotorPreparationKeepsInterruptedBundleUnusable(t *testing.T){
 f:=newSignedBridge(t)
 root:=protectedMotorTestRoot(t)
 ops:=protectedMotorTestOps()
 ops.SealNew=func(path string)error{
  if strings.HasSuffix(path,".sig"){return os.ErrPermission}
  return protectedMotorTestOps().SealNew(path)
 }
 _,err:=PrepareProtectedVersionedMotor(context.Background(),f.candidate,root,f.pub,ops)
 if err==nil{t.Fatal("incomplete protected signature was accepted")}
 dst:=filepath.Join(root,"motor-0.28.7","VOLVE_DNS_Motor_0_28_7.exe")
 if _,err:=VerifyStaged(dst,f.pub);err==nil{
  t.Fatal("interrupted copy became a verified installed motor")
 }
 if _,err:=PrepareProtectedVersionedMotor(context.Background(),f.candidate,root,f.pub,protectedMotorTestOps());err==nil{
  t.Fatal("unreviewed partial bundle silently overwritten on retry")
 }
}
