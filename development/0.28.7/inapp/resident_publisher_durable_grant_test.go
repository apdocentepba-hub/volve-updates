package motorupdate

import (
 "bytes"
 "context"
 "errors"
 "encoding/base64"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
)

// These are intentionally INERT synthetic source bytes. The fixture's ACL
// callback is fake and must NEVER authorize production or SYSTEM writes.
func TestDurablePublisherGrantSurvivesNewProcessAndRejectsReplay(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil}
 err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,allow,allow,allow,allow)
 if err!=nil{t.Fatal(err)}
 if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,allow,allow,allow,allow);err==nil{
  t.Fatal("create-only signed publisher authorization was overwritten")
 }
 // Fresh process reads only on-disk evidence. The caller passes no permit
 // or signature bytes and must know only the compiled, pinned public key.
 child:=exec.Command(os.Args[0],"-test.run=^TestDurablePublisherGrantReadInNewProcess$","-test.v")
 child.Env=append(os.Environ(),
  "VOLVE_CI_DURABLE_GRANT_CHILD=1",
  "VOLVE_CI_DURABLE_GRANT_ROOT="+f.root,
  "VOLVE_CI_DURABLE_GRANT_KEY="+base64.StdEncoding.EncodeToString(f.pub))
 out,err:=child.CombinedOutput()
 if err!=nil||!bytes.Contains(out,[]byte("VOLVE_DURABLE_GRANT_VERIFIED")){
  t.Fatalf("independent process refused sealed publisher grant: %v %s",err,out)
 }
}

func TestDurablePublisherGrantReadInNewProcess(t *testing.T){
 if os.Getenv("VOLVE_CI_DURABLE_GRANT_CHILD")!="1"{return}
 root:=os.Getenv("VOLVE_CI_DURABLE_GRANT_ROOT")
 key,err:=base64.StdEncoding.DecodeString(os.Getenv("VOLVE_CI_DURABLE_GRANT_KEY"))
 if err!=nil{t.Fatal(err)}
 allow:=func(string)error{return nil}
 result,err:=LoadResidentDurablePublisherGrant(context.Background(),root,key,allow,allow,allow)
 if err!=nil||len(result.Permit)==0||len(result.Signature)==0{
  t.Fatalf("fresh process did not bind signed permit to protected journal: %v",err)
 }
 t.Log("VOLVE_DURABLE_GRANT_VERIFIED")
}

func TestDurablePublisherGrantRejectsTamperingAndIncompleteWrites(t *testing.T){
 for _,mode:=range []string{"permit-bytes","signature-bytes","missing-signature","extra-file","unsafe-acl","parent-symlink","rearm-with-expired","cancel"}{
  t.Run(mode,func(t *testing.T){
   f:=makeSignedRecoveryFixture(t,false)
   allow:=func(string)error{return nil}
   dir:=filepath.Join(f.root,"legacy-engine-recovery",residentGrantFolder)
   if mode=="rearm-with-expired"{
    expired:=makeSignedRecoveryFixture(t,true)
    if err:=PersistResidentDurablePublisherGrant(context.Background(),expired.root,
      expired.permit,expired.sig,expired.pub,allow,allow,allow,allow);err==nil{
     t.Fatal("expired permit allowed a new persistence step")
    }
    return
   }
   if mode=="cancel"{
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if err:=PersistResidentDurablePublisherGrant(ctx,f.root,f.permit,f.sig,f.pub,
      allow,allow,allow,allow);!errors.Is(err,context.Canceled){
     t.Fatalf("cancelled grant still created directory: %v",err)
    }
    if _,err:=os.Lstat(dir);!errors.Is(err,os.ErrNotExist){t.Fatal("cancellation modified disk")}
    return
   }
   if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
    f.permit,f.sig,f.pub,allow,allow,allow,allow);err!=nil{t.Fatal(err)}
   switch mode{
   case "permit-bytes":if err:=os.WriteFile(filepath.Join(dir,residentGrantPermitFile),[]byte("invalid signature"),0600);err!=nil{t.Fatal(err)}
   case "signature-bytes":if err:=os.WriteFile(filepath.Join(dir,residentGrantSignatureFile),[]byte("tampered signature"),0600);err!=nil{t.Fatal(err)}
   case "missing-signature":if err:=os.Remove(filepath.Join(dir,residentGrantSignatureFile));err!=nil{t.Fatal(err)}
   case "extra-file":if err:=os.WriteFile(filepath.Join(dir,"unexpected.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
   case "unsafe-acl":
    forbidden:=filepath.Join(dir,residentGrantPermitFile)
    verifyACL:=func(p string)error{
     if p==forbidden{return errors.New("untrusted owner")}
     return nil
    }
    if _,err:=LoadResidentDurablePublisherGrant(context.Background(),f.root,f.pub,
     verifyACL,allow,allow);err==nil{
     t.Fatal("untrusted file ACL was accepted")
    }
    return
   case "parent-symlink":
    // The actual recovery subtree must never be followed through a link.
    // Windows can refuse symlink creation without elevation: in that case
    // skip only this fixture; production independently checks reparse points.
    parent:=filepath.Join(f.root,"legacy-engine-recovery")
    target:=filepath.Join(f.root,"original-parent")
    if err:=os.Rename(parent,target);err!=nil{t.Fatal(err)}
    if err:=os.Symlink(target,parent);err!=nil{t.Skipf("symlink privilege unavailable: %v",err)}
   }
   if _,err:=LoadResidentDurablePublisherGrant(context.Background(),f.root,f.pub,
    allow,allow,allow);err==nil{
    t.Fatalf("unsafe persistent publisher authorization accepted in scenario %s",mode)
   }
  })
 }
}

func TestDurablePublisherGrantFailsClosedWhenInterruptedAfterFirstFile(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil}
 calls:=0
 seal:=func(path string)error{
  calls++
  if strings.HasSuffix(path,residentGrantSignatureFile){return errors.New("injected seal failure after grant bytes written")}
  return nil
 }
 if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,seal,allow,allow,allow);err==nil{
  t.Fatal("injected interruption did not prevent completion")
 }
 if calls!=3{t.Fatalf("expected sealed directory and both files before failure, got %d",calls)}
 if _,err:=LoadResidentDurablePublisherGrant(context.Background(),f.root,f.pub,
  allow,allow,allow);err!=nil{
  // A fixture's permissive callback cannot tell that an ACL sealing failed;
  // in production strict ACL verification rejects it.
 }else{
  // Require a REAL negative permission callback for the failed object.
  denied:=func(path string)error{
   if filepath.Base(path)==residentGrantSignatureFile{return errors.New("unsealed partial grant")}
   return nil
  }
  if _,err:=LoadResidentDurablePublisherGrant(context.Background(),f.root,f.pub,
   denied,allow,allow);err==nil{
   t.Fatal("partially sealed signed grant accepted")
  }
 }
 // It must remain create-only and not auto-overwrite on a second attempt.
 if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,allow,allow,allow,allow);err==nil{
  t.Fatal("interrupted signed grant overwritten without investigation")
 }
}

func TestDurablePublisherGrantRejectsExpiredOrTerminalJournalOnNewRead(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil}
 if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,allow,allow,allow,allow);err!=nil{t.Fatal(err)}
 if err:=FinishResidentRecoveryIntent(context.Background(),f.journal,"restored",allow,allow);err!=nil{t.Fatal(err)}
 if _,err:=LoadResidentDurablePublisherGrant(context.Background(),f.root,f.pub,allow,allow,allow);err==nil{
  t.Fatal("terminal journal authorized another independent recovery")
 }
}
