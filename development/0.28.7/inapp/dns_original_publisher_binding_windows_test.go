//go:build windows

package motorupdate

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func signedDNSBindingFixture(t *testing.T,f signedRecoveryFixture,pin string)([]byte,[]byte){
 t.Helper()
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("no armed CI resident transaction: %v",err)}
 permitHash:=sha256.Sum256(f.permit)
 binding:=SignedDNSOriginalBinding{
  Schema:1,Component:signedDNSReceiptComponent,
  IntentNonce:state.Intent.Nonce,LegacyMotorSHA256:state.Intent.LegacySHA256,
  LegacyTaskXMLSHA256:state.Intent.TaskXMLSHA256,
  TargetMotorSHA256:state.Intent.TargetSHA256,
  TargetMotorVersion:state.Intent.TargetVersion,
  SignedMigrationPermitSHA256:hex.EncodeToString(permitHash[:]),
  OriginalDNSJournalSHA256:pin,
 }
 raw,err:=json.Marshal(binding)
 if err!=nil{t.Fatal(err)}
 return raw,[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,raw)))
}

func TestSignedDNSBindingRejectsReplayedNonceMotorTaskPermitAndBackup(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 _,_,pin:=makeStagedDNSFixture(t)
 raw,sig:=signedDNSBindingFixture(t,f,pin)
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 if _,err:=VerifySignedDNSOriginalBinding(context.Background(),raw,sig,f.pub,state.Intent,f.permit);err!=nil{
  t.Fatalf("valid editor binding rejected: %v",err)
 }
 var original SignedDNSOriginalBinding
 if err:=json.Unmarshal(raw,&original);err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{
  name string
  apply func(*SignedDNSOriginalBinding)
 }{
  {"other-nonce",func(b *SignedDNSOriginalBinding){b.IntentNonce=strings.Repeat("0",32)}},
  {"old-motor",func(b *SignedDNSOriginalBinding){b.LegacyMotorSHA256=strings.Repeat("1",64)}},
  {"task-xml",func(b *SignedDNSOriginalBinding){b.LegacyTaskXMLSHA256=strings.Repeat("2",64)}},
  {"target-motor",func(b *SignedDNSOriginalBinding){b.TargetMotorSHA256=strings.Repeat("3",64)}},
  {"target-version",func(b *SignedDNSOriginalBinding){b.TargetMotorVersion="0.28.8"}},
  {"signed-permit",func(b *SignedDNSOriginalBinding){b.SignedMigrationPermitSHA256=strings.Repeat("4",64)}},
  {"missing-dns-digest",func(b *SignedDNSOriginalBinding){b.OriginalDNSJournalSHA256=""}},
 } {
  t.Run(tc.name,func(t *testing.T){
   changed:=original
   tc.apply(&changed)
   changedRaw,err:=json.Marshal(changed)
   if err!=nil{t.Fatal(err)}
   changedSig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,changedRaw)))
   if _,err:=VerifySignedDNSOriginalBinding(context.Background(),changedRaw,changedSig,f.pub,state.Intent,f.permit);err==nil{
    t.Fatal("publisher-signed mismatched DNS receipt accepted for a different pending recovery")
   }
  })
 }
}

func TestSignedDNSBindingDeniesForgeryAndNonCanonicalPayload(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 _,_,pin:=makeStagedDNSFixture(t)
 raw,sig:=signedDNSBindingFixture(t,f,pin)
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 otherPub,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 forged:=append([]byte(nil),raw...)
 pos:=bytes.Index(forged,[]byte(pin))
 if pos<0{t.Fatal("signed original DNS digest absent")}
 forged[pos]='0'
 cases:=[]struct{name string;payload,signature []byte;key ed25519.PublicKey}{
  {"forged-payload",forged,sig,f.pub},
  {"wrong-publisher",raw,sig,otherPub},
  {"no-signature",raw,nil,f.pub},
  {"no-publisher-key",raw,sig,nil},
  {"trailing-json",append(append([]byte(nil),raw...),[]byte("{}")...),sig,f.pub},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  if _,err:=VerifySignedDNSOriginalBinding(context.Background(),tc.payload,tc.signature,tc.key,state.Intent,f.permit);err==nil{
   t.Fatal("untrusted signed DNS receipt accepted")
  }
 })}
 pretty:=new(bytes.Buffer)
 if err:=json.Indent(pretty,raw,"","  ");err!=nil{t.Fatal(err)}
 prettySig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,pretty.Bytes())))
 if _,err:=VerifySignedDNSOriginalBinding(context.Background(),pretty.Bytes(),prettySig,f.pub,state.Intent,f.permit);err==nil{
  t.Fatal("noncanonical JSON accepted despite a syntactically valid Ed25519 signature")
 }
}

func TestSignedDNSBindingRejectsCancelledAndUnrelatedPermit(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 _,_,pin:=makeStagedDNSFixture(t)
 raw,sig:=signedDNSBindingFixture(t,f,pin)
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=VerifySignedDNSOriginalBinding(ctx,raw,sig,f.pub,state.Intent,f.permit);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled signed DNS binding admitted: %v",err)
 }
 if _,err:=VerifySignedDNSOriginalBinding(context.Background(),raw,sig,f.pub,state.Intent,[]byte("other permit"));err==nil{
  t.Fatal("DNS receipt accepted with different publisher permit bytes")
 }
}

func prepareNativeSignedDNSRecoveryLab(t *testing.T)(signedRecoveryFixture,string,[]byte,[]byte,string,context.Context){
 t.Helper()
 ctx:=context.Background()
 f:=makeSignedRecoveryFixture(t,false)
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("real ACL/publisher/Win32 lock integration requires disposable Windows CI")
 }
 // Unlike earlier test doubles, EVERY persisted grant, journal and fallback
 // object is sealed using the exact native Windows SYSTEM/Admin SID policy.
 parent:=filepath.Join(f.root,"legacy-engine-recovery")
 for _,path:=range []string{f.root,parent,f.journal,f.backup}{
  if err:=sealDNSBackupLabNode(ctx,path);err!=nil{t.Fatalf("cannot seal recovery parent: %v",err)}
 }
 for _,dir:=range []string{f.journal,f.backup}{
  nodes,err:=os.ReadDir(dir)
  if err!=nil{t.Fatal(err)}
  for _,node:=range nodes{
   path:=filepath.Join(dir,node.Name())
   if node.IsDir(){t.Fatal("unexpected recursive CI recovery original")}
   if err:=sealDNSBackupLabNode(ctx,path);err!=nil{t.Fatalf("cannot seal fixture evidence: %v",err)}
  }
 }
 protect:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 if err:=PersistResidentDurablePublisherGrant(ctx,f.root,f.permit,f.sig,f.pub,
  seal,protect,protect,protect);err!=nil{t.Fatalf("cannot persist signed publisher grant under real ACL: %v",err)}
 const guid="{12345678-1234-1234-1234-123456789abc}"
 raw,pin,err:=BuildDNSOriginalJournal(ctx,[]DNSServerState{
  {InterfaceGUID:guid,Family:DNSIPv6,Mode:DNSAutomatic},
  {InterfaceGUID:guid,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"1.1.1.1","8.8.8.8"}},
 })
 if err!=nil{t.Fatal(err)}
 if report,err:=StoreDNSOriginalBackupNativeWindows(ctx,parent,raw,pin);err!=nil||
  !report.FileVerified{t.Fatalf("native sealed original DNS backup invalid: %v",err)}
 binding,signature:=signedDNSBindingFixture(t,f,pin)
 return f,parent,binding,signature,pin,ctx
}

func TestNativeSignedDNSOriginalReadOnlyReviewBindsPermitJournalAndDNS(t *testing.T){
 f,_,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 review,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature)
 if err!=nil{t.Fatal(err)}
 if !review.PublisherBindingVerified||!review.MotorAndTaskBindingVerified||
  !review.OriginalDNSReadbackVerified||!review.NativeNTFSACLVerified||
  !review.ProtectedKernelMutexHeld||review.ReviewedFamilies!=2||
  review.PerformedDNSWrites||review.InstallAuthorized||review.RestoreAuthorized{
  t.Fatalf("joined trust review unintentionally allowed real DNS writes: %+v",review)
 }
 // It must be callable again from an independently acquired Win32 thread
 // after releasing the first lease; no lock or descriptor may be cached.
 second,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature)
 if err!=nil||second!=review{t.Fatalf("durable publisher/DNS evidence failed independent reopen: %v",err)}
 t.Log("PASS VOLVE_NATIVE_DNS_BACKUP_PUBLISHER_GRANT_NONCE_SIGNED_UNDER_WIN32_MUTEX_NO_WRITES")
}

func TestNativeSignedDNSOriginalReadOnlyReviewRejectsTamperBeforeApproval(t *testing.T){
 f,parent,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 if _,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature);err!=nil{t.Fatal(err)}
 file:=filepath.Join(parent,DNSOriginalBackupDirectoryName,DNSOriginalBackupFileName)
 out,err:=exec.CommandContext(ctx,"icacls.exe",file,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("cannot weaken lab DNS backup ACL: %v %s",err,string(out))}
 if review,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature);err==nil||
  review.PublisherBindingVerified||review.RestoreAuthorized{
  t.Fatal("tampered native backup ACL admitted into publisher-bound DNS review")
 }
}

func TestNativeSignedDNSOriginalReadOnlyReviewRejectsDifferentSignature(t *testing.T){
 f,_,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 altered:=append([]byte(nil),signature...)
 altered[0]='X'
 if review,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,altered);err==nil||
  review.PublisherBindingVerified||review.RestoreAuthorized{
  t.Fatal("modified signed DNS receipt accepted for a pending protected motor recovery")
 }
 state,err:=InspectResidentRecoveryJournal(ctx,f.journal,func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil||state.Status!="recovery-required"{
  t.Fatal("read-only signed-DNS review changed the pending recovery journal")
 }
}

func TestNativeSignedDNSOriginalReadOnlyReviewRejectsOtherWin32Lease(t *testing.T){
 f,_,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{t.Fatal(err)}
 busy,done:=context.WithTimeout(ctx,140*time.Millisecond)
 defer done()
 review,err:=ReviewSignedDNSOriginalBackupNativeWindows(busy,f.root,f.pub,binding,signature)
 release()
 if !errors.Is(err,context.DeadlineExceeded)||review.PublisherBindingVerified{
  t.Fatalf("publisher DNS reviewer bypassed another protected Windows transaction: %v",err)
 }
}
