//go:build windows

package motorupdate

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "sync"
 "testing"
 "time"
)

func makeNativeDNSActivationOnceFixture(t *testing.T)(
 string,[]byte,[]byte,ed25519.PublicKey,
 DNSActivationExternallyPinnedEvidence,time.Time,string,
){
 t.Helper()
 _,parent,_,_,pin,_:=prepareNativeSignedDNSRecoveryLab(t)
 f:=makeDNSGrantFixture(t)
 f.now=time.Now().UTC()
 f.grant.IssuedAtUnix=f.now.Add(-time.Minute).Unix()
 f.grant.ExpiresAtUnix=f.now.Add(10*time.Minute).Unix()
 f.pins.OriginalDNSJournalSHA256=pin
 f.grant.OriginalDNSJournalSHA256=pin
 raw,signature:=signDNSActivationFixture(t,f)
 return parent,raw,signature,f.pub,f.pins,f.now,
  filepath.Join(parent,dnsActivationOnceFilePrefix+f.grant.IntentNonce+".json")
}

func TestWindowsNativeSignedDNSActivationNonceCreatesExactlyOneDurableReceipt(t *testing.T){
 parent,raw,sig,pub,pins,now,path:=makeNativeDNSActivationOnceFixture(t)
 ctx:=context.Background()
 first,err:=ReserveSignedDNSActivationOnceNativeWindows(ctx,parent,raw,sig,pub,pins,now)
 if err!=nil{t.Fatal(err)}
 if first.Schema!=1||first.Component!=dnsActivationOnceReceiptComponent||
  first.IntentNonce!=pins.IntentNonce||first.TargetMotorSHA256!=pins.TargetMotorSHA256||
  first.OriginalDNSJournalSHA256!=pins.OriginalDNSJournalSHA256{
  t.Fatalf("nonce reservation receipt not bound to exact signed publisher identity: %+v",first)
 }
 rawReceipt,err:=os.ReadFile(path)
 if err!=nil{t.Fatal(err)}
 var persisted DNSActivationOnceReceipt
 if err:=json.Unmarshal(rawReceipt,&persisted);err!=nil||persisted!=first{
  t.Fatal("durable one-use receipt differs from returned attestation")
 }
 if err:=nativeDNSOriginalBackupACL(ctx,path);err!=nil{t.Fatal(err)}
 if _,err:=ReserveSignedDNSActivationOnceNativeWindows(ctx,parent,raw,sig,pub,pins,now);err==nil||
  !strings.Contains(err.Error(),"already reserved"){
  t.Fatalf("replay of exact still-valid signature was not rejected: %v",err)
 }
 after,err:=os.ReadFile(path)
 if err!=nil||!bytes.Equal(rawReceipt,after){t.Fatal("replay modified the first durable receipt")}
 t.Log("PASS: Windows NTFS O_EXCL nonce receipt, real SYSTEM/Admin ACL, exact publisher pin; NO DNS WRITES")
}

func TestWindowsNativeSignedDNSActivationNonceRejectsUntrustedGrantBeforeFileCreation(t *testing.T){
 for _,tc:=range []string{"invalid-signature","wrong-publisher","other-journal","expired","wrong-root"}{
  t.Run(tc,func(t *testing.T){
   parent,raw,sig,pub,pins,now,path:=makeNativeDNSActivationOnceFixture(t)
   switch tc{
   case "invalid-signature":sig=append([]byte(nil),sig...);sig[0]^=1
   case "wrong-publisher":pub=append(ed25519.PublicKey(nil),pub...);pub[0]^=1
   case "other-journal":pins.OriginalDNSJournalSHA256=strings.Repeat("f",64)
   case "expired":now=now.Add(25*time.Minute)
   case "wrong-root":parent=filepath.Join(filepath.Dir(parent),"untrusted-tree")
   }
   if _,err:=ReserveSignedDNSActivationOnceNativeWindows(
    context.Background(),parent,raw,sig,pub,pins,now,
   );err==nil{
    t.Fatal("untrusted signed grant or parent accepted")
   }
   if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){
    t.Fatalf("rejected signed activation created a marker: %v",err)
   }
  })
 }
}

func TestWindowsNativeSignedDNSActivationNonceRejectsParentACLDrift(t *testing.T){
 parent,raw,sig,pub,pins,now,path:=makeNativeDNSActivationOnceFixture(t)
 if _,err:=exec.Command("icacls.exe",parent,"/grant","*S-1-1-0:W").CombinedOutput();err!=nil{
  t.Fatalf("cannot stage disposable ACL downgrade: %v",err)
 }
 if _,err:=ReserveSignedDNSActivationOnceNativeWindows(
  context.Background(),parent,raw,sig,pub,pins,now,
 );err==nil{
  t.Fatal("untrusted recovery parent allowed one-use receipt creation")
 }
 if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){
  t.Fatalf("ACL downgrade failed closed after touching marker: %v",err)
 }
}

func TestWindowsNativeSignedDNSActivationNonceConcurrentReplayOnlyOneWins(t *testing.T){
 parent,raw,sig,pub,pins,now,path:=makeNativeDNSActivationOnceFixture(t)
 const competitors=4
 errs:=make([]error,competitors)
 var wg sync.WaitGroup
 for i:=0;i<competitors;i++{
  wg.Add(1)
  go func(i int){
   defer wg.Done()
   _,errs[i]=ReserveSignedDNSActivationOnceNativeWindows(
    context.Background(),parent,raw,sig,pub,pins,now)
  }(i)
 }
 wg.Wait()
 good,denied:=0,0
 for _,err:=range errs{
  if err==nil{good++}else if strings.Contains(err.Error(),"already reserved"){denied++}else{
   t.Fatalf("unexpected concurrent nonce reservation failure: %v",err)
  }
 }
 if good!=1||denied!=competitors-1{
  t.Fatalf("race did not reserve exactly once: allowed=%d denied=%d",good,denied)
 }
 if err:=nativeDNSOriginalBackupACL(context.Background(),path);err!=nil{t.Fatal(err)}
}
