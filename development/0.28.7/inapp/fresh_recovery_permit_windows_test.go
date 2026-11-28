//go:build windows

package motorupdate

import(
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "time"
 "strings"
 "testing"
)

func TestWindowsFreshRecoveryPermitDistinctScope(t *testing.T){
 ctx:=context.Background()
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 permit:=freshRecoveryPermit{1,freshRecoveryPermitComponent,freshRecoveryOperation,pins}
 raw,err:=json.Marshal(permit);if err!=nil{t.Fatal(err)}
 sig:=ed25519.Sign(priv,raw)
 if got,err:=verifyFreshRecoveryPermit(ctx,raw,sig,pub,pins);err!=nil||got!=permit{t.Fatal("valid recovery-only permit rejected",err)}
 for _,name:=range []string{"activation-scope","foreign-transaction","foreign-dns","foreign-motor","foreign-watchdog","foreign-owner","noncanonical","wrong-key","bad-signature"}{
  t.Run(name,func(t *testing.T){
   g,p:=permit,pins
   key:=pub
   switch name{
   case "activation-scope":g.Component=freshActivationComponent;g.Operation=freshActivationOperation
   case "foreign-transaction":p.TransactionID=strings.Repeat("b",32)
   case "foreign-dns":p.OriginalDNSJournalSHA256=strings.Repeat("f",64)
   case "foreign-motor":p.MotorSHA256=strings.Repeat("f",64)
   case "foreign-watchdog":p.WatchdogExecutableSHA256=strings.Repeat("f",64)
   case "foreign-owner":p.OwnerApprovalSHA256=strings.Repeat("f",64)
   case "wrong-key":key,_,err=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
   }
   r,err:=json.Marshal(g);if err!=nil{t.Fatal(err)}
   if name=="noncanonical"{r=append(r,' ')}
   s:=ed25519.Sign(priv,r);if name=="bad-signature"{s[0]^=1}
   if got,err:=verifyFreshRecoveryPermit(ctx,r,s,key,p);err==nil||got!=(freshRecoveryPermit{}){t.Fatal("unsafe recovery accepted")}
  })
 }
 t.Log("PASS VOLVE_FRESH_RECOVERY_PERMIT_DISTINCT_SCOPE_NO_ACTIVATION_EXPIRY")
}


// Real NTFS storage and Windows mutex, with synthetic DNS state and
// independent fence. No legacy motor or migration journal is created.
func TestWindowsFreshPersistedRecoveryResumesWithoutActivationGrant(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted NTFS only")}
 ctx,cancel:=context.WithTimeout(context.Background(),360*time.Second);defer cancel()
 id:=strings.Repeat("c",32)
 root:=filepath.Join(t.TempDir(),id)
 parent:=filepath.Join(root,"legacy-engine-recovery")
 seal:=func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 for _,dir:=range []string{root,parent}{
  if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
  if err:=seal(dir);err!=nil{t.Fatal(err)}
 }
 h:=windowsActivationHostFixture()
 journal,dnsPin,err:=BuildDNSOriginalJournal(ctx,[]DNSServerState{h.states[DNSIPv4],h.states[DNSIPv6]})
 if err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,parent,journal,dnsPin,seal,check);err!=nil{t.Fatal(err)}
 pins:=freshActivationEvidence{id,strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),dnsPin,strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
 // A synthetic historical review is sufficient for staging the DNS-only
 // permit. This test does not claim a full four-archive boot recovery.
 historical,err:=json.Marshal(originalRecoveryReviewEvidence{1,"original-recovery-review-unarmed",id,pins.OriginalReviewSHA256});if err!=nil{t.Fatal(err)}
 if err:=residentCreate(filepath.Join(root,originalRecoveryReviewFile),historical,seal,check);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 raw,err:=json.Marshal(freshRecoveryPermit{1,freshRecoveryPermitComponent,freshRecoveryOperation,pins});if err!=nil{t.Fatal(err)}
 sig:=ed25519.Sign(priv,raw)
 bad:=append([]byte(nil),sig...);bad[0]^=1
 path:=filepath.Join(root,freshRecoveryPermitName)
 if err:=persistFreshRecoveryPermitNative(ctx,root,raw,bad,pub,pins);err==nil{t.Fatal("invalid signature staged")}
 if _,err:=os.Lstat(path);!os.IsNotExist(err){t.Fatal("invalid signature created rescue slot")}
 if err:=persistFreshRecoveryPermitNative(ctx,root,raw,sig,pub,pins);err!=nil{t.Fatal("durable recovery permit staging",err)}
 saved,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=persistFreshRecoveryPermitNative(ctx,root,raw,sig,pub,pins);!errors.Is(err,os.ErrExist){t.Fatal("recovery slot not create-only",err)}
 records,err:=VerifyDNSOriginalJournal(ctx,journal,dnsPin);if err!=nil{t.Fatal(err)}
 for _,r:=range records{h.states[r.Original.Family]=copyWindowsActivationDNSState(r.Expected)}
 simulated:=&signedDNSBootRecoveryFixture{host:h,records:records}
 // No activation grant and a damaged consumed reservation must not stop
 // authorized rescue. The independent fence remains mandatory.
 consumed:=filepath.Join(root,freshReservationName)
 if err:=os.WriteFile(consumed,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if err:=seal(consumed);err!=nil{t.Fatal(err)}
 allow:=false
 fenceCalls:=0
 fence:=func(c context.Context,e freshActivationEvidence)error{
  fenceCalls++
  if !allow||e!=pins{return errors.New("candidate not independently fenced")}
  return c.Err()
 }
 run:=func(inspect WindowsReadOnlyPowerShell)error{
  release,err:=AcquireProtectedResidentTransitionLease(ctx)
  if err!=nil{return err}
  defer release()
  // Reopen the disk envelope on EVERY invocation, including retry.
  return restoreFreshOriginalDNSUnderLease(ctx,root,pub,pins,fence,inspect,simulated.invoke)
 }
 if err:=run(h.inspect);err==nil||simulated.writes!=0||fenceCalls!=0{t.Fatal("unarmed recovery reached fence or DNS writer",err)}
 // Real create-only pending marker under native mutex. The readiness
 // guard remains synthetic and cannot authorize any real DNS writes.
 release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
 held:=&exclusiveDNSActivationGuard{inner:&freshReservationFixtureGuard{},acquire:AcquireProtectedResidentTransitionLease,release:release}
 pending,err:=armFreshRecoveryPendingUnderLease(ctx,root,pub,pins,held)
 if err!=nil{held.close();t.Fatal("pending marker arming failed",err)}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{held.close();t.Fatal(err)}
 if _,err:=armFreshRecoveryPendingUnderLease(ctx,root,pub,pins,held);!errors.Is(err,os.ErrExist){held.close();t.Fatal("pending transaction rearmed",err)}
 held.close()
 if err:=run(h.inspect);err==nil||simulated.writes!=0||fenceCalls==0{t.Fatal("unfenced recovery reached DNS writer",err)}
 allow=true
 extra:=true
 if err:=run(windowsActivationInspectorWithExtraAdapter(h,&extra));err==nil||simulated.writes!=0{t.Fatal("foreign adapter reached DNS writer",err)}
 simulated.failAt=2
 if err:=run(h.inspect);err==nil||simulated.writes!=2{t.Fatal("mid-recovery failure not preserved",err)}
 simulated.failAt=0
 if err:=run(h.inspect);err!=nil||simulated.writes!=3{t.Fatal("durable recovery could not resume",err)}
 simulated.expectOriginal(t)
 if err:=run(h.inspect);err!=nil||simulated.writes!=3{t.Fatal("restoration not idempotent",err)}
 after,err:=os.ReadFile(path);if err!=nil||!bytes.Equal(saved,after){t.Fatal("rescue permit modified")}
 broken,err:=os.ReadFile(consumed);if err!=nil||string(broken)!="{"{t.Fatal("consumed activation marker was rewritten")}
 if err:=os.WriteFile(path,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if err:=run(h.inspect);err==nil||simulated.writes!=3{t.Fatal("tampered rescue permit accepted",err)}
 if err:=persistFreshRecoveryPermitNative(ctx,root,raw,sig,pub,pins);!errors.Is(err,os.ErrExist){t.Fatal("damaged rescue permit reused",err)}
 pendingPath:=filepath.Join(root,freshRecoveryPendingName)
 if err:=os.WriteFile(pendingPath,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 release,err=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
 invalid:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending)
 release()
 if invalid==nil{t.Fatal("partial pending marker accepted")}
 t.Log("PASS VOLVE_FRESH_RECOVERY_PENDING_CREATE_ONLY_REQUIRED_BEFORE_RESCUE")
 t.Log("PASS VOLVE_FRESH_PERSISTED_RESCUE_RESUME_IDEMPOTENT_WITHOUT_ACTIVATION_MEMORY_DNS_ONLY")
}
