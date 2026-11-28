//go:build windows

package motorupdate

import(
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestWindowsFreshReservationNativeCreateOnly(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted NTFS only")}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64)}
 root:=filepath.Join(t.TempDir(),pins.TransactionID)
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 if err:=nativeSealApprovedOriginalBackupNode(ctx,root);err!=nil{t.Fatal(err)}
 // Synthetic historical review, not a real recovery authorization. The
 // test's guard is in-memory; native NTFS and named mutex are real.
 historical,err:=json.Marshal(originalRecoveryReviewEvidence{1,"original-recovery-review-unarmed",pins.TransactionID,pins.OriginalReviewSHA256});if err!=nil{t.Fatal(err)}
 reviewPath:=filepath.Join(root,originalRecoveryReviewFile)
 if err:=residentCreate(reviewPath,historical,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)});err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now()
 raw,err:=json.Marshal(freshActivationAdmission{1,freshActivationComponent,freshActivationOperation,pins,now.Add(-time.Minute).Unix(),now.Add(5*time.Minute).Unix()});if err!=nil{t.Fatal(err)}
 sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
 held:=&exclusiveDNSActivationGuard{inner:&freshReservationFixtureGuard{},acquire:AcquireProtectedResidentTransitionLease,release:release}
 defer held.close()
 marker:=filepath.Join(root,freshReservationName)
 bad:=append([]byte(nil),sig...);bad[0]='!'
 if _,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,bad,pub,pins,host,held);err==nil{t.Fatal("invalid signature reserved marker")}
 if _,err:=os.Lstat(marker);!os.IsNotExist(err){t.Fatal("invalid admission created marker")}
 first,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,sig,pub,pins,host,held)
 if err!=nil||first.Evidence!=pins{t.Fatal("fresh reservation failed",err)}
 initial,err:=os.ReadFile(marker);if err!=nil{t.Fatal(err)}
 if _,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,sig,pub,pins,host,held);!errors.Is(err,os.ErrExist){t.Fatal("fresh admission replay accepted or unexpected refusal",err)}
 after,err:=os.ReadFile(marker);if err!=nil||!bytes.Equal(initial,after){t.Fatal("replay modified reservation")}
 if err:=nativeDNSOriginalBackupACL(ctx,marker);err!=nil{t.Fatal(err)}
 t.Log("PASS VOLVE_FRESH_NATIVE_RESERVATION_CREATE_ONLY_ACL_REPLAY_REFUSED_NO_DNS")
}

type freshReservationFixtureGuard struct{}
func(*freshReservationFixtureGuard)VerifyArmed(context.Context,string)error{return nil}
func(*freshReservationFixtureGuard)VerifyLiveProtection(context.Context,string)error{return errors.New("fixture cannot verify live protection")}
func(*freshReservationFixtureGuard)RecoverIndependently(context.Context,string)error{return errors.New("fixture cannot restore DNS")}
func(*freshReservationFixtureGuard)CommitActive(context.Context,string)error{return errors.New("fixture cannot commit activation")}
