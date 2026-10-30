//go:build windows

package main

// Non-mutating tests only. They never query, switch or start a live SYSTEM
// task, process or DNS listener.
import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func TestWindowsResidentOutcomeSignedCandidatePathIsConstrained(t *testing.T){
 root:=t.TempDir()
 path,err:=residentOutcomeCandidatePath(root,"0.28.7")
 if err!=nil{t.Fatal(err)}
 want:=filepath.Join(root,"motor-0.28.7","VOLVE_DNS_Motor_0_28_7.exe")
 if path!=want{t.Fatalf("unexpected signed motor path %q, want %q",path,want)}
 for _,v:=range []string{"","0.28","0.28.7-rc","../0.28.7","1..3","3.2/0","0.28.7;bad"}{
  if _,err:=residentOutcomeCandidatePath(root,v);err==nil{
   t.Fatalf("untrusted candidate version accepted: %q",v)
  }
 }
 if _,err:=residentOutcomeCandidatePath("relative-root","0.28.7");err==nil {
  t.Fatal("relative installed motor root accepted")
 }
}

func TestWindowsResidentHealthRequiresReadOnlySYSTEMIdentity(t *testing.T){
 root:=t.TempDir()
 checks:=newResidentWindowsHealthChecks(root,nil)
 if checks.IPv4DNS!="127.0.0.1:53" || checks.IPv6DNS!="[::1]:53" {
  t.Fatal("resident health was not configured for production dual-stack port 53")
 }
 if len(checks.TCPAddresses)<2 {
  t.Fatal("only one independent connectivity endpoint configured")
 }
 canceled,cancel:=context.WithCancel(context.Background());cancel()
 if err:=checks.VerifyRunningIdentity(canceled,motorupdate.ResidentRecoveryIntent{},"committed");err==nil{
  t.Fatal("cancelled Windows health identity accepted")
 }
 // Missing publisher key and protected original recovery cannot certify a
 // production motor. Never construct a positive fake SYSTEM task in this test.
 if err:=checks.VerifyRunningIdentity(context.Background(),
  motorupdate.ResidentRecoveryIntent{
   Schema:1,Task:"VOLVE-DNS-SERVER-0270",TargetVersion:"0.28.7",
   TargetSHA256:strings.Repeat("a",64),
  },"committed");err==nil{
  t.Fatal("fake candidate and missing publisher key accepted")
 }
 if _,err:=os.Stat(filepath.Join(root,localRecoveryFolder));!os.IsNotExist(err){
  t.Fatal("read-only identity check created an unexpected backup")
 }
}
