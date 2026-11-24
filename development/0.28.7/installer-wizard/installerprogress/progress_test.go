package installerprogress

import (
 "sync"
 "testing"
)

func advance(t *testing.T,s *State,n int) {
 t.Helper()
 for _,stage:=range order[:n] {
  if err:=s.Confirm(stage);err!=nil {t.Fatal(err)}
 }
}
func TestComplete(t *testing.T) {
 s:=New()
 for i,stage:=range order[:len(order)-1] {
  if err:=s.Confirm(stage);err!=nil {t.Fatal(err)}
  v:=s.View()
  if v.Percent!=(i+1)*100/len(order) || v.Percent>=100 {t.Fatal(v)}
 }
 if s.View().Status!="awaiting_reboot" || !s.View().RebootRequired || s.View().Next!=PostBootVerified {t.Fatal(s.View())}
 if s.Confirm(PostBootVerified)==nil || s.ConfirmReboot()==nil {t.Fatal("unattested post-boot stage accepted")}
 if s.RequireReboot()!=nil || s.ConfirmReboot()!=nil {t.Fatal(s.View())}
 if v:=s.View();v.Status!="completed"||v.Percent!=100||v.RebootRequired||v.Next!="" {t.Fatal(v)}
 if s.Confirm(CommitVerified)==nil||s.Fail()==nil||s.ConfirmReboot()==nil {t.Fatal("terminal accepted")}
}
func TestOutOfOrder(t *testing.T) {
 s:=New()
 if s.Confirm(MotorVerified)==nil||s.View().Percent!=0 {t.Fatal(s.View())}
 advance(t,s,1)
 if s.Confirm(Preflight)==nil||s.View().Percent!=100/len(order) {t.Fatal(s.View())}
}
func TestReboot(t *testing.T) {
 s:=New()
 for i:=0;i<len(order)-1;i++ {
  if s.RequireReboot()==nil||s.ConfirmReboot()==nil {t.Fatal("premature reboot")}
  if err:=s.Confirm(order[i]);err!=nil {t.Fatal(err)}
 }
 if s.RequireReboot()!=nil||s.RequireReboot()==nil||s.Confirm(PostBootVerified)==nil||!s.View().RebootRequired {t.Fatal(s.View())}
 if s.ConfirmReboot()!=nil||s.View().Percent!=100 {t.Fatal(s.View())}
}
func TestFailureBeforeActivation(t *testing.T) {
 for i:=0;i<3;i++ {
  s:=New();advance(t,s,i)
  if s.Fail()!=nil||s.View().Status!="failed_before_activation"||s.ConfirmRecovery()==nil||s.Confirm(order[i])==nil {t.Fatal(s.View())}
 }
}
func TestRecovery(t *testing.T) {
 for i:=3;i<len(order);i++ {
  for _,success:=range []bool{true,false} {
   s:=New();advance(t,s,i)
   if i==len(order)-1 {if s.RequireReboot()!=nil {t.Fatal(s.View())}}
   if s.Fail()!=nil||s.View().Status!="recovery_required"||s.Confirm(order[i])==nil||s.ConfirmReboot()==nil {t.Fatal(s.View())}
   if success {
    if s.ConfirmRecovery()!=nil||s.View().Status!="recovered_not_installed" {t.Fatal(s.View())}
   } else {
    if s.RecoveryFailed()!=nil||s.View().Status!="recovery_failed" {t.Fatal(s.View())}
   }
   if s.View().Percent==100||s.View().RebootRequired||s.Confirm(order[i])==nil {t.Fatal(s.View())}
  }
 }
}
func TestZeroValue(t *testing.T) {
 var s State
 if s.Confirm(Preflight)==nil||s.Fail()==nil||s.ConfirmReboot()==nil||s.RequireReboot()==nil {t.Fatal("uninitialized accepted")}
}
func TestConcurrentReaders(t *testing.T) {
 s:=New()
 var wg sync.WaitGroup
 for i:=0;i<8;i++ {
  wg.Add(1)
  go func(){
   defer wg.Done()
   prev:=0
   for j:=0;j<1000;j++ {
    v:=s.View()
    if v.Percent<prev||v.Percent>100||(v.Percent==100&&v.Status!="completed"){t.Errorf("inconsistent view: %+v",v);return}
    prev=v.Percent
   }
  }()
 }
 advance(t,s,len(order)-1)
 if s.RequireReboot()!=nil||s.ConfirmReboot()!=nil {t.Fatal(s.View())}
 wg.Wait()
}
