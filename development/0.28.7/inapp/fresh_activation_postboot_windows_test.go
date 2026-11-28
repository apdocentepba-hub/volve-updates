//go:build windows

package motorupdate

import(
 "context"
 "os"
 "testing"
)

func TestFreshBootIdentityRejectsSameBootAndInconsistentEvidence(t *testing.T){
 before:=freshBootIdentity{1800000000000,123,1800000001000}
 after:=freshBootIdentity{1800000300000,234,1800000301000}
 wall:=before.BootUnixMilli+900000
 if err:=validateFreshBootSample(before,wall,wall+2000,900000,902000);err!=nil{t.Fatal(err)}
 if err:=verifyFreshLaterBoot(before,after);err!=nil{t.Fatal(err)}
 for _,b:=range []freshBootIdentity{before,{before.BootUnixMilli,234,before.StartEventUnixMilli},{after.BootUnixMilli,123,after.StartEventUnixMilli},{after.BootUnixMilli,234,after.BootUnixMilli-600000},{0,234,0},{after.BootUnixMilli,0,after.StartEventUnixMilli}}{
  if err:=verifyFreshLaterBoot(before,b);err==nil{t.Fatal("same/ambiguous boot accepted",b)}
 }
 if err:=validateFreshBootSample(before,wall,wall+2000,1000,3000);err==nil{t.Fatal("wall-clock evidence accepted despite incompatible kernel uptime")}
 if err:=validateFreshBootSample(before,wall,wall+2000,900000,899999);err==nil{t.Fatal("backwards kernel uptime accepted")}
 t.Log("PASS VOLVE_FRESH_BOOT_IDENTITY_REFUSES_SAME_BOOT_CLOCK_ONLY")
}
func TestWindowsFreshNativeBootObservationReadOnly(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted native boot observation only")}
 first,err:=observeFreshBootNative(context.Background());if err!=nil{t.Fatal(err)}
 second,err:=observeFreshBootNative(context.Background());if err!=nil{t.Fatal(err)}
 if first!=second{t.Fatal("native boot identity not stable within same boot")}
 if err:=verifyFreshLaterBoot(first,second);err==nil{t.Fatal("same Windows session accepted as reboot")}
 t.Log("PASS VOLVE_FRESH_NATIVE_BOOT_WMI_EVENT_KERNEL_UPTIME_READ_ONLY")
}
