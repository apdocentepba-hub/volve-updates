//go:build windows

package main

// These tests MUST NOT create a production task, install a motor, change DNS
// or run a production recovery. Windows CI uses an Administrator, not SYSTEM.
import (
 "context"
 "errors"
 "os"
 "strings"
 "testing"
 "time"
)

func TestPinnedResidentBootCLIFailsClosedWithoutActualSYSTEM(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 if err:=verifyResidentActualSYSTEM(ctx);err==nil{
  t.Skip("SYSTEM test runner must never exercise productive boot recovery")
 }
 before:=os.Getenv("ProgramData")
 root,err:=pinnedRecoveryInstalledRootWindows(ctx)
 if err==nil||root!=""{t.Fatalf("nonSYSTEM obtained product boot root: %q %v",root,err)}
 result,err:=runPinnedResidentBootRecoveryCLIWindows(ctx)
 if err==nil||result!=""{t.Fatalf("nonSYSTEM invoked signed protected boot: %q %v",result,err)}
 if os.Getenv("ProgramData")!=before{t.Fatal("refused boot modified process environment")}
}

func TestPinnedResidentBootCLIRefusesCancelledContext(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 result,err:=runPinnedResidentBootRecoveryCLIWindows(ctx)
 if result!=""||!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled signed boot did not fail closed: %q %v",result,err)
 }
 root,err:=pinnedRecoveryInstalledRootWindows(ctx)
 if root!=""||!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled root lookup did not fail closed: %q %v",root,err)
 }
}

func TestPinnedRecoveryBootCLIHasNoUserControlledRootOrAutomaticTask(t *testing.T){
 src,err:=os.ReadFile("main_windows.go");if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(src),
  "len(os.Args)==2 && os.Args[1]==\"--recover-pinned-signed-boot\""){
  t.Fatal("signed boot recovery command is absent or accepts user-controlled path arguments")
 }
 bridge,err:=os.ReadFile("resident_pinned_boot_cli_windows.go");if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(bridge),"verifyResidentActualSYSTEM")||
  !strings.Contains(string(bridge),"GetFolderPath('CommonApplicationData')")||
  !strings.Contains(string(bridge),"VOLVE-Browser-Filter"){
  t.Fatal("boot CLI is not restricted to the fixed LocalSystem Windows installation")
 }
 for _,forbidden:=range []string{
  "Register-ScheduledTask","Start-ScheduledTask","Set-DnsClientServerAddress",
  "os.Remove(","os.Rename(","os.Mkdir(",
 }{
  if strings.Contains(string(bridge),forbidden){
   t.Fatalf("fixed boot CLI registers a task, activates DNS or mutates files: %q",forbidden)
  }
 }
}
