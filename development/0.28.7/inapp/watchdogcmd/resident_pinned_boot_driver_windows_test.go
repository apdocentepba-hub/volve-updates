//go:build windows

package main

// Negative tests only. They cannot instantiate or start a production DNS
// watchdog on ordinary Windows, nor install tasks or alter DNS adapters.
import (
 "context"
 "errors"
 "path/filepath"
 "testing"
 "time"
)

func TestPinnedResidentBootDriverRejectsCancelledOrRelativeRoot(t *testing.T){
 cancelled,stop:=context.WithCancel(context.Background())
 stop()
 if driver,err:=newPinnedResidentBootRecoveryDriverWindows(cancelled,t.TempDir());driver!=nil||
  !errors.Is(err,context.Canceled){
  t.Fatalf("cancelled signed watchdog constructor not refused: driver=%v err=%v",driver,err)
 }
 ctx,done:=context.WithTimeout(context.Background(),15*time.Second)
 defer done()
 if driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,"relative");driver!=nil||err==nil {
  t.Fatalf("noncanonical root permitted to construct signed SYSTEM driver: driver=%v err=%v",driver,err)
 }
 if driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,t.TempDir()+string(filepath.Separator)+"..");driver!=nil||err==nil {
  t.Fatalf("non-clean root permitted to construct signed SYSTEM driver: driver=%v err=%v",driver,err)
 }
}

func TestPinnedResidentBootDriverRejectsInteractiveWindowsToken(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
 defer cancel()
 // CI normally runs as elevated Admin, not SYSTEM. On a SYSTEM runner the
 // test skips rather than constructing a production-identity controller.
 if err:=verifyResidentActualSYSTEM(ctx);err==nil{
  t.Skip("SYSTEM identity: skip constructor instead of creating productive-identity driver")
 }
 driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,t.TempDir())
 if err==nil||driver!=nil{
  t.Fatalf("admin/user token constructed privileged boot driver: %v",err)
 }
}
