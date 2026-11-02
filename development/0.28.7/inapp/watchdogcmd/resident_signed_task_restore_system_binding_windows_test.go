//go:build windows

package main

import (
 "context"
 "errors"
 "testing"
 "time"
)

// This test never calls a mutation: in a normal hosted runner the restricted
// production wrapper MUST reject the admin user before accessing any journal.
func TestSignedProductionSYSTEMTaskRestoreRejectsInteractiveWindowsRunner(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 defer cancel()
 if err:=verifyResidentActualSYSTEM(ctx);err==nil {
  t.Skip("runner is legitimately SYSTEM; never exercise a production-name restore in tests")
 }
 if err:=restoreSignedOriginalSYSTEMTaskWithPinnedPublisherWindows(ctx,t.TempDir());err==nil{
  t.Fatal("non-SYSTEM Windows runner was allowed to invoke production task restoration")
 }
}

func TestSignedProductionSYSTEMTaskRestoreRejectsCancelledContext(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 if err:=verifyResidentActualSYSTEM(ctx);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled SYSTEM verification continued: %v",err)
 }
 if err:=restoreSignedOriginalSYSTEMTaskWithPinnedPublisherWindows(ctx,
  t.TempDir());!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled production task recovery continued: %v",err)
 }
}
