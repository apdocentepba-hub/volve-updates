//go:build windows

package main

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestSignedCombinedPublisherBindingRejectsInteractiveRunner(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
 defer cancel()
 if err:=verifyResidentActualSYSTEM(ctx);err==nil{
  t.Skip("SYSTEM runner: never exercise production-named rollback in a unit test")
 }
 err:=recoverSignedOriginalAndSYSTEMTaskWithPublisherBindingWindows(ctx,t.TempDir())
 if err==nil{t.Fatal("interactive Windows token accessed production-signed recovery")}
}
func TestSignedCombinedPublisherBindingRejectsCancelledOrUnrelatedStages(t *testing.T){
 root:=t.TempDir()
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 err:=sealResidentOriginalRecoveryStageNTFS(ctx,root,
  filepath.Join(root,".volve-signed-original-recovery-synthetic"))
 if !errors.Is(err,context.Canceled){
  t.Fatalf("cancelled NTFS sealing was permitted: %v",err)
 }
 err=recoverSignedOriginalAndSYSTEMTaskWithPublisherBindingWindows(ctx,root)
 if !errors.Is(err,context.Canceled){
  t.Fatalf("cancelled recovery reached critical path: %v",err)
 }
 ctx2,stop:=context.WithTimeout(context.Background(),15*time.Second)
 defer stop()
 if err:=verifyResidentActualSYSTEM(ctx2);err==nil{
  t.Skip("test does not touch files under real SYSTEM token")
 }
 foreign:=filepath.Join(t.TempDir(),"unrelated.exe")
 payload:=[]byte("MZ-DONT-CHANGE")
 if err:=os.WriteFile(foreign,payload,0600);err!=nil{t.Fatal(err)}
 if err:=sealResidentOriginalRecoveryStageNTFS(ctx2,root,foreign);err==nil{
  t.Fatal("non-SYSTEM identity sealed an unrelated file")
 }
 found,err:=os.ReadFile(foreign)
 if err!=nil||string(found)!=string(payload){
  t.Fatalf("foreign file modified during refused NTFS stage operation: %v",err)
 }
}
