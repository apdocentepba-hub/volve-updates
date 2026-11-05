package signedstage

import (
 "context"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "testing"
 "time"
)

func TestConcurrentStageAndRecoveryCannotInterfere(t *testing.T){
 src,dst,pub:=signedFixture(t)
 entered:=make(chan struct{})
 release:=make(chan struct{})
 done:=make(chan error,1)
 go func(){
  paused:=false
  _,err:=prepare(context.Background(),src,dst,pub,func(string)error{
   if !paused{
    paused=true
    close(entered)
    <-release
   }
   return nil
  })
  done<-err
 }()
 select {case <-entered:case <-time.After(15*time.Second):close(release);t.Fatal("stage worker did not reach pending write")}
 if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub);err==nil{
  close(release)
  t.Fatal("recovery started while source writer owned transaction")
 }
 if _,err:=PrepareInactiveLabVersion(context.Background(),src,dst,pub);err==nil{
  close(release)
  t.Fatal("second concurrent version preparation was permitted")
 }
 if _,err:=os.Stat(dst+".pending");err!=nil{
  close(release)
  t.Fatal("first writer pending directory was modified:",err)
 }
 close(release)
 select {
 case err:=<-done:
  if err!=nil{t.Fatal("first writer failed after concurrent rejected operations:",err)}
 case <-time.After(15*time.Second):
  t.Fatal("stage worker did not finish")
 }
 if _,err:=os.Stat(dst);err!=nil{t.Fatal("original stage was not promoted safely:",err)}
 requireAbsent(t,dst+".pending")
}

func TestProcessCrashReleasesExclusiveKernelLock(t *testing.T){
 // The helper exits without releasing: verify the OS owns lifetime of lock.
 if os.Getenv("VOLVE_CI_MUTEX_TEST_CHILD")=="1"{
  dst:=os.Getenv("VOLVE_CI_MUTEX_TEST_DESTINATION")
  release,err:=acquireStageLock(dst)
  if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(3)}
  _=release
  fmt.Println("CI_LOCK_ACQUIRED_THEN_PROCESS_EXITED_WITHOUT_RELEASE")
  os.Exit(0)
 }
 dir:=t.TempDir()
 dst:=filepath.Join(dir,PreparedPrefix+"CRASH-RECOVERY")
 child:=exec.Command(os.Args[0],"-test.run=^TestProcessCrashReleasesExclusiveKernelLock$")
 child.Env=append(os.Environ(),"VOLVE_CI_MUTEX_TEST_CHILD=1","VOLVE_CI_MUTEX_TEST_DESTINATION="+dst)
 childOutput,err:=child.CombinedOutput()
 if err!=nil{t.Fatalf("helper could not acquire OS-owned mutex: %v %s",err,childOutput)}
 release,err:=acquireStageLock(dst)
 if err!=nil{t.Fatalf("process exit left an unrecoverable mutex lock: %v",err)}
 release()
}
