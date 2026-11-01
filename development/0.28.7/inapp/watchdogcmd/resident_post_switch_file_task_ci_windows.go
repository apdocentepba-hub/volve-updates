//go:build windows

package main

// Isolated Windows CI-only integration for a missing original executable
// followed by restoration of a disposable SYSTEM Scheduler task. No product
// task, adapters, DNS, live motor or terminal recovery receipts are touched.
//
// This is NOT a production restorer: it cannot overwrite an existing new
// engine, prove a publisher-signed permission or confirm active DNS health.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)

func restoreMissingOriginalAndDisposableTaskCILab(
 ctx context.Context,root,pilotTask string,
 runPS func(context.Context,string)(string,error),
)error{
 if err:=ctx.Err();err!=nil{return err}
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
  !pilotTaskPattern.MatchString(pilotTask)||
  runPS==nil||!filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return errors.New("integrated file/task restoration reserved for hosted Windows CI only")
 }
 suffix:=strings.TrimPrefix(pilotTask,"VOLVE-CI-ManagedMotor-")
 release,err:=acquireCIBootMutex(ctx,"VOLVE-CI-BootLock-"+suffix)
 if err!=nil{return fmt.Errorf("cannot lock disposable restoration: %w",err)}
 defer release()
 // The missing EXE is prepared from the old sealed backup without clobbering
 // any other installed motor. After that, the existing task import path
 // requires the original EXE to match that protected copy byte for byte.
 if err:=restoreMissingLegacyExecutableCILab(ctx,root,pilotTask);err!=nil{
  return fmt.Errorf("original bytes cannot be reconstructed: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 // Revalidates the original snapshot/journal and the disposable live task,
 // then imports only the expected single-SYSTEM-action original XML.
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(ctx,root,pilotTask,runPS);err!=nil{
  return fmt.Errorf("original disposable SYSTEM task not restored: %w",err)
 }
 // The journal must remain pending until separate SYSTEM identity, DNS v4/v6
 // and Internet health checks succeed; this function writes no receipt.
 return nil
}
