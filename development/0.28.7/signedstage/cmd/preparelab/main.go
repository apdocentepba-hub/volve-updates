// Command preparelab is CI-only. It does NOT install, update, uninstall,
// activate a Windows task or alter the system DNS configuration.
package main
import (
"context"
"crypto/ed25519"
"encoding/hex"
"flag"
"fmt"
"os"
"path/filepath"
"time"
"volve.local/installer/signedstage"
)
func main(){
 source:=flag.String("source","","already authenticated synthetic staged source")
 destination:=flag.String("out","","fresh inactive VOLVE-CI-VERSION- directory")
 keyHex:=flag.String("pubkey","","independent CI-only Ed25519 publisher key")
 recover:=flag.Bool("recover-pending",false,"recover abandoned, independently authenticated CI-only pending stage")
 flag.Parse()
 root:=os.Getenv("RUNNER_TEMP")
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||root==""||!filepath.IsAbs(root)||filepath.Dir(*source)!=root||filepath.Dir(*destination)!=root{
  fmt.Fprintln(os.Stderr,"REFUSED: only GitHub-hosted disposable temporary CI staging permitted");os.Exit(2)
 }
 public,err:=hex.DecodeString(*keyHex)
 if err!=nil||len(public)!=ed25519.PublicKeySize{fmt.Fprintln(os.Stderr,"REFUSED: pinned Ed25519 public key required");os.Exit(2)}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 if *recover{
  outcome,err:=signedstage.RecoverAbandonedInactiveLabStage(ctx,*source,*destination,public)
  if err!=nil{fmt.Fprintln(os.Stderr,"REFUSED: unsafe abandoned CI pending recovery:",err);os.Exit(1)}
  fmt.Printf("PASS VOLVE_LAB_ABANDONED_STAGE_RECOVERY status=%s NO_ACTIVATION NO_DNS NO_TASKS NO_RELEASE\n",outcome)
  return
 }
 m,err:=signedstage.PrepareInactiveLabVersion(ctx,*source,*destination,public)
 if err!=nil{fmt.Fprintln(os.Stderr,"REFUSED: inactive staging:",err);os.Exit(1)}
 fmt.Printf("PASS VOLVE_SEVEN_COMPONENT_INACTIVE_VERSION_PREPARED release=%s items=%d NO_ACTIVATION NO_DNS NO_TASKS NO_RELEASE\n",m.Release,len(m.Components))
}
