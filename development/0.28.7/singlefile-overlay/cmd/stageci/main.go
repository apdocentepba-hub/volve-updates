// Command stageci extracts synthetic signed assets ONLY inside GitHub-hosted CI.
// It cannot install VOLVE, register tasks, change DNS or start the motor.
package main

import (
 "crypto/ed25519"
 "encoding/hex"
 "flag"
 "fmt"
 "os"
 "volve.local/installer/singlefile"
)

func main(){
 exe:=flag.String("exe","","signed single-file laboratory executable")
 out:=flag.String("out","","fresh VOLVE-CI- laboratory staging destination")
 keyHex:=flag.String("pubkey","","synthetic test Ed25519 public key")
 flag.Parse()
 if os.Getenv("GITHUB_ACTIONS")!="true" || os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" {
  fmt.Fprintln(os.Stderr,"REFUSED: disposable GitHub-hosted CI environment required")
  os.Exit(2)
 }
 key,err:=hex.DecodeString(*keyHex)
 if err!=nil||len(key)!=ed25519.PublicKeySize{fmt.Fprintln(os.Stderr,"missing synthetic test public key");os.Exit(2)}
 manifest,err:=singlefile.StageInLab(*exe,ed25519.PublicKey(key),*out)
 if err!=nil{fmt.Fprintln(os.Stderr,"REFUSED:",err);os.Exit(1)}
 fmt.Printf("PASS VOLVE_STAGE_VERIFIED_LAB release=%s items=%d NO_INSTALL NO_DNS_CHANGE\n",manifest.Release,len(manifest.Components))
}
