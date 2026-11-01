//go:build windows && volveci

package main

// CI-ONLY SOURCE INJECTION: this file is deliberately NOT in apply_overlay.go.
// The dedicated workflow copies it into the reconstructed VOLVE main package
// ONLY for a disposable hosted-VM recovery test. A normal product build never
// contains this alias, even when compiling the regular production sources.
//
// Existing protected rollback XML requires the exact "--dns-service" argument.
// On a throwaway VM we need to exercise that restored task with the ACTUAL
// VOLVE 400k+ DNS engine, not an imitation. This compile-time-only shim
// translates that one legacy CLI action to the already-isolated CI runner.
import (
 "fmt"
 "os"
 "path/filepath"
)

func init() {
 if len(os.Args)!=2 || os.Args[1]!="--dns-service" {return}
 exe,err:=os.Executable()
 if err!=nil || filepath.Base(exe)!="VOLVE_DNS_Server_0270.exe" {return}
 // A dedicated, predictable subdirectory inside this test's random TEMP root.
 // The real 0.28.7 production DNS parser loads the complete 400,002-rule feed
 // from here, rather than the user's ProgramData or Windows DNS configuration.
 labRoot:=filepath.Join(filepath.Dir(exe),"VOLVE-CI-FreshDNS53-413040")
 if err:=assertCIFreshVM(labRoot,ciFreshToken);err!=nil {
  fmt.Fprintln(os.Stderr,"VOLVE CI restored full motor refused:",err)
  os.Exit(1)
 }
 if err:=runCIFreshDNS53(labRoot,ciFreshToken);err!=nil{
  fmt.Fprintln(os.Stderr,"VOLVE CI restored full motor failed:",err)
  os.Exit(1)
 }
 os.Exit(0)
}
