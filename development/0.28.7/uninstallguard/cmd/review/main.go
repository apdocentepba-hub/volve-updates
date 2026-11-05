// VOLVE uninstaller OWNERSHIP REVIEW only. This program has no mutators.
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "time"

    "volve.local/uninstallguard"
)

func main() {
    if len(os.Args)!=2 || os.Args[1]!="--review-only" {
        fmt.Fprintln(os.Stderr,"VOLVE uninstaller review only. Use --review-only (NO UNINSTALL).")
        os.Exit(2)
    }
    ctx,cancel:=context.WithTimeout(context.Background(),50*time.Second)
    defer cancel()
    evidence,err:=uninstallguard.InspectWindowsReadOnly(ctx)
    if err!=nil {
        fmt.Fprintln(os.Stderr,"VOLVE uninstall census rejected:",err)
        os.Exit(1)
    }
    plan,err:=uninstallguard.Review(evidence)
    if err!=nil {
        fmt.Fprintln(os.Stderr,"VOLVE unsigned removal evidence rejected:",err)
        os.Exit(1)
    }
    if err:=json.NewEncoder(os.Stdout).Encode(plan);err!=nil {
        fmt.Fprintln(os.Stderr,"VOLVE audit output failed:",err)
        os.Exit(1)
    }
}
