//go:build windows

package main

// Read-only consistency gate for a *proposed* resident migration. Verifying a
// backup and a journal separately is insufficient: an attacker or an operator
// error could pair the journal for one original motor with another backup.
// This gate NEVER arms a watchdog, schedules a task or authorizes a switch.
import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"

    "volve-browser-protection/motorupdate"
)

const chainLegacyMax = 80 << 20

type residentChainEvidence struct {
    LegacySHA256 string
    TaskXMLSHA256 string
    TargetSHA256 string
    TargetVersion string
    IntentNonce string
}

func digestResidentLive(ctx context.Context, path string) (string,error) {
    if err:=ctx.Err();err!=nil{return "",err}
    if !filepath.IsAbs(path)||filepath.Base(path)!=residentLegacyExe {
        return "",errors.New("legacy live motor path not allowlisted")
    }
    stat,err:=os.Lstat(path);if err!=nil{return "",err}
    if !stat.Mode().IsRegular()||stat.Size()<1||stat.Size()>chainLegacyMax {
        return "",errors.New("legacy live executable is linked or outside size bound")
    }
    file,err:=os.Open(path);if err!=nil{return "",err}
    defer file.Close()
    h:=sha256.New()
    n,err:=io.Copy(h,io.LimitReader(file,chainLegacyMax+1))
    if err!=nil{return "",err}
    if n!=stat.Size() || n>chainLegacyMax {
        return "",errors.New("legacy executable changed while hashing")
    }
    if err:=ctx.Err();err!=nil{return "",err}
    return hex.EncodeToString(h.Sum(nil)),nil
}

// auditPendingResidentChain is valid only *before* a production switch, when
// the original motor remains installed and the transaction is still pending.
// The actual future switch still requires the publisher-signed permit,
// independent SYSTEM watchdog and a live scheduler/DNS preflight.
func auditPendingResidentChain(ctx context.Context,root string)(residentChainEvidence,error) {
    var empty residentChainEvidence
    if err:=ctx.Err();err!=nil{return empty,err}
    backup,err:=auditResidentRollback(ctx,root)
    if err!=nil{return empty,fmt.Errorf("recovery backup not independently trusted: %w",err)}
    journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
    state,err:=auditResidentJournal(ctx,journalDir)
    if err!=nil{return empty,fmt.Errorf("recovery journal not independently trusted: %w",err)}
    if state.Status!="recovery-required" {
        return empty,fmt.Errorf("journal is %s, expected pending transaction",state.Status)
    }
    if state.Intent.LegacySHA256!=backup.LegacySHA256 ||
       state.Intent.TaskXMLSHA256!=backup.TaskXMLSHA256 {
        return empty,errors.New("journal identifies a different original motor or SYSTEM task")
    }
    active,err:=digestResidentLive(ctx,filepath.Join(root,residentLegacyExe))
    if err!=nil{return empty,err}
    if active!=backup.LegacySHA256 {
        return empty,errors.New("installed motor differs from protected fallback")
    }
    // Detect a late replacement while reading the installed motor. This is
    // read-only evidence, not an atomic handle or a substitute for the Windows
    // task switch boundary's own identity recheck.
    again,err:=auditResidentRollback(ctx,root)
    if err!=nil||again!=backup{return empty,errors.New("recovery backup changed during chain audit")}
    next,err:=auditResidentJournal(ctx,journalDir)
    if err!=nil||next!=state{return empty,errors.New("recovery journal changed during chain audit")}
    return residentChainEvidence{
        LegacySHA256:backup.LegacySHA256,
        TaskXMLSHA256:backup.TaskXMLSHA256,
        TargetSHA256:state.Intent.TargetSHA256,
        TargetVersion:state.Intent.TargetVersion,
        IntentNonce:state.Intent.Nonce,
    },nil
}

// Compile-time guard: the audited record is a fact to compare, not permission
// to construct or run a SignedLegacySwitchDriver.
var _ motorupdate.ResidentRecoveryJournalState
