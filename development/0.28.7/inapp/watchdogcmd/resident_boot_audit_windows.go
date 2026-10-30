//go:build windows

package main

// Step 3 independent startup classifier. It only reads the protected boot
// transaction; it is NOT the production SYSTEM restore driver. In particular,
// a valid journal is never a publisher permit and this file cannot change DNS.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentBootAudit struct{
 Status string
 Action string
 LegacySHA256 string
}

// auditResidentBootPlan is safe for a new, independent process to invoke
// after the writer has exited. A valid pending transaction is classified as
// "recover-original" ONLY if the original EXE, XML and journal hashes/ACLs
// remain bound. Any ambiguity fails closed; terminal receipts never trigger
// a new rollback.
func auditResidentBootPlan(ctx context.Context,root string)(residentBootAudit,error){
 var empty residentBootAudit
 if err:=ctx.Err();err!=nil{return empty,err}
 if !filepath.IsAbs(root){return empty,errors.New("boot audit install root not absolute")}
 info,err:=os.Lstat(root)
 if err!=nil{return empty,err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{
  return empty,errors.New("boot audit root redirected")
 }
 dir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=auditResidentJournal(ctx,dir)
 if err!=nil{return empty,fmt.Errorf("protected boot journal rejected: %w",err)}
 switch state.Status{
 case "not-armed","committed","restored":
  return residentBootAudit{Status:state.Status,Action:"no-action",LegacySHA256:state.Intent.LegacySHA256},nil
 case "recovery-required":
  chain,err:=auditPendingResidentChain(ctx,root)
  if err!=nil{return empty,fmt.Errorf("pending boot backup/journal chain rejected: %w",err)}
  if chain.LegacySHA256!=state.Intent.LegacySHA256 ||
     chain.TaskXMLSHA256!=state.Intent.TaskXMLSHA256 ||
     chain.TargetSHA256!=state.Intent.TargetSHA256 ||
     chain.TargetVersion!=state.Intent.TargetVersion ||
     chain.IntentNonce!=state.Intent.Nonce {
    return empty,errors.New("boot chain changed between protected reads")
  }
  return residentBootAudit{Status:"recovery-required",Action:"recover-original",LegacySHA256:chain.LegacySHA256},nil
 default:
  return empty,errors.New("unexpected boot recovery journal status")
 }
}
