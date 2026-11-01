//go:build windows

package main

// The independent watchdog's actual read-only boot audit now uses the same
// protected kernel transition mutex as the privileged updater and the future
// production recovery policy. It cannot inspect an in-flight journal while
// another owner may be switching the real motor. This is NOT a restorer.
import (
 "context"
 "errors"
 "fmt"

 "volve-browser-protection/motorupdate"
)

func auditResidentBootPlanProtected(ctx context.Context,root string)(residentBootAudit,error){
 var empty residentBootAudit
 if err:=ctx.Err();err!=nil{return empty,err}
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return empty,fmt.Errorf("exclusive protected boot audit refused: %w",err)}
 if release==nil{return empty,errors.New("protected boot audit acquired no Windows lease")}
 defer release()
 if err:=ctx.Err();err!=nil{return empty,err}
 return auditResidentBootPlan(ctx,root)
}
