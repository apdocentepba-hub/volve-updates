package browserpolicytx

import (
    "context"
    "errors"
    "fmt"
)

// LabStore is deliberately NOT a Windows registry writer. Implementations
// must create only absent entries atomically and must not overwrite values.
// Native production registry writes require an independently approved,
// durable SYSTEM transaction and are not implemented in this module.
type LabStore interface {
    Exists(context.Context,Value)(bool,error)
    CreateOnly(context.Context,Value)error
    DeleteOnlyIfEqual(context.Context,Value)error
}

type TrialResult struct {
    Checked int `json:"checked"`
    Created int `json:"created"`
    Reverted int `json:"reverted"`
    State string `json:"state"`
    CanInstall bool `json:"can_install"`
}

// Rehearse enforces refusal of any pre-existing (unowned) value, then applies
// the fully validated policy to a lab store and rolls ALL writes back in
// reverse order, even if the caller canceled or a later write failed.
// A crash can interrupt this IN-MEMORY simulation. It is not production
// crash-recovery evidence, a persistent journal or an installation driver.
func Rehearse(ctx context.Context,plan Plan,store LabStore)(TrialResult,error) {
    var zero TrialResult
    if ctx==nil||store==nil {return zero,errors.New("context and lab store required")}
    if err:=ctx.Err();err!=nil{return zero,err}
    if err:=Validate(plan);err!=nil{return zero,err}
    for _,v:=range plan.RegistryValues {
        if err:=ctx.Err();err!=nil{return zero,err}
        found,err:=store.Exists(ctx,v)
        if err!=nil{return zero,fmt.Errorf("preflight failed closed: %w",err)}
        if found{return zero,fmt.Errorf("pre-existing value %s/%s prevents ownership assumption",v.Key,v.Name)}
    }
    created:=make([]Value,0,len(plan.RegistryValues))
    result:=TrialResult{Checked:len(plan.RegistryValues),State:"LAB_NOT_RELEASE"}
    // Rollback must not use an already canceled request context.
    rollback:=func()error {
        var failures []error
        for i:=len(created)-1;i>=0;i-- {
            if err:=store.DeleteOnlyIfEqual(context.Background(),created[i]);err!=nil{
                failures=append(failures,fmt.Errorf("rollback %s/%s: %w",created[i].Key,created[i].Name,err))
            }else{result.Reverted++}
        }
        return errors.Join(failures...)
    }
    for _,v:=range plan.RegistryValues {
        if err:=ctx.Err();err!=nil{
            back:=rollback()
            if back!=nil{return result,errors.Join(err,back)}
            return result,err
        }
        if err:=store.CreateOnly(ctx,v);err!=nil{
            back:=rollback()
            if back!=nil{return result,errors.Join(err,back)}
            return result,err
        }
        created=append(created,v)
        result.Created++
    }
    if err:=rollback();err!=nil {return result,fmt.Errorf("incomplete lab rollback: %w",err)}
    for _,v:=range plan.RegistryValues {
        found,err:=store.Exists(context.Background(),v)
        if err!=nil||found{return result,errors.New("post-rollback lab state is not clean")}
    }
    result.State="LAB_ROLLBACK_COMPLETE_NO_INSTALL"
    return result,nil
}
