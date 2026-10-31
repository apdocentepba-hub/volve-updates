//go:build windows

package motorupdate

// An opt-in Windows DNS command adapter for a dedicated, controlled lab.
// No product command, task, service or update controller calls this module.
// A future privileged caller must verify a signed, sealed recovery journal,
// snapshot provenance, process identity and an exclusive transaction lock.
import (
    "context"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "reflect"
    "strings"
)

// WindowsDNSNativeInvoke is deliberately injectable. A production invoker
// MUST use exec.CommandContext with an absolute netsh executable and an argv
// slice, never cmd.exe, PowerShell interpolation or a shell command string.
type WindowsDNSNativeInvoke func(context.Context, []string) error

// DefaultWindowsDNSNativeInvoke is implemented but NOT wired to VOLVE's
// installed app. It is only safe when called by a separately authenticated,
// locked recovery driver against a dedicated test adapter. It does not
// authorize an interface or a recovery attempt by itself.
func DefaultWindowsDNSNativeInvoke(ctx context.Context, args []string) error {
    if err:=ctx.Err();err!=nil{return err}
    systemRoot:=os.Getenv("SystemRoot")
    if systemRoot==""||!filepath.IsAbs(systemRoot){
        return errors.New("Windows system root unavailable")
    }
    executable:=filepath.Join(systemRoot,"System32","netsh.exe")
    info,err:=os.Lstat(executable)
    if err!=nil{return fmt.Errorf("native netsh executable unavailable: %w",err)}
    if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0 {
        return errors.New("native netsh executable is not a regular file")
    }
    cmd:=exec.CommandContext(ctx,executable,args...)
    output,err:=cmd.CombinedOutput()
    if err!=nil{
        // Do not leak arbitrary command output or credentials to updater logs.
        return fmt.Errorf("native Windows DNS operation failed: %w",err)
    }
    _=output
    return nil
}

type windowsPinnedRestoreAction struct {
    record DNSRestoreRecord
    index uint32
    command WindowsDNSCommand
}

// NewWindowsPinnedStaticDNSWriter pins every permitted command to a complete
// GUID/family+current InterfaceIndex binding and the exact historical DNS
// list. It never accepts a free-form netsh argv from the recovery journal.
// Live adapter identity is rechecked immediately before every invocation.
// Caller MUST pass an authenticated runner and invoke via the batch restore,
// which independently checks observed DNS before and after each write.
func NewWindowsPinnedStaticDNSWriter(
    ctx context.Context,
    records []DNSRestoreRecord,
    inspect WindowsReadOnlyPowerShell,
    invoke WindowsDNSNativeInvoke,
) (WindowsDNSRestoreWriter,error) {
    if inspect==nil||invoke==nil||len(records)==0{return nil,errors.New("missing trusted recovery inputs")}
    if err:=ctx.Err();err!=nil{return nil,err}
    actions:=make([]windowsPinnedRestoreAction,0)
    seen:=map[string]bool{}
    for _,r:=range records {
        if err:=validateWindowsStaticRecoveryRecord(r);err!=nil{return nil,err}
        key:=strings.ToLower(r.Original.InterfaceGUID)+string(r.Original.Family)
        if seen[key]{return nil,errors.New("duplicate adapter/family in pinned recovery")}
        seen[key]=true
        index,_,err:=observeWindowsDNSRestoreStage(ctx,r,inspect)
        if err!=nil{return nil,err}
        cmds,err:=PlanWindowsDNSRestore(r.Original,index)
        if err!=nil{return nil,err}
        for _,cmd:=range cmds {
            actions=append(actions,windowsPinnedRestoreAction{record:r,index:index,command:cmd})
        }
    }
    return func(ctx context.Context,got WindowsDNSCommand) error {
        if err:=ctx.Err();err!=nil{return err}
        var authorized *windowsPinnedRestoreAction
        for i:=range actions {
            a:=&actions[i]
            if got.Program==a.command.Program&&reflect.DeepEqual(got.Args,a.command.Args) {
                if authorized!=nil{return errors.New("ambiguous pinned DNS command")}
                authorized=a
            }
        }
        if authorized==nil{return errors.New("DNS recovery command not pinned to verified journal")}
        index,err:=FindWindowsAdapterIndex(ctx,authorized.record.Original.InterfaceGUID,inspect)
        if err!=nil||index!=authorized.index{
            return errors.New("DNS adapter identity changed before native command")
        }
        // Immutable pinned argv. No external strings are interpolated into
        // a shell, and no DNS mutation occurs without a supplied invoker.
        return invoke(ctx,append([]string(nil),authorized.command.Args...))
    },nil
}
