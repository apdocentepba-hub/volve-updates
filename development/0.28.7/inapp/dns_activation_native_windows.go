//go:build windows

package motorupdate

// Native Windows adapter for the future authenticated DNS activation.
// This file contains no public installation command or scheduled task.
// It can only be constructed within motorupdate with a verified original
// journal, an injected protected recovery guard and a fixed netsh invoker.
// The CI tests inject an in-memory invoker, never alter Windows DNS.
import (
 "context"
 "errors"
 "fmt"
 "strings"
)

type windowsActivationPinnedFamily struct {
 record DNSRestoreRecord
 index uint32
}

type windowsPinnedDNSActivationBackend struct {
 pinned map[string]windowsActivationPinnedFamily
 inspect WindowsReadOnlyPowerShell
 invoke WindowsDNSNativeInvoke
 guard DNSActivationSafetyGuard
 journalSHA256 string
}

func windowsActivationFamilyKey(guid string, family DNSAddressFamily)string {
 return strings.ToLower(guid)+"|"+string(family)
}

// newWindowsPinnedDNSActivationBackend refuses untrusted or incomplete DNS
// evidence. The constructor itself NEVER calls a Windows DNS writer.
// A production SYSTEM controller must independently establish the real
// publisher-signed grant, sealed NTFS backup and boot watchdog behind guard.
func newWindowsPinnedDNSActivationBackend(
 ctx context.Context, journal []byte, independentlyPinnedSHA256 string,
 inspect WindowsReadOnlyPowerShell, invoke WindowsDNSNativeInvoke,
 guard DNSActivationSafetyGuard,
)(*windowsPinnedDNSActivationBackend,error){
 if ctx==nil||inspect==nil||invoke==nil||guard==nil{
  return nil,errors.New("native DNS activation requires Windows inventory, writer and trusted recovery guard")
 }
 if err:=ctx.Err();err!=nil{return nil,err}
 records,err:=VerifyDNSOriginalJournal(ctx,journal,independentlyPinnedSHA256)
 if err!=nil{return nil,fmt.Errorf("original DNS journal pin rejected: %w",err)}
 if err:=guard.VerifyArmed(ctx,independentlyPinnedSHA256);err!=nil{
  return nil,fmt.Errorf("protected boot recovery not armed: %w",err)
 }
 backend:=&windowsPinnedDNSActivationBackend{
  pinned:make(map[string]windowsActivationPinnedFamily,len(records)),
  inspect:inspect,invoke:invoke,guard:guard,journalSHA256:independentlyPinnedSHA256,
 }
 for _,record:=range records{
  index,err:=FindWindowsAdapterIndex(ctx,record.Original.InterfaceGUID,inspect)
  if err!=nil{return nil,fmt.Errorf("untrusted original adapter identity: %w",err)}
  key:=windowsActivationFamilyKey(record.Original.InterfaceGUID,record.Original.Family)
  if _,exists:=backend.pinned[key];exists{return nil,errors.New("duplicate protected adapter/family")}
  backend.pinned[key]=windowsActivationPinnedFamily{record:record,index:index}
 }
 // Verify EVERY original Windows DNS source before returning any runnable
 // backend. A changed secondary IPv6 adapter cannot be ignored.
 for _,record:=range records{
  current,err:=backend.Read(ctx,record.Original.InterfaceGUID,record.Original.Family)
  if err!=nil{return nil,err}
  if !sameDNSState(current,record.Original){
   return nil,errors.New("native activation original DNS is no longer identical to authenticated backup")
  }
 }
 if err:=guard.VerifyArmed(ctx,independentlyPinnedSHA256);err!=nil{
  return nil,fmt.Errorf("recovery became unarmed during native preflight: %w",err)
 }
 return backend,nil
}

func(b *windowsPinnedDNSActivationBackend)Read(
 ctx context.Context,guid string,family DNSAddressFamily,
)(DNSServerState,error){
 var denied DNSServerState
 if b==nil||b.inspect==nil||ctx==nil{return denied,errors.New("native DNS inspection unavailable")}
 if err:=ctx.Err();err!=nil{return denied,err}
 key:=windowsActivationFamilyKey(guid,family)
 pinned,ok:=b.pinned[key]
 if !ok{return denied,errors.New("DNS adapter/family not in authenticated original journal")}
 index,err:=FindWindowsAdapterIndex(ctx,guid,b.inspect)
 if err!=nil||index!=pinned.index{return denied,errors.New("DNS adapter GUID or InterfaceIndex changed")}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,b.inspect)
 if err!=nil{return denied,err}
 var match *DNSServerState
 for i:=range observed.States{
  item:=&observed.States[i]
  if windowsActivationFamilyKey(item.InterfaceGUID,item.Family)==key{
   if match!=nil{return denied,errors.New("duplicate live DNS adapter family")}
   match=item
  }
 }
 if match==nil{return denied,errors.New("original adapter DNS family disappeared")}
 rechecked,err:=FindWindowsAdapterIndex(ctx,guid,b.inspect)
 if err!=nil||rechecked!=index{return denied,errors.New("DNS adapter identity changed during readback")}
 return copyWindowsActivationDNSState(*match),nil
}

func copyWindowsActivationDNSState(s DNSServerState)DNSServerState{
 s.Servers=append([]string(nil),s.Servers...)
 return s
}

// Apply accepts ONLY the exact pinned localhost target, never arbitrary
// DNS servers or UI-supplied commands. The recovery guard is independently
// rechecked immediately before invoking native netsh. The coordinator also
// checks every IPv4/IPv6 family before and after every mutation.
func(b *windowsPinnedDNSActivationBackend)Apply(ctx context.Context,next DNSServerState)error{
 if b==nil||b.inspect==nil||b.invoke==nil||b.guard==nil||ctx==nil{
  return errors.New("protected native DNS writer unavailable")
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=validDNSState(next);err!=nil{return err}
 pinned,ok:=b.pinned[windowsActivationFamilyKey(next.InterfaceGUID,next.Family)]
 if !ok||!sameDNSState(next,pinned.record.Expected){
  return errors.New("DNS mutation not pinned to signed localhost journal")
 }
 before,err:=b.Read(ctx,next.InterfaceGUID,next.Family)
 if err!=nil{return err}
 if !sameDNSState(before,pinned.record.Original){
  return errors.New("DNS source changed before protected localhost write")
 }
 if err:=b.guard.VerifyArmed(ctx,b.journalSHA256);err!=nil{
  return fmt.Errorf("watchdog or publisher authorization not armed at native write: %w",err)
 }
 // Rebind GUID after the authorization call, to reject adapter replacement.
 index,err:=FindWindowsAdapterIndex(ctx,next.InterfaceGUID,b.inspect)
 if err!=nil||index!=pinned.index{return errors.New("DNS interface identity changed after authorization")}
 cmds,err:=PlanWindowsDNSRestore(next,index)
 if err!=nil{return err}
 if len(cmds)!=1||cmds[0].Program!="netsh.exe"{
  return errors.New("native DNS activation must be a single family-scoped localhost command")
 }
 if err:=validatePinnedWindowsDNSArgv(cmds[0].Args);err!=nil{return err}
 // A publisher/boot guard may take time to re-attest; during that window,
 // another process could change DNS after our first read. Never clobber it.
 immediatelyBefore,err:=b.Read(ctx,next.InterfaceGUID,next.Family)
 if err!=nil{return fmt.Errorf("native DNS last-moment source verification failed: %w",err)}
 if !sameDNSState(immediatelyBefore,pinned.record.Original){
  return errors.New("DNS assignment changed after watchdog attestation; refuse native write")
 }
 if err:=b.invoke(ctx,append([]string(nil),cmds[0].Args...));err!=nil{
  return fmt.Errorf("native localhost DNS write failed: %w",err)
 }
 after,err:=b.Read(ctx,next.InterfaceGUID,next.Family)
 if err!=nil{return fmt.Errorf("independent native DNS write readback unavailable: %w",err)}
 if !sameDNSState(after,next){
  return errors.New("native DNS did not equal expected localhost after write")
 }
 return nil
}
