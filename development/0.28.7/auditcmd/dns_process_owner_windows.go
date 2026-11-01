//go:build windows

package main

// This is an optional, independent READ-ONLY observation of which SYSTEM
// process owns the two exact UDP/53 loopback sockets. It NEVER attests to
// Scheduler parentage, a publisher signature, health, version or permission
// to replace an existing motor.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "time"
)

const windowsVOLVEDNSOwnerQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$records=@(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {[int]$_.LocalPort -eq 53});
$v4=@($records | Where-Object {[string]$_.LocalAddress -eq '127.0.0.1'});
$v6=@($records | Where-Object {[string]$_.LocalAddress -eq '::1'});
$result=[ordered]@{
 schema=1; exact_ipv4_socket=($v4.Count -eq 1);
 exact_ipv6_socket=($v6.Count -eq 1);
 same_nonzero_pid=$false; process_observed=$false;
 system_owner=$false; legacy_executable_path_match=$false;
 dns_service_args_match=$false;
};
if($v4.Count -eq 1 -and $v6.Count -eq 1){
 $v4pid=[int]$v4[0].OwningProcess;$v6pid=[int]$v6[0].OwningProcess;
 if($v4pid -gt 0 -and $v4pid -eq $v6pid){
  $result.same_nonzero_pid=$true;
  $procs=@(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId="+$v4pid) -ErrorAction Stop);
  if($procs.Count -eq 1){
   $proc=$procs[0];$result.process_observed=$true;
   $owner=Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid -ErrorAction Stop;
   if([int]$owner.ReturnValue -eq 0 -and [string]$owner.Sid -eq 'S-1-5-18'){
    $result.system_owner=$true
   };
   $base=[string]$env:ProgramData;
   if([IO.Path]::IsPathRooted($base)){
    $expected=[IO.Path]::GetFullPath([IO.Path]::Combine($base,'VOLVE-Browser-Filter','VOLVE_DNS_Server_0270.exe'));
    if([string]::Equals([string]$proc.ExecutablePath,$expected,[StringComparison]::OrdinalIgnoreCase)){
     $result.legacy_executable_path_match=$true;
     $cmd=[string]$proc.CommandLine;
     $result.dns_service_args_match=($cmd -ceq ($expected+' --dns-service') -or $cmd -ceq ('"'+$expected+'" --dns-service'))
    }
   }
  }
 }
};
ConvertTo-Json -InputObject ([pscustomobject]$result) -Compress -Depth 3`

type dnsOwnerRead func(context.Context,string)([]byte,error)

func defaultDNSOwnerRead(ctx context.Context,query string)([]byte,error){
 if query!=windowsVOLVEDNSOwnerQuery{return nil,errors.New("unsupported privileged DNS owner query")}
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if root==""||!filepath.IsAbs(root){return nil,errors.New("Windows SystemRoot unavailable")}
 binary:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 localCtx,cancel:=context.WithTimeout(ctx,20*time.Second)
 defer cancel()
 out,err:=exec.CommandContext(localCtx,binary,"-NoLogo","-NoProfile","-NonInteractive","-Command",query).Output()
 if err!=nil{return nil,fmt.Errorf("read-only DNS owner query failed: %w",err)}
 return out,nil
}

type DNSOwnerEvidence struct{
 Schema int `json:"schema"`
 ExactIPv4Socket bool `json:"exact_ipv4_socket"`
 ExactIPv6Socket bool `json:"exact_ipv6_socket"`
 SameNonzeroPID bool `json:"same_nonzero_pid"`
 ProcessObserved bool `json:"process_observed"`
 SystemOwner bool `json:"system_owner"`
 LegacyExecutablePathMatch bool `json:"legacy_executable_path_match"`
 DNSServiceArgsMatch bool `json:"dns_service_args_match"`
}

type DNSOwnerReport struct {
 Status string `json:"status"`
 Evidence *DNSOwnerEvidence `json:"evidence,omitempty"`
 RunningMotorConfirmed bool `json:"running_motor_confirmed"`
 SignedMigrationAuthorized bool `json:"signed_migration_authorized"`
 CanModifyDNS bool `json:"can_modify_dns"`
}

func inspectDNSOwnerReadOnly(ctx context.Context,read dnsOwnerRead) DNSOwnerReport{
 report:=DNSOwnerReport{Status:"NOT_VERIFIED"}
 if err:=ctx.Err();err!=nil{return report}
 if read==nil{return report}
 raw,err:=read(ctx,windowsVOLVEDNSOwnerQuery)
 if err!=nil||len(raw)<2||len(raw)>4096{return report}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var result DNSOwnerEvidence
 if err:=dec.Decode(&result);err!=nil{return report}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return report}
 if result.Schema!=1{return report}
 if result.DNSServiceArgsMatch && !result.LegacyExecutablePathMatch{return report}
 if result.LegacyExecutablePathMatch && !result.ProcessObserved{return report}
 if result.SystemOwner && !result.ProcessObserved{return report}
 if result.ProcessObserved && !result.SameNonzeroPID{return report}
 if result.SameNonzeroPID && (!result.ExactIPv4Socket || !result.ExactIPv6Socket){return report}
 if err:=ctx.Err();err!=nil{return report}
 report.Status="SOCKET_OWNER_OBSERVED_READ_ONLY"
 if result.ExactIPv4Socket && result.ExactIPv6Socket&&result.SameNonzeroPID &&
  result.ProcessObserved &&result.SystemOwner &&result.LegacyExecutablePathMatch &&
  result.DNSServiceArgsMatch {
  report.Status="EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED"
 }
 report.Evidence=&result
 // No positive claim about real DNS query health or Scheduler identity.
 return report
}

// Keep diagnostics independent of the security-sensitive migration driver.
func (e DNSOwnerReport) Safe()bool{
 return !e.RunningMotorConfirmed&&!e.SignedMigrationAuthorized&&!e.CanModifyDNS &&
  !strings.Contains(e.Status,"AUTHORIZE")
}
