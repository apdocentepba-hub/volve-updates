//go:build windows

// Test capsule only. The production setup does not compile this program.
package main

import (
 "embed"
 "fmt"
 "io/fs"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
)

//go:embed payload/*
var capsule embed.FS

func run()error{
 if len(os.Args)!=5||os.Args[1]!="--stage-private-ci"||
 os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
 os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")!="PRIVATE_GUEST_ONLY"{
  return fmt.Errorf("private CI staging only")
 }
 root:=filepath.Clean(`C:\VOLVE-CI-PrivateDNS`)
 path,err:=syscall.UTF16PtrFromString(root)
 if err!=nil{return err}
 attr,err:=syscall.GetFileAttributes(path)
 if err!=nil{return err}
 if attr&0x400!=0||attr&0x10==0{return fmt.Errorf("staging root is a reparse point or not a directory")}
 // Use the actual built-in Windows PowerShell; no PATH-selected command.
 win:=os.Getenv("SystemRoot")
 if !strings.EqualFold(win,`C:\Windows`){return fmt.Errorf("unexpected Windows root")}
 ps:=filepath.Join(win,"System32","WindowsPowerShell","v1.0","powershell.exe")
 const inspect=`$ErrorActionPreference='Stop';$c=Get-CimInstance Win32_ComputerSystem;if(($c.Manufacturer+' '+$c.Model) -notmatch '(?i)virtual machine|hyper-v'){throw 'not Hyper-V'};$n=@(Get-NetAdapter);if($n.Count -ne 1 -or $n[0].Name -cne 'VOLVE-CI-PRIVATE-DNS' -or $n[0].Status -ne 'Up'){throw 'invalid NIC'};if(@(Get-NetRoute|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'external route'};if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'installed motor'};[Console]::Write('PRIVATE-CI')`
 raw,err:=exec.Command(ps,"-NoProfile","-NonInteractive","-Command",inspect).Output()
 if err!=nil||strings.TrimSpace(string(raw))!="PRIVATE-CI"{return fmt.Errorf("private VM attestation refused")}
 sub,err:=fs.Sub(capsule,"payload")
 if err!=nil{return err}
 return stageCapsule(root,sub,os.Args[2:])
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println("PASS VOLVE_PRIVATE_CAPSULE_STAGED_THREE_EXACT_COMPONENTS NO_INSTALL")
}
