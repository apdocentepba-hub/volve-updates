//go:build windows

package main

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func TestPinnedResidentTerminalReceiptExactPathAndNoAlias(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-Installed")
 parent:=filepath.Join(root,residentRecoveryParent)
 dir:=filepath.Join(parent,residentJournalDirName)
 signedResult:=filepath.Join(dir,motorupdate.ResidentResultFile)
 for _,tc:=range []struct{path string;ok bool}{
  {signedResult,true},
  {filepath.Join(dir,motorupdate.ResidentIntentFile),false},
  {filepath.Join(parent,"publisher-authorization","migration-permit.sig"),false},
  {filepath.Join(root,"installed-engines","motor-0.28.7","VOLVE_DNS_Motor_0_28_7.exe"),false},
  {filepath.Join(dir,"resident-result.json.bak"),false},
  {filepath.Join(dir,".","..",residentJournalDirName,motorupdate.ResidentResultFile),true},
  {filepath.Join(dir,"..",motorupdate.ResidentResultFile),false},
  {filepath.Join(t.TempDir(),residentRecoveryParent,residentJournalDirName,motorupdate.ResidentResultFile),false},
  {"resident-result.json",false},
 } {
  got:=pinnedResidentTerminalReceiptPath(root,tc.path)
  if got!=tc.ok{t.Fatalf("terminal path allowlist: %q accepted=%t expected=%t",tc.path,got,tc.ok)}
 }
 if pinnedResidentTerminalReceiptPath("relative",signedResult){
  t.Fatal("untrusted relative installed root allowed terminal receipt")
 }
 if pinnedResidentTerminalReceiptPath(root+string(os.PathSeparator)+".",signedResult){
  t.Fatal("noncanonical installed root accepted")
 }
}

func TestPinnedResidentTerminalSealCannotModifyUnrelatedPaths(t *testing.T){
 ctx:=context.Background()
 root:=filepath.Join(t.TempDir(),"VOLVE-Installed")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 foreign:=filepath.Join(root,"legacy-engine-recovery","original-before-upgrade","VOLVE_DNS_Legacy_Recovery.exe")
 if err:=sealPinnedResidentTerminalReceiptNTFS(ctx,root,foreign);err==nil{
  t.Fatal("SYSTEM terminal-seal helper accepted unrelated original motor")
 }
 if _,err:=os.Lstat(foreign);!errors.Is(err,os.ErrNotExist){
  t.Fatalf("refused terminal sealing created unrelated file: %v",err)
 }
 cancelled,stop:=context.WithCancel(ctx);stop()
 path:=filepath.Join(root,residentRecoveryParent,residentJournalDirName,motorupdate.ResidentResultFile)
 if err:=sealPinnedResidentTerminalReceiptNTFS(cancelled,root,path);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled terminal seal did not fail before Windows mutation: %v",err)
 }
 if _,err:=runPinnedResidentBootRecoveryWindows(cancelled,root);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled production-identity boot policy did not refuse: %v",err)
 }
}

func TestPinnedResidentBootEntryRejectsNonSYSTEMWithoutTouchingInstallation(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
 defer cancel()
 if err:=verifyResidentActualSYSTEM(ctx);err==nil {
  t.Skip("CI is unexpectedly SYSTEM: refuse to execute a productive-identity boot policy")
 }
 root:=filepath.Join(t.TempDir(),"VOLVE-Installed")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 result,err:=runPinnedResidentBootRecoveryWindows(ctx,root)
 if err==nil||result!=""{
  t.Fatalf("non-SYSTEM Windows actor was admitted to autonomous protected boot recovery: %q %v",result,err)
 }
 entries,err:=os.ReadDir(root)
 if err!=nil||len(entries)!=0{
  t.Fatalf("refused autonomous boot recovery created installed files: %v / %d",err,len(entries))
 }
}

func TestPinnedResidentBootTerminalSourceHasNoReleaseOrTaskRegistration(t *testing.T){
 // Guard the mechanical product boundary: private signed boot routines
 // may NOT be exposed directly via main() or add a new scheduler service.
 src,err:=os.ReadFile("resident_pinned_boot_terminal_windows.go")
 if err!=nil{t.Fatal(err)}
 source:=string(src)
 for _,token:=range []string{
  "verifyResidentActualSYSTEM","checkResidentJournalNTFS",
  "motorupdate.RecoverPendingResidentAfterBoot",
  "sealPinnedResidentTerminalReceiptNTFS",
  "Set-Acl -LiteralPath $p",
  "VOLVE_SIGNED_RECOVERY_RESULT_SEALED",
 }{
  if !strings.Contains(source,token){t.Errorf("private signed terminal recovery omitted safety fence: %q",token)}
 }
 for _,token:=range []string{
  "Register-ScheduledTask","Start-ScheduledTask -TaskName",
  "Set-DnsClientServerAddress","Set-NetIPInterface",
  "Remove-Item","os.Remove(","Set-ScheduledTask",
 } {
  if strings.Contains(source,token){t.Errorf("terminal-only recovery unexpectedly controls production subsystem: %q",token)}
 }
}
