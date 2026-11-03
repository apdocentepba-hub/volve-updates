//go:build windows

package main

import (
 "path/filepath"
 "testing"
)

func TestProtectedMotorTargetNativePathAllowlist(t *testing.T){
 installed:=filepath.Join(t.TempDir(),"VOLVE-Browser-Filter")
 inventory:=filepath.Join(installed,"installed-engines")
 versionDir:=filepath.Join(inventory,"motor-0.28.7")
 exe:=filepath.Join(versionDir,"VOLVE_DNS_Motor_0_28_7.exe")
 for _,item:=range []struct{path string;verify,sealable bool}{
  {inventory,true,false},
  {versionDir,true,true},
  {exe,true,true},
  {exe+".json",true,true},
  {exe+".sig",true,true},
  {filepath.Join(inventory,"motor-0.28.6"),true,true},
  {filepath.Join(versionDir,"VOLVE_DNS_Motor_0_28_8.exe"),false,false},
  {filepath.Join(versionDir,"VOLVE_DNS_Motor_0_28_7.exe.old"),false,false},
  {filepath.Join(versionDir,"other.txt"),false,false},
  {filepath.Join(versionDir,"nested","VOLVE_DNS_Motor_0_28_7.exe"),false,false},
  {filepath.Join(installed,"legacy-engine-recovery","original-before-upgrade"),false,false},
  {filepath.Join(installed,"VOLVE_DNS_Server_0270.exe"),false,false},
  {filepath.Join(inventory,"motor-0.28.7-stale"),false,false},
  {filepath.Join(inventory,"motor-0.28"),false,false},
  {filepath.Join(inventory,"motor-0.28.7","..","motor-0.28.7","VOLVE_DNS_Motor_0_28_7.exe"),true,true},
  {"relative-file.exe",false,false},
 }{
  got:=pinnedProtectedMotorDestination(installed,item.path,true)
  if got!=item.verify{t.Fatalf("native allowlist path=%q verify=%t want=%t",item.path,got,item.verify)}
  got=pinnedProtectedMotorDestination(installed,item.path,false)
  if got!=item.sealable{t.Fatalf("native sealing allowlist path=%q seal=%t want=%t",item.path,got,item.sealable)}
 }
 // A UNC/network source, sibling installed root or parent traversal cannot
 // supply the product authorization path; no existing task is read or changed.
 for _,installedRoot:=range []string{"relative-install",filepath.Join(installed,"..")}{
  if pinnedProtectedMotorDestination(installedRoot,exe,true){
   t.Fatalf("untrusted installed root accepted: %q",installedRoot)
  }
 }
}
