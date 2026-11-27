//go:build windows && volveci

package main

import (
 "errors"
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestCIFreshStartupDiagnosticExactBytes(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-CI-FreshDNS53-123456")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 path:=filepath.Join(root,"ci-startup-failure.txt")
 writeCIFreshFailureDiagnostic(root,"wrong",ciFreshStage("catalog-verify",errors.New("private fixture")))
 if _,err:=os.Stat(path);!os.IsNotExist(err){t.Fatal("invalid token wrote receipt")}
 writeCIFreshFailureDiagnostic(root,ciFreshToken,ciFreshStage("vm-attestation",errors.New("private fixture")))
 if _,err:=os.Stat(path);!os.IsNotExist(err){t.Fatal("failed VM attestation wrote receipt")}
 writeCIFreshFailureDiagnostic(root,ciFreshToken,ciFreshStage("catalog-verify",errors.New("private fixture")))
 actual,err:=os.ReadFile(path)
 expected:="stage=catalog-verify;win32=0"+string(byte(10))
 if err!=nil||string(actual)!=expected{t.Fatal("diagnostic bytes differ from expected LF-terminated record",err)}
 writeCIFreshFailureDiagnostic(root,ciFreshToken,ciFreshStage("upstream-tcp-bind",syscall.Errno(10048)))
 actual,err=os.ReadFile(path)
 if err!=nil||string(actual)!=expected{t.Fatal("first failure receipt overwritten",err)}
 second:=filepath.Join(t.TempDir(),"VOLVE-CI-FreshDNS53-123457")
 if err:=os.Mkdir(second,0700);err!=nil{t.Fatal(err)}
 writeCIFreshFailureDiagnostic(second,ciFreshToken,ciFreshStage("upstream-tcp-bind",syscall.Errno(10048)))
 actual,err=os.ReadFile(filepath.Join(second,"ci-startup-failure.txt"))
 if err!=nil||string(actual)!="stage=upstream-tcp-bind;win32=10048"+string(byte(10)){t.Fatal("native errno receipt invalid",err)}
 t.Log("PASS VOLVE_CI_STARTUP_DIAGNOSTIC_EXACT_LF_CREATE_ONLY")
}
