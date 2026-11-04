//go:build windows

package main

import (
    "bytes"
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

func testSignedArgs(t *testing.T) []string {
    t.Helper()
    get:=func(key string) string {
        value:=os.Getenv(key)
        if value==""{t.Fatalf("mandatory signed CI fixture missing: %s",key)}
        return value
    }
    return []string{
        "--exe",get("VOLVE_CI_AUTHENTICODE_OS_BINARY"),
        "--pubkey",get("VOLVE_CI_ED25519_PUB"),
        "--certsha",get("VOLVE_CI_AUTHENTICODE_CERT_SHA256"),
        "--filehash",get("VOLVE_CI_AUTHENTICODE_FILE_SHA256"),
        "--installed-root",t.TempDir(),
    }
}

func requireHosted(t *testing.T){
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
       os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" {
        t.Skip("integration requires disposable hosted Windows CI")
    }
}

func TestSetupReviewActualWindowsEXENeverAuthorizes(t *testing.T){
    requireHosted(t)
    args:=testSignedArgs(t)
    ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second)
    defer cancel()
    var out bytes.Buffer
    if err:=execute(ctx,args,&out);err!=nil{t.Fatal(err)}
    var result report
    if err:=json.Unmarshal(out.Bytes(),&result);err!=nil{t.Fatal(err)}
    if result.Schema!=1||result.ReleaseApproved||
       result.ExecutableAction!="NONE_REVIEW_ONLY_NO_INSTALL_NO_DNS_NO_TASKS"||
       result.Review.InventoriesChecked!=6||result.Review.PackageParts!=7||
       result.Review.InstallAuthorized||result.Review.UpgradeAuthorized||
       result.Plan.CanInstall||result.Plan.CanUpgrade||
       result.Plan.CanChangeDNS||result.Plan.CanChangeTasks{
        t.Fatalf("installer preflight claimed mutations: %+v",result)
    }
    if out.Len()==0||out.Len()>16<<10{t.Fatalf("unbounded or absent review JSON: %d",out.Len())}
    t.Log("PASS VOLVE_SETUP_EXECUTABLE_NATIVE_WINDOWS_PREFLIGHT_ONLY")
}

func TestSetupReviewFailsClosedOnWrongPublisherAndBadRoot(t *testing.T){
    requireHosted(t)
    base:=testSignedArgs(t)
    for _,test:=range []struct{
        name string
        change func([]string)
    }{
        {"wrong-cert",func(a []string){a[5]=strings.Repeat("0",64)}},
        {"wrong-file",func(a []string){a[7]=strings.Repeat("0",64)}},
        {"missing-root",func(a []string){a[9]=filepath.Join(t.TempDir(),"nonexistent")}},
        {"missing-key",func(a []string){a[3]=""}},
        {"unknown-argument",func(a []string){a[0]="--allow-install"}},
    }{
        t.Run(test.name,func(t *testing.T){
            a:=append([]string{},base...)
            test.change(a)
            var out bytes.Buffer
            if err:=execute(context.Background(),a,&out);err==nil||out.Len()!=0{
                t.Fatalf("invalid preflight produced output or succeeded: %v",err)
            }
        })
    }
}

func TestSetupReviewRefusesNonHostedExecution(t *testing.T){
    t.Setenv("GITHUB_ACTIONS","false")
    t.Setenv("RUNNER_ENVIRONMENT","local")
    var out bytes.Buffer
    if err:=execute(context.Background(),nil,&out);err==nil||out.Len()!=0{
        t.Fatalf("non-CI installer preview unexpectedly accepted: %v",err)
    }
}
