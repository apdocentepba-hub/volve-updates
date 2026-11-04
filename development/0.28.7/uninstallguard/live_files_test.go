package uninstallguard

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func buildFileFixture(t *testing.T)(InstalledReceipt,string,string){
    t.Helper()
    install:=filepath.Join(t.TempDir(),"VOLVE")
    data:=filepath.Join(t.TempDir(),"VOLVE-Browser-Filter")
    for _,p:=range []string{install,data}{
        if err:=os.MkdirAll(p,0700);err!=nil{t.Fatal(err)}
    }
    r:=testReceipt()
    for i:=range r.Files {
        f:=&r.Files[i]
        root:=install
        if i%2==1 {f.Root="data";root=data} else {f.Root="install"}
        bytes:=[]byte("VOLVE TEST-ONLY COMPONENT "+f.ID+"\n")
        if err:=os.WriteFile(filepath.Join(root,f.File),bytes,0600);err!=nil{t.Fatal(err)}
        h:=sha256.Sum256(bytes)
        f.SHA256=hex.EncodeToString(h[:])
        f.Size=int64(len(bytes))
    }
    return r,install,data
}

func TestReadOnlySignedFilesMatchEightExactHashesAndNeverAuthorize(t *testing.T){
    r,install,data:=buildFileFixture(t)
    a,err:=auditReceiptFilesAtRoots(context.Background(),r,install,data)
    if err!=nil{t.Fatal(err)}
    if a.MatchedFiles!=8||a.CheckedFiles!=8||a.Status!="READ_ONLY_FILE_HASHES_MATCH_TASKS_AND_PROCESS_UNVERIFIED"{
        t.Fatalf("unexpected audit: %+v",a)
    }
    if a.CanUninstall||a.CanStopMotor||a.CanDeleteTasks||a.CanDeleteFiles||
        a.CanChangeDNS||a.TaskOwnershipVerified||a.ProcessOwnershipVerified{
        t.Fatalf("file hashes gave destructive authority: %+v",a)
    }
}

func TestReadOnlySignedFilesRejectTamperedAndMissingInputs(t *testing.T){
    for _,scenario:=range []string{"different-bytes","missing-file","wrong-signed-root","wrong-size"}{
        t.Run(scenario,func(t *testing.T){
            r,install,data:=buildFileFixture(t)
            f:=r.Files[0]
            p:=filepath.Join(install,f.File)
            switch scenario {
            case "different-bytes":
                b:=[]byte("VOLVE TEST-ONLY COMPONENT "+f.ID+"\n")
                b[len(b)-3]^=1
                if err:=os.WriteFile(p,b,0600);err!=nil{t.Fatal(err)}
            case "missing-file":
                if err:=os.Remove(p);err!=nil{t.Fatal(err)}
            case "wrong-signed-root":
                r.Files[0].Root="data"
            case "wrong-size":
                r.Files[0].Size++
            }
            report,err:=auditReceiptFilesAtRoots(context.Background(),r,install,data)
            if err==nil||report.MatchedFiles!=0{
                t.Fatalf("tampered installed component accepted: %+v %v",report,err)
            }
        })
    }
}

func TestReadOnlySignedFilesRejectLinkedFileOrRoot(t *testing.T){
    r,install,data:=buildFileFixture(t)
    p:=filepath.Join(install,r.Files[0].File)
    real:=filepath.Join(t.TempDir(),"outside.txt")
    if err:=os.WriteFile(real,[]byte("outside"),0600);err!=nil{t.Fatal(err)}
    if err:=os.Remove(p);err!=nil{t.Fatal(err)}
    if err:=os.Symlink(real,p);err!=nil{t.Skipf("symlink unavailable (Windows privilege): %v",err)}
    report,err:=auditReceiptFilesAtRoots(context.Background(),r,install,data)
    if err==nil||report.MatchedFiles!=0{t.Fatalf("linked installed file accepted: %+v %v",report,err)}

    // A linked directory must not silently redirect the entire install.
    realDir:=t.TempDir()
    linked:=filepath.Join(t.TempDir(),"VOLVE")
    if err:=os.Symlink(realDir,linked);err==nil{
        report,err=auditReceiptFilesAtRoots(context.Background(),r,linked,data)
        if err==nil||report.MatchedFiles!=0{t.Fatalf("linked root accepted: %+v %v",report,err)}
    }
}

func TestReadOnlySignedFilesRejectInvalidContextAndRoot(t *testing.T){
    r,install,data:=buildFileFixture(t)
    if _,err:=auditReceiptFilesAtRoots(nil,r,install,data);err==nil{t.Fatal("nil context accepted")}
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if _,err:=auditReceiptFilesAtRoots(ctx,r,install,data);!errors.Is(err,context.Canceled){
        t.Fatalf("cancelled operation was not rejected: %v",err)
    }
    if _,err:=auditReceiptFilesAtRoots(context.Background(),r,install,install);err==nil{t.Fatal("same roots accepted")}
    if _,err:=auditReceiptFilesAtRoots(context.Background(),r,install,data + string(filepath.Separator) + ".." + string(filepath.Separator) + "VOLVE-Browser-Filter");err==nil{
        t.Fatal("noncanonical data path accepted")
    }
}

func TestReadOnlySignedFilesNeverConfusesNamesAndIds(t *testing.T){
    r,install,data:=buildFileFixture(t)
    r.Files[0].File=".."+string(filepath.Separator)+"outside"
    if _,err:=auditReceiptFilesAtRoots(context.Background(),r,install,data);err==nil{t.Fatal("traversal accepted")}
    r,install,data=buildFileFixture(t)
    r.Files[0].Root=strings.ToUpper(r.Files[0].Root)
    if _,err:=auditReceiptFilesAtRoots(context.Background(),r,install,data);err==nil{t.Fatal("invalid root selector accepted")}
}
