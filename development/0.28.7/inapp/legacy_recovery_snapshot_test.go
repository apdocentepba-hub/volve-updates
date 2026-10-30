package motorupdate

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

func legacyRecoveryFixture(t *testing.T)(string,[]byte,string){
    t.Helper()
    root:=t.TempDir()
    exe:=filepath.Join(root,legacyServiceName)
    if err:=os.WriteFile(exe,[]byte("MZ_ci_known_running_legacy_engine_fixed_bytes"),0600);err!=nil{t.Fatal(err)}
    task:=[]byte(strings.Repeat("<Task><Principal>SYSTEM</Principal><Exec>VOLVE_DNS_Server_0270.exe --dns-service</Exec></Task>",2))
    dest:=filepath.Join(root,"recovery-v1")
    return exe,task,dest
}
func testSecureLabFolder(string)error{return nil} // TEST-ONLY: production must enforce ACL.
func TestUnversionedRecoveryCreatesDurableExactMotorAndTaskBackup(t *testing.T){
    exe,xml,dest:=legacyRecoveryFixture(t)
    got,err:=PrepareUnversionedLegacyRecovery(context.Background(),exe,xml,dest,testSecureLabFolder)
    if err!=nil{t.Fatal(err)}
    restored,err:=VerifyUnversionedLegacyRecovery(dest,testSecureLabFolder)
    if err!=nil{t.Fatal(err)}
    if got!=restored || got.OriginalTask!=legacySystemTask || got.OriginalArgs!="--dns-service" ||
       got.Component!="dns-engine-legacy-recovery" {
        t.Fatalf("not a stable unversioned fallback: %#v %#v",got,restored)
    }
    orig,err:=os.ReadFile(exe);if err!=nil{t.Fatal(err)}
    after,err:=os.ReadFile(filepath.Join(dest,legacyBackupExe));if err!=nil{t.Fatal(err)}
    sum:=sha256.Sum256(orig)
    if string(after)!=string(orig) || got.ExeSHA256!=hex.EncodeToString(sum[:]) {
        t.Fatal("fallback engine differs from live source")
    }
    if got.CapturedUTC==""{t.Fatal("missing UTC evidence")}
    if err:=os.WriteFile(filepath.Join(dest,legacyBackupExe),[]byte("changed backup"),0600);err!=nil{t.Fatal(err)}
    if _,err:=VerifyUnversionedLegacyRecovery(dest,testSecureLabFolder);err==nil{
        t.Fatal("tampered fallback engine incorrectly trusted")
    }
}
func TestUnversionedRecoveryCannotOverwriteExistingBackup(t *testing.T){
    exe,xml,dest:=legacyRecoveryFixture(t)
    if _,err:=PrepareUnversionedLegacyRecovery(context.Background(),exe,xml,dest,testSecureLabFolder);err!=nil{t.Fatal(err)}
    expected,err:=os.ReadFile(filepath.Join(dest,legacyBackupReceipt));if err!=nil{t.Fatal(err)}
    if _,err:=PrepareUnversionedLegacyRecovery(context.Background(),exe,xml,dest,testSecureLabFolder);err==nil{
        t.Fatal("overwrote the only fallback")
    }
    actual,err:=os.ReadFile(filepath.Join(dest,legacyBackupReceipt));if err!=nil{t.Fatal(err)}
    if string(expected)!=string(actual){t.Fatal("existing receipt was altered")}
}
func TestUnversionedRecoveryRejectsUnsafeInputsBeforeWriting(t *testing.T){
    for _,kind:=range []string{"no-acl-verifier","untrusted-acl","cancelled","short-xml","wrong-original-name","relative-destination","linked-original","preexisting-target"}{
        t.Run(kind,func(t *testing.T){
            exe,xml,dest:=legacyRecoveryFixture(t)
            var protect func(string)error=testSecureLabFolder
            ctx:=context.Background()
            switch kind {
            case "no-acl-verifier":protect=nil
            case "untrusted-acl":protect=func(string)error{return errors.New("unexpected users write ACL")}
            case "cancelled":
                c,cancel:=context.WithCancel(ctx);cancel();ctx=c
            case "short-xml":xml=[]byte("<Task/>")
            case "wrong-original-name":
                wrong:=filepath.Join(filepath.Dir(exe),"stranger.exe")
                if err:=os.Rename(exe,wrong);err!=nil{t.Fatal(err)};exe=wrong
            case "relative-destination":dest="relative-recovery"
            case "linked-original":
                target:=filepath.Join(filepath.Dir(exe),"real-engine")
                if err:=os.Rename(exe,target);err!=nil{t.Fatal(err)}
                if err:=os.Symlink(target,exe);err!=nil{t.Skipf("symlink permission unavailable: %v",err)}
            case "preexisting-target":
                if err:=os.Mkdir(dest,0700);err!=nil{t.Fatal(err)}
            }
            if _,err:=PrepareUnversionedLegacyRecovery(ctx,exe,xml,dest,protect);err==nil{
                t.Fatalf("unsafe %s permitted",kind)
            }
            if kind!="preexisting-target"{
                if _,err:=os.Lstat(dest);!errors.Is(err,os.ErrNotExist){
                    t.Fatalf("unsafe %s created backup: %v",kind,err)
                }
            }
        })
    }
}
func TestUnversionedRecoveryRejectsChangedXMLAndReceipt(t *testing.T){
    for _,which:=range []string{"xml","receipt","symlink"}{
        t.Run(which,func(t *testing.T){
            exe,xml,dest:=legacyRecoveryFixture(t)
            _,err:=PrepareUnversionedLegacyRecovery(context.Background(),exe,xml,dest,testSecureLabFolder)
            if err!=nil{t.Fatal(err)}
            p:=filepath.Join(dest,legacyBackupXML)
            switch which {
            case "xml":
                if err:=os.WriteFile(p,[]byte("corrupted xml"),0600);err!=nil{t.Fatal(err)}
            case "receipt":
                p=filepath.Join(dest,legacyBackupReceipt)
                if err:=os.WriteFile(p,[]byte(`{"schema":1,"component":"dns-engine-legacy-recovery","extra":"bad"}`),0600);err!=nil{t.Fatal(err)}
            case "symlink":
                original:=filepath.Join(dest,"xml-stash")
                if err:=os.Rename(p,original);err!=nil{t.Fatal(err)}
                if err:=os.Symlink(original,p);err!=nil{t.Skipf("symlink permission unavailable: %v",err)}
            }
            if _,err:=VerifyUnversionedLegacyRecovery(dest,testSecureLabFolder);err==nil{
                t.Fatalf("%s tamper accepted",which)
            }
        })
    }
}
func TestUnversionedRecoveryRequiresProtectedDestinationOnRead(t *testing.T){
    exe,xml,dest:=legacyRecoveryFixture(t)
    if _,err:=PrepareUnversionedLegacyRecovery(context.Background(),exe,xml,dest,testSecureLabFolder);err!=nil{t.Fatal(err)}
    if _,err:=VerifyUnversionedLegacyRecovery(dest,func(string)error{return errors.New("ACL not protected")});err==nil{
        t.Fatal("weak ACL accepted for restore")
    }
}


// A failed OS sealing callback must not publish a partially trusted fallback.
func TestUnversionedRecoverySealingFailureNeverPublishesBackup(t *testing.T) {
    exe,xml,dest:=legacyRecoveryFixture(t)
    calls:=[]string{}
    failOnReceipt:=func(path string) error {
        calls=append(calls,filepath.Base(path))
        if filepath.Base(path)==legacyBackupReceipt {
            return errors.New("synthetic NTFS owner/DACL seal failure")
        }
        return nil
    }
    _,err:=PrepareUnversionedLegacyRecoveryWithSealing(context.Background(),
        exe,xml,dest,testSecureLabFolder,failOnReceipt)
    if err==nil || !strings.Contains(err.Error(),"seal") {
        t.Fatalf("failed seal was accepted: %v",err)
    }
    if _,statErr:=os.Lstat(dest);!errors.Is(statErr,os.ErrNotExist) {
        t.Fatalf("unsealed recovery was published: %v",statErr)
    }
    if len(calls)!=4 || calls[0]==legacyBackupReceipt {
        t.Fatalf("unexpected sealing order: %#v",calls)
    }
    if original,e:=os.ReadFile(exe);e!=nil || string(original)!="MZ_ci_known_running_legacy_engine_fixed_bytes" {
        t.Fatalf("sealing failure changed the resident motor: %v",e)
    }
}

func TestUnversionedRecoverySealingCallsAllFourNewNodes(t *testing.T) {
    exe,xml,dest:=legacyRecoveryFixture(t)
    calls:=map[string]int{}
    seal:=func(path string)error{
        calls[filepath.Base(path)]++
        if _,err:=os.Lstat(path);err!=nil{return err}
        return nil
    }
    got,err:=PrepareUnversionedLegacyRecoveryWithSealing(context.Background(),
        exe,xml,dest,testSecureLabFolder,seal)
    if err!=nil{t.Fatal(err)}
    if len(calls)!=4 || calls[legacyBackupExe]!=1 ||
       calls[legacyBackupXML]!=1 || calls[legacyBackupReceipt]!=1 {
        t.Fatalf("missing or repeated sealing callback: %#v",calls)
    }
    if saved,err:=VerifyUnversionedLegacyRecovery(dest,testSecureLabFolder);err!=nil || saved!=got {
        t.Fatalf("sealed recovery integrity not preserved: %v",err)
    }
}
