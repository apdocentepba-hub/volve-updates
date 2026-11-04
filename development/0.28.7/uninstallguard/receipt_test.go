package uninstallguard

import (
    "bytes"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"
    "sort"
    "strings"
    "testing"

    "volve.local/installer/unifiedbundle"
)

func testReceipt() InstalledReceipt {
    names:=unifiedbundle.RequiredFiles()
    ids:=make([]string,0,len(names))
    for id:=range names {ids=append(ids,id)}
    sort.Strings(ids)
    files:=make([]ReceiptFile,0,len(ids))
    for _,id:=range ids {
        files=append(files,ReceiptFile{ID:id,File:names[id],Size:128,SHA256:strings.Repeat("a",64)})
    }
    return InstalledReceipt{
        Schema:1,Release:"0.28.7",Platform:"windows-amd64",
        State:completedReceiptState,InstallationID:strings.Repeat("a",32),
        InstallRoot:`C:\Program Files\VOLVE`,
        DataRoot:`C:\ProgramData\VOLVE-Browser-Filter`,
        Origin:"MIGRATED_FROM_0286",OriginMotorSHA256:strings.Repeat("b",64),
        PackageManifestSHA256:strings.Repeat("c",64),
        OriginalDNSSnapshotSHA256:strings.Repeat("d",64),
        RecoveryJournalSHA256:strings.Repeat("e",64),
        Files:files,
        Tasks:[]ReceiptTask{{Name:"VOLVE-MANAGED-DNS-0287",Principal:"SYSTEM",
            XMLSHA256:strings.Repeat("f",64),ActionSHA256:strings.Repeat("1",64)}},
    }
}

func testSigned(t *testing.T,r InstalledReceipt)([]byte,[]byte,ed25519.PublicKey,ed25519.PrivateKey){
    t.Helper()
    public,private,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    raw,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
    return raw,ed25519.Sign(private,raw),public,private
}

func TestVerifiedEditorialReceiptIsNotAnUninstallPermit(t *testing.T){
    raw,sig,key,_:=testSigned(t,testReceipt())
    r,err:=VerifySignedInstalledReceipt(raw,sig,key)
    if err!=nil || len(r.Files)!=8 {t.Fatalf("authentic receipt rejected: %+v %v",r,err)}
    host:=knownHost()
    host.OtherVolveTasks=1;host.ProgramFilesRoot=true;host.ProgramDataResidues=1
    plan,err:=ReviewWithSignedReceipt(host,raw,sig,key)
    if err!=nil||plan.Mode!="REVIEW_AUTHENTIC_INSTALLED_0287_RECEIPT_BUT_LIVE_OWNERSHIP_UNPROVEN"{
        t.Fatalf("receipt did not produce distinct nonauthorizing review: %+v %v",plan,err)
    }
    if len(plan.Requirements)!=6 {t.Fatalf("signed receipt should satisfy only its own proof: %+v",plan)}
    ensureNoWrites(t,{Plan:plan})
}

func TestLegacyOrRecoveryCannotBeRemovedEvenWithValidSignedReceipt(t *testing.T){
    raw,sig,key,_:=testSigned(t,testReceipt())
    for _,tt:=range []struct{legacy int;recovery bool;mode string}{
        {3,false,"STOP_LEGACY_0286_PROTECTION_PRESENT"},
        {3,true,"STOP_RECOVERY_JOURNAL_PRESENT"},
        {0,true,"STOP_RECOVERY_JOURNAL_PRESENT"},
    }{
        e:=knownHost();e.LegacyTasks=tt.legacy;e.RecoveryJournalPresent=tt.recovery
        e.OtherVolveTasks=2;e.ProgramFilesRoot=true;e.ProgramDataResidues=2
        p,err:=ReviewWithSignedReceipt(e,raw,sig,key)
        if err!=nil || p.Mode!=tt.mode {t.Fatalf("legacy/recovery incorrectly promoted: %+v %v",p,err)}
        ensureNoWrites(t,{Plan:p})
    }
}

func TestReceiptSignatureAndCanonicalJSONRejectManipulation(t *testing.T){
    raw,sig,key,private:=testSigned(t,testReceipt())
    changed:=append([]byte(nil),raw...)
    changed[len(changed)-5]^=1
    if _,err:=VerifySignedInstalledReceipt(changed,sig,key);err==nil{t.Fatal("tampered receipt accepted")}
    wrong,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    if _,err=VerifySignedInstalledReceipt(raw,sig,wrong);err==nil{t.Fatal("wrong editor key accepted")}
    if _,err=VerifySignedInstalledReceipt(raw,sig,nil);err==nil{t.Fatal("missing editor pin accepted")}

    // Malicious publisher-authenticated but noncanonical content must not pass.
    tests:=[][]byte{
        append(append([]byte(nil),raw...),byte('\n')),
        bytes.Replace(raw,[]byte(`"schema":1`),[]byte(`"schema":1,"schema":1`),1),
        bytes.Replace(raw,[]byte(`"schema":1`),[]byte(`"unexpected":true,"schema":1`),1),
        append(append([]byte(nil),raw...),[]byte(" {}")...),
    }
    for _,invalid:=range tests {
        signed:=ed25519.Sign(private,invalid)
        if _,err:=VerifySignedInstalledReceipt(invalid,signed,key);err==nil{
            t.Fatalf("noncanonical or extra-data signed receipt accepted: %s",invalid[:50])
        }
    }
}

func TestSignedReceiptRejectsIncorrectOwnersMissingFilesAndUnsafeRoots(t *testing.T){
    for name,change:=range map[string]func(*InstalledReceipt){
        "missing-file":func(r *InstalledReceipt){r.Files=r.Files[:7]},
        "unsorted":func(r *InstalledReceipt){r.Files[0],r.Files[1]=r.Files[1],r.Files[0]},
        "duplicate-file":func(r *InstalledReceipt){r.Files[1]=r.Files[0]},
        "wrong-filename":func(r *InstalledReceipt){r.Files[0].File="VOLVE_FAKE.exe"},
        "bad-file-hash":func(r *InstalledReceipt){r.Files[0].SHA256="xx"},
        "wrong-release":func(r *InstalledReceipt){r.Release="0.28.6"},
        "not-committed":func(r *InstalledReceipt){r.State="PENDING"},
        "unsafe-root":func(r *InstalledReceipt){r.InstallRoot=`C:\Program Files\..\Windows`},
        "unc-root":func(r *InstalledReceipt){r.InstallRoot=`\\server\share\VOLVE`},
        "ads-root":func(r *InstalledReceipt){r.DataRoot=`C:\ProgramData\VOLVE:other`},
        "legacy-task":func(r *InstalledReceipt){r.Tasks[0].Name="VOLVE-DNS-SERVER-0270"},
        "other-principal":func(r *InstalledReceipt){r.Tasks[0].Principal="USER"},
        "missing-task-hash":func(r *InstalledReceipt){r.Tasks[0].XMLSHA256=""},
        "missing-dns-backup":func(r *InstalledReceipt){r.OriginalDNSSnapshotSHA256=""},
        "fresh-with-old":func(r *InstalledReceipt){r.Origin="FRESH"},
    }{
        t.Run(name,func(t *testing.T){
            r:=testReceipt()
            change(&r)
            raw,sig,key,_:=testSigned(t,r)
            if _,err:=VerifySignedInstalledReceipt(raw,sig,key);err==nil{
                t.Fatal("a signed but invalid identity was accepted")
            }
        })
    }
}

func TestSignedReceiptCannotOverrideIncompleteHostInventory(t *testing.T){
    raw,sig,key,_:=testSigned(t,testReceipt())
    p,err:=ReviewWithSignedReceipt(Evidence{},raw,sig,key)
    if err==nil||p.Mode!=""{t.Fatalf("missing privileged live inventory accepted: %+v %v",p,err)}
}

// Keep test return with named type so audit tests share the existing no-write
// invariant without allowing an accidental weakening of that invariant.
type auditPlan struct{Plan Plan}
func ensureNoWrites(t *testing.T,p auditPlan){
    t.Helper()
    x:=p.Plan
    if x.CanUninstall||x.CanStopMotor||x.CanChangeDNS||x.CanDeleteTasks||x.CanRemoveBrowserPolicies||x.CanDeleteFiles{
        t.Fatalf("receipt review wrongly authorized removal: %+v",x)
    }
}
