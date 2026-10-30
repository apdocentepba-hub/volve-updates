package motorupdate

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

type signedBridgeFixture struct{
    live,backup,candidate,root string
    permit LegacyMigrationPermit
    raw,sig []byte
    pub ed25519.PublicKey
    priv ed25519.PrivateKey
    preflightCalls int
}
func newSignedBridge(t *testing.T)*signedBridgeFixture {
    t.Helper()
    root:=t.TempDir()
    live:=filepath.Join(root,legacyServiceName)
    if err:=os.WriteFile(live,[]byte("MZ_UNVERSIONED_PREVIOUS_MOTOR_FIXED_0270"),0600);err!=nil{t.Fatal(err)}
    task:=[]byte(strings.Repeat("<Task><Principal>SYSTEM</Principal><Exec Command='VOLVE_DNS_Server_0270.exe'/></Task>",2))
    backup:=filepath.Join(root,"recovery")
    prev,err:=PrepareUnversionedLegacyRecovery(context.Background(),live,task,backup,testSecureLabFolderBridge)
    if err!=nil{t.Fatal(err)}
    pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    next:=[]byte("MZ_0287_SIGNED_MOTOR_BRIDGE_TARGET")
    sum:=sha256.Sum256(next)
    manifest:=Manifest{
        Schema:1,Component:"dns-engine",Version:"0.28.7",MinPanelVersion:"0.28.7",
        URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
        SHA256:hex.EncodeToString(sum[:]),Size:int64(len(next)),Notes:"signed laboratory bridge",
    }
    candidate:=filepath.Join(root,"VOLVE_DNS_Motor_0_28_7.exe")
    if err:=os.WriteFile(candidate,next,0600);err!=nil{t.Fatal(err)}
    rawManifest,err:=json.Marshal(manifest);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".json",rawManifest,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,rawManifest))),0600);err!=nil{t.Fatal(err)}
    now:=time.Now().UTC()
    permit:=LegacyMigrationPermit{
        Schema:1,Component:"dns-engine-legacy-migration",FromTask:legacySystemTask,
        FromArgs:legacyServiceArg,FromExecutable:legacyServiceName,
        FromSHA256:prev.ExeSHA256,FromSize:prev.ExeSize,FromTaskXMLSHA256:prev.XMLSHA256,
        ToVersion:manifest.Version,ToSHA256:manifest.SHA256,ToSize:manifest.Size,
        MinPanelVersion:manifest.MinPanelVersion,
        IssuedUTC:now.Add(-time.Hour).Format(time.RFC3339),
        ExpiresUTC:now.Add(24*time.Hour).Format(time.RFC3339),
    }
    raw,err:=json.Marshal(permit);if err!=nil{t.Fatal(err)}
    sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
    return &signedBridgeFixture{live:live,backup:backup,candidate:candidate,root:root,permit:permit,raw:raw,sig:sig,pub:pub,priv:priv}
}
func testSecureLabFolderBridge(string)error{return nil} // test only, real Windows uses ACL checker
func (f *signedBridgeFixture)verify(ctx context.Context)(VerifiedLegacyMigrationProof,error){
    return VerifySignedUnversionedLegacyMigration(ctx,f.live,f.backup,f.candidate,"0.28.7",
        f.raw,f.sig,f.pub,testSecureLabFolderBridge,func()error{f.preflightCalls++;return nil})
}
func (f *signedBridgeFixture)resign(t *testing.T){
    t.Helper();b,e:=json.Marshal(f.permit);if e!=nil{t.Fatal(e)}
    f.raw=b;f.sig=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,b)))
}
func TestSignedUnversionedBridgeRequiresExactTwoSignedIdentitiesAndProtectedOldBackup(t *testing.T){
    f:=newSignedBridge(t)
    proof,err:=f.verify(context.Background())
    if err!=nil{t.Fatal(err)}
    if proof.CandidateVersion!="0.28.7" || proof.CandidateSHA256!=f.permit.ToSHA256 ||
        proof.LegacySHA256!=f.permit.FromSHA256 || f.preflightCalls!=1{
        t.Fatalf("bridge proof mismatch %#v",proof)
    }
}
func TestSignedUnversionedBridgeRejectsForgeryTamperingAndInvalidTask(t *testing.T){
    for _,kind:=range []string{
        "unsigned","wrong-publisher","wrong-task","wrong-args","wrong-executable",
        "different-old-hash","different-old-xml-hash","different-new-hash",
        "different-new-version","different-new-size","different-new-panel",
        "altered-old-binary","altered-candidate","altered-backup",
        "missing-backup","missing-manifest","existing-managed-receipt",
        "expired","future-issued","too-long-validity","unsupported-old-updater","new-panel-too-old",
        "extra-signed-json","unknown-signed-json",
    }{
        t.Run(kind,func(t *testing.T){
            f:=newSignedBridge(t)
            panel:="0.28.7"
            switch kind{
            case "unsigned":f.sig=[]byte("not a signature")
            case "wrong-publisher":f.pub,_ ,_=ed25519.GenerateKey(rand.Reader)
            case "wrong-task":f.permit.FromTask="VOLVE-CI-OTHER";f.resign(t)
            case "wrong-args":f.permit.FromArgs="--diagnose";f.resign(t)
            case "wrong-executable":f.permit.FromExecutable="other.exe";f.resign(t)
            case "different-old-hash":f.permit.FromSHA256=strings.Repeat("0",64);f.resign(t)
            case "different-old-xml-hash":f.permit.FromTaskXMLSHA256=strings.Repeat("1",64);f.resign(t)
            case "different-new-hash":f.permit.ToSHA256=strings.Repeat("2",64);f.resign(t)
            case "different-new-version":f.permit.ToVersion="0.29.0";f.resign(t)
            case "different-new-size":f.permit.ToSize++;f.resign(t)
            case "different-new-panel":f.permit.MinPanelVersion="0.29.0";f.resign(t)
            case "altered-old-binary":if err:=os.WriteFile(f.live,[]byte("MZ_CHANGED"),0600);err!=nil{t.Fatal(err)}
            case "altered-candidate":if err:=os.WriteFile(f.candidate,[]byte("MZ_UNSIGNED"),0600);err!=nil{t.Fatal(err)}
            case "altered-backup":if err:=os.WriteFile(filepath.Join(f.backup,legacyBackupExe),[]byte("MZ_MODIFIED"),0600);err!=nil{t.Fatal(err)}
            case "missing-backup":if err:=os.Remove(filepath.Join(f.backup,legacyBackupReceipt));err!=nil{t.Fatal(err)}
            case "missing-manifest":if err:=os.Remove(f.candidate+".json");err!=nil{t.Fatal(err)}
            case "existing-managed-receipt":if err:=os.WriteFile(filepath.Join(f.root,installedReceiptName),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
            case "expired":f.permit.ExpiresUTC=time.Now().UTC().Add(-time.Second).Format(time.RFC3339);f.resign(t)
            case "future-issued":f.permit.IssuedUTC=time.Now().UTC().Add(time.Hour).Format(time.RFC3339);f.resign(t)
            case "too-long-validity":f.permit.ExpiresUTC=time.Now().UTC().Add(400*24*time.Hour).Format(time.RFC3339);f.resign(t)
            case "unsupported-old-updater":
                // Re-sign a valid but too-old new motor target and its manifest.
                b,_:=os.ReadFile(f.candidate+".json")
                var m Manifest
                if err:=json.Unmarshal(b,&m);err!=nil{t.Fatal(err)}
                m.Version="0.27.0";m.MinPanelVersion="0.28.7"
                raw,_:=json.Marshal(m)
                if err:=os.WriteFile(f.candidate+".json",raw,0600);err!=nil{t.Fatal(err)}
                if err:=os.WriteFile(f.candidate+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,raw))),0600);err!=nil{t.Fatal(err)}
                f.permit.ToVersion="0.27.0";f.resign(t)
            case "new-panel-too-old":panel="0.28.6"
            case "extra-signed-json":f.raw=append(f.raw,[]byte(" {}")...);f.sig=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,f.raw)))
            case "unknown-signed-json":
                f.raw=append(f.raw[:len(f.raw)-1],[]byte(`,"injected":true}`)...)
                f.sig=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,f.raw)))
            }
            _,err:=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,f.candidate,panel,
                f.raw,f.sig,f.pub,testSecureLabFolderBridge,func()error{f.preflightCalls++;return nil})
            if err==nil{t.Fatalf("unsafe signed bridge case %s accepted",kind)}
        })
    }
}
func TestSignedUnversionedBridgeFailsClosedOnPreflightACLAndCancellation(t *testing.T){
    f:=newSignedBridge(t)
    _,err:=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,f.candidate,"0.28.7",
        f.raw,f.sig,f.pub,testSecureLabFolderBridge,func()error{return errors.New("rescue unavailable")})
    if err==nil || !strings.Contains(err.Error(),"rescue unavailable"){t.Fatalf("live rescue bypassed: %v",err)}
    _,err=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,f.candidate,"0.28.7",
        f.raw,f.sig,f.pub,func(string)error{return errors.New("unsafe ACL")},func()error{return nil})
    if err==nil || !strings.Contains(err.Error(),"unsafe ACL"){t.Fatalf("unsafe ACL bypassed: %v",err)}
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    _,err=f.verify(ctx)
    if !errors.Is(err,context.Canceled){t.Fatalf("cancellation bypassed: %v",err)}
}
