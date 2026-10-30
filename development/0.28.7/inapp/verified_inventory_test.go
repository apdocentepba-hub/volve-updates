package motorupdate

import (
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
)

func signedInventoryCandidate(t *testing.T, root, version string, private ed25519.PrivateKey) string {
    t.Helper()
    dir:=filepath.Join(root,"motor-"+version)
    if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
    payload:=[]byte("MZ_LAB_SIGNED_MOTOR_VERSION_"+version)
    h:=sha256.Sum256(payload)
    m:=Manifest{Schema:1,Component:"dns-engine",Version:version,
        MinPanelVersion:"0.28.7",
        URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v"+version+"/VOLVE_DNS_Motor_"+strings.ReplaceAll(version,".","_")+".exe",
        SHA256:hex.EncodeToString(h[:]),Size:int64(len(payload)),Notes:"test candidate only",
    }
    raw,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
    candidate:=installedEnginePath(root,version)
    for _,p:=range []struct{file string;data []byte}{
        {candidate,payload},
        {candidate+".json",raw},
        {candidate+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private,raw)))},
    } {
        if err:=os.WriteFile(p.file,p.data,0600);err!=nil{t.Fatal(err)}
    }
    return candidate
}
func inventoryKey(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey) {
    t.Helper()
    pub,priv,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    return pub,priv
}

func TestInventoryRejectsUnknownLegacyEngine(t *testing.T) {
    root:=t.TempDir();pub,_:=inventoryKey(t)
    if _,err:=InspectInstalledEngine(root,pub); !errors.Is(err,ErrUnregisteredEngine) {
        t.Fatalf("missing receipt should be unknown, got %v",err)
    }
}

func TestInventoryTracksVerifiedUpgradeAndRejectsDowngrade(t *testing.T) {
    root:=t.TempDir();pub,priv:=inventoryKey(t)
    a:=signedInventoryCandidate(t,root,"0.28.7",priv)
    b:=signedInventoryCandidate(t,root,"0.28.8",priv)
    if err:=RecordVerifiedEngine(root,a,pub);err!=nil{t.Fatal(err)}
    if err:=RecordVerifiedEngine(root,a,pub);err!=nil{t.Fatalf("same signed candidate should be idempotent: %v",err)}
    got,err:=InspectInstalledEngine(root,pub)
    if err!=nil || got!="0.28.7"{t.Fatalf("incorrect installed version %q err=%v",got,err)}
    if err:=RecordVerifiedEngine(root,b,pub);err!=nil{t.Fatal(err)}
    got,err=InspectInstalledEngine(root,pub)
    if err!=nil || got!="0.28.8"{t.Fatalf("unexpected new installed version %q err=%v",got,err)}
    if err:=RecordVerifiedEngine(root,a,pub);err==nil {t.Fatal("engine downgraded")}
}

func TestInventoryRejectsTamperedBinaryOrManifest(t *testing.T) {
    root:=t.TempDir();pub,priv:=inventoryKey(t)
    candidate:=signedInventoryCandidate(t,root,"0.28.7",priv)
    if err:=RecordVerifiedEngine(root,candidate,pub);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate,[]byte("MZ_tampered"),0600);err!=nil{t.Fatal(err)}
    if _,err:=InspectInstalledEngine(root,pub);err==nil{t.Fatal("tampered motor accepted")}
    if err:=RecordVerifiedEngine(root,candidate,pub);err==nil{t.Fatal("tampered motor re-recorded")}
}

func TestInventoryRejectsChangedReceiptAndStaleVersion(t *testing.T) {
    root:=t.TempDir();pub,priv:=inventoryKey(t)
    candidate:=signedInventoryCandidate(t,root,"0.28.7",priv)
    if err:=RecordVerifiedEngine(root,candidate,pub);err!=nil{t.Fatal(err)}
    state:=filepath.Join(root,installedReceiptName)
    if err:=os.WriteFile(state,[]byte(`{"schema":1,"version":"0.28.8","sha256":"`+strings.Repeat("0",64)+`"}`),0600);err!=nil{t.Fatal(err)}
    if _,err:=InspectInstalledEngine(root,pub);err==nil{t.Fatal("false installed version accepted")}
    if err:=RecordVerifiedEngine(root,candidate,pub);err==nil{t.Fatal("corrupt receipt overwritten")}
}

func TestInventoryRejectsUnexpectedFieldsAndRelativeRoot(t *testing.T) {
    root:=t.TempDir();pub,priv:=inventoryKey(t)
    candidate:=signedInventoryCandidate(t,root,"0.28.7",priv)
    if err:=RecordVerifiedEngine(root,candidate,pub);err!=nil{t.Fatal(err)}
    state:=filepath.Join(root,installedReceiptName)
    if err:=os.WriteFile(state,[]byte(`{"schema":1,"version":"0.28.7","sha256":"`+strings.Repeat("0",64)+`","task":"hijack"}`),0600);err!=nil{t.Fatal(err)}
    if _,err:=InspectInstalledEngine(root,pub);err==nil{t.Fatal("unknown receipt field accepted")}
    if _,err:=InspectInstalledEngine("relative",pub);err==nil{t.Fatal("relative trusted directory accepted")}
}

func TestInventoryRejectsOutOfRootCandidate(t *testing.T) {
    root:=t.TempDir();elsewhere:=t.TempDir();pub,priv:=inventoryKey(t)
    candidate:=signedInventoryCandidate(t,elsewhere,"0.28.7",priv)
    if err:=RecordVerifiedEngine(root,candidate,pub);err==nil{t.Fatal("out-of-root signed candidate accepted")}
}

func TestInventoryRejectsSymlinkedMotorFile(t *testing.T) {
    root:=t.TempDir();pub,priv:=inventoryKey(t)
    candidate:=signedInventoryCandidate(t,root,"0.28.7",priv)
    data,err:=os.ReadFile(candidate);if err!=nil{t.Fatal(err)}
    backing:=filepath.Join(root,"other.exe")
    if err:=os.WriteFile(backing,data,0600);err!=nil{t.Fatal(err)}
    if err:=os.Remove(candidate);err!=nil{t.Fatal(err)}
    if err:=os.Symlink(backing,candidate);err!=nil{t.Skipf("symlink requires privileges on this OS: %v",err)}
    if err:=RecordVerifiedEngine(root,candidate,pub);err==nil{t.Fatal("symlinked candidate accepted")}
}
