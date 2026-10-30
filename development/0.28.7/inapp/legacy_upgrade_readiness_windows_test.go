//go:build windows

package main

// Read-only unit tests. No Windows tasks, DNS configuration or rescue scripts
// are modified; all signed objects are ephemeral laboratory fixtures.
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

    "volve-browser-protection/motorupdate"
)

func makeSignedLegacyUpgradeFixture(t *testing.T)(string,string,ed25519.PublicKey){
    t.Helper()
    root:=t.TempDir()
    old:=[]byte("MZ_VOLVE_LEGACY_DNS_FIXTURE_0270")
    oldExe:=filepath.Join(root,dnsServiceFile)
    if err:=os.WriteFile(oldExe,old,0600);err!=nil{t.Fatal(err)}
    oldHash:=sha256.Sum256(old)
    pub,priv,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    legacy:=motorupdate.LegacyMotorStatement{
        Schema:1,Component:"dns-engine-legacy",Version:"0.27.0",
        TaskName:dnsServiceTask,ExecutableName:dnsServiceFile,Args:"--dns-service",
        SHA256:hex.EncodeToString(oldHash[:]),Size:int64(len(old)),
    }
    raw,err:=json.Marshal(legacy);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(root,legacyUpgradeStatement),raw,0600);err!=nil{t.Fatal(err)}
    signature:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
    if err:=os.WriteFile(filepath.Join(root,legacyUpgradeSignature),signature,0600);err!=nil{t.Fatal(err)}
    candidate:=filepath.Join(root,"VOLVE_DNS_Motor_0_28_7.exe")
    next:=[]byte("MZ_SIGNED_LAB_DNS_ENGINE_0287")
    if err:=os.WriteFile(candidate,next,0600);err!=nil{t.Fatal(err)}
    nextHash:=sha256.Sum256(next)
    m:=motorupdate.Manifest{
        Schema:1,Component:"dns-engine",Version:"0.28.7",MinPanelVersion:"0.28.7",
        URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
        SHA256:hex.EncodeToString(nextHash[:]),Size:int64(len(next)),Notes:"signed temporary motor evidence fixture",
    }
    manifest,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".json",manifest,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,manifest))),0600);err!=nil{t.Fatal(err)}
    return root,candidate,pub
}
func goodLegacyPreflight()(string,error){return "identity and rescue verified in disposable test",nil}

func TestResidentMotorIdentityReadinessRequiresDualSignedEvidence(t *testing.T){
    root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
    result,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.7",pub,goodLegacyPreflight)
    if err!=nil{t.Fatal(err)}
    if result.LegacyVersion!="0.27.0" || result.CandidateVersion!="0.28.7" ||
        len(result.LegacySHA256)!=64 || len(result.CandidateSHA256)!=64 {
        t.Fatalf("unexpected verified motor identities: %#v",result)
    }
    report:=formatLegacyUpgradeEvidence(result)
    if !strings.Contains(report,"SOLO LECTURA") || !strings.Contains(report,"NO AUTORIZA REEMPLAZAR"){
        t.Fatalf("unsafe readiness wording: %s",report)
    }
}
func TestResidentMotorEvidenceNeverTrustsPreflightFailure(t *testing.T){
    root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
    wanted:=errors.New("SYSTEM rescue task unavailable")
    _,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.7",pub,
        func()(string,error){return "",wanted})
    if !errors.Is(err,wanted){t.Fatalf("failed preflight bypassed: %v",err)}
}
func TestResidentMotorEvidenceRejectsUnsignedLegacyAndNoStatement(t *testing.T){
    for _,mode:=range []string{"missing","tampered","forged"}{
        t.Run(mode,func(t *testing.T){
            root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
            path:=filepath.Join(root,legacyUpgradeStatement)
            switch mode {
            case "missing":
                if err:=os.Remove(path);err!=nil{t.Fatal(err)}
            case "tampered":
                if err:=os.WriteFile(path,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
            case "forged":
                forged,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
                pub=forged
            }
            if _,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.7",pub,goodLegacyPreflight);err==nil{
                t.Fatal("untrusted installed legacy motor granted version")
            }
        })
    }
}
func TestResidentMotorEvidenceRejectsModifiedInstalledMotor(t *testing.T){
    root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
    if err:=os.WriteFile(filepath.Join(root,dnsServiceFile),[]byte("MZ_TAMPERED_LEGACY_ENGINE"),0600);err!=nil{t.Fatal(err)}
    if _,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.7",pub,goodLegacyPreflight);err==nil{
        t.Fatal("altered legacy motor accepted")
    }
}
func TestResidentMotorEvidenceRejectsTamperedCandidate(t *testing.T){
    root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
    if err:=os.WriteFile(candidate,[]byte("MZ_UNTRUSTED_MOTOR"),0600);err!=nil{t.Fatal(err)}
    if _,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.7",pub,goodLegacyPreflight);err==nil{
        t.Fatal("altered candidate motor accepted")
    }
}
func TestResidentMotorEvidenceEnforcesPanelCompatibility(t *testing.T){
    root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
    if _,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.6",pub,goodLegacyPreflight);err==nil{
        t.Fatal("panel older than signed minimum accepted")
    }
}
func TestResidentMotorEvidenceRejectsCancellationAndNoPreflight(t *testing.T){
    root,candidate,pub:=makeSignedLegacyUpgradeFixture(t)
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    called:=false
    if _,err:=analyzeResidentUpgradeEvidence(ctx,root,candidate,"0.28.7",pub,func()(string,error){called=true;return "",nil});!errors.Is(err,context.Canceled) {
        t.Fatalf("cancellation ignored: %v",err)
    }
    if called{t.Fatal("preflight ran despite cancellation")}
    if _,err:=analyzeResidentUpgradeEvidence(context.Background(),root,candidate,"0.28.7",pub,nil);err==nil{
        t.Fatal("missing Windows preflight accepted")
    }
}
