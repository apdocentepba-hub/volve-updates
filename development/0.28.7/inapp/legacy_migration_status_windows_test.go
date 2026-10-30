//go:build windows

package main

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

    "volve-browser-protection/motorupdate"
)

// Ephemeral fixture keys are for CI ONLY, never production migration grants.
type migrationStatusFixture struct {
    root, candidate, backup string
    pub ed25519.PublicKey
    priv ed25519.PrivateKey
}

func makeMigrationStatusFixture(t *testing.T) migrationStatusFixture {
    t.Helper()
    root := t.TempDir()
    live := filepath.Join(root, dnsServiceFile)
    old := []byte("MZ_PREVIOUS_VOLVE_UNVERSIONED_RESIDENT_DNS")
    if err := os.WriteFile(live, old, 0600); err != nil { t.Fatal(err) }
    parent := filepath.Join(root, localRecoveryFolder)
    if err := os.Mkdir(parent, 0700); err != nil { t.Fatal(err) }
    backup := filepath.Join(parent, localRecoverySnapshot)
    xml := []byte(strings.Repeat("<Task><Principal>SYSTEM</Principal><Command>VOLVE_DNS_Server_0270.exe</Command></Task>", 2))
    record, err := motorupdate.PrepareUnversionedLegacyRecovery(
        context.Background(), live, xml, backup, func(string) error { return nil },
    )
    if err != nil { t.Fatal(err) }
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    candidate := filepath.Join(root, "VOLVE_DNS_Motor_0_28_7.exe")
    next := []byte("MZ_NEXT_SIGNED_DNS_ENGINE_0287")
    if err := os.WriteFile(candidate, next, 0600); err != nil { t.Fatal(err) }
    sum := sha256.Sum256(next)
    manifest := motorupdate.Manifest{
        Schema: 1, Component: "dns-engine", Version: "0.28.7",
        MinPanelVersion: "0.28.7",
        URL: "https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
        SHA256: hex.EncodeToString(sum[:]), Size: int64(len(next)), Notes: "ephemeral CI only",
    }
    rawManifest, err := json.Marshal(manifest)
    if err != nil { t.Fatal(err) }
    if err := os.WriteFile(candidate+".json", rawManifest, 0600); err != nil { t.Fatal(err) }
    if err := os.WriteFile(candidate+".sig", []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, rawManifest))), 0600); err != nil { t.Fatal(err) }
    now := time.Now().UTC()
    permit := motorupdate.LegacyMigrationPermit{
        Schema: 1, Component: "dns-engine-legacy-migration",
        FromTask: "VOLVE-DNS-SERVER-0270", FromArgs: "--dns-service",
        FromExecutable: dnsServiceFile,
        FromSHA256: record.ExeSHA256, FromSize: record.ExeSize,
        FromTaskXMLSHA256: record.XMLSHA256,
        ToVersion: manifest.Version, ToSHA256: manifest.SHA256, ToSize: manifest.Size,
        MinPanelVersion: manifest.MinPanelVersion,
        IssuedUTC: now.Add(-time.Hour).Format(time.RFC3339),
        ExpiresUTC: now.Add(time.Hour).Format(time.RFC3339),
    }
    raw, err := json.Marshal(permit)
    if err != nil { t.Fatal(err) }
    if err := os.WriteFile(candidate+signedMigrationJSON, raw, 0600); err != nil { t.Fatal(err) }
    if err := os.WriteFile(candidate+signedMigrationSignature,
        []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))), 0600); err != nil { t.Fatal(err) }
    return migrationStatusFixture{root: root, candidate: candidate, backup: backup, pub: pub, priv: priv}
}
func statusTestACL(string) error { return nil } // CI only: real caller checks Windows NTFS DACL.

func TestPreparedSignedMigrationValidIsReadOnlyAndNeverClaimsInstalled(t *testing.T) {
    f := makeMigrationStatusFixture(t)
    called := 0
    report, found := preparedSignedLegacyMigrationStatus(
        context.Background(), f.root, f.candidate, "0.28.7", f.pub,
        true, func()(string,error){ called++; return "CI task and DNS OK",nil }, statusTestACL,
    )
    if !found || called!=1 || !strings.Contains(report,"permiso editorial firmado") ||
        !strings.Contains(report,"NO se cambió el motor") ||
        !strings.Contains(report,"bloqueada") {
        t.Fatalf("verified status must never claim installation: %q (found=%v, calls=%d)",report,found,called)
    }
    if _,err:=os.Stat(filepath.Join(f.backup,"VOLVE_DNS_Legacy_Recovery.exe"));err!=nil{t.Fatal(err)}
    if _,err:=os.Stat(filepath.Join(f.root,dnsServiceFile));err!=nil{t.Fatal(err)}
}

func TestPreparedSignedMigrationRefusesPartialForgedAndUnsafeEvidence(t *testing.T) {
    for _, mode := range []string{
        "missing-signature", "fake-signature", "wrong-key", "tampered-live-motor",
        "tampered-backup", "insecure-parent-acl", "missing-preflight", "preflight-fails",
        "not-admin", "older-panel",
    } {
        t.Run(mode,func(t *testing.T){
            f:=makeMigrationStatusFixture(t)
            key:=f.pub
            elevated:=true
            panel:="0.28.7"
            acl:=statusTestACL
            preflight:=func()(string,error){return "CI",nil}
            switch mode {
            case "missing-signature":
                if err:=os.Remove(f.candidate+signedMigrationSignature);err!=nil{t.Fatal(err)}
            case "fake-signature":
                if err:=os.WriteFile(f.candidate+signedMigrationSignature,[]byte("fake"),0600);err!=nil{t.Fatal(err)}
            case "wrong-key":
                key,_,_=ed25519.GenerateKey(rand.Reader)
            case "tampered-live-motor":
                if err:=os.WriteFile(filepath.Join(f.root,dnsServiceFile),[]byte("MZ_CHANGED"),0600);err!=nil{t.Fatal(err)}
            case "tampered-backup":
                if err:=os.WriteFile(filepath.Join(f.backup,"VOLVE_DNS_Legacy_Recovery.exe"),[]byte("MZ_CHANGED"),0600);err!=nil{t.Fatal(err)}
            case "insecure-parent-acl":
                acl=func(string)error{return errors.New("Everyone can write")}
            case "missing-preflight":
                preflight=nil
            case "preflight-fails":
                preflight=func()(string,error){return "",errors.New("rescue unavailable")}
            case "not-admin":
                elevated=false
            case "older-panel":
                panel="0.28.6"
            }
            report,found:=preparedSignedLegacyMigrationStatus(context.Background(),f.root,f.candidate,panel,key,elevated,preflight,acl)
            if !found || strings.Contains(report,"permiso editorial firmado y respaldo original verificados") ||
                !strings.Contains(report,"no se instal") {
                t.Fatalf("invalid case %s accepted: %q (found=%v)",mode,report,found)
            }
        })
    }
}

func TestPreparedSignedMigrationAbsentDoesNotReplaceLegacyAttestationFlow(t *testing.T){
    f:=makeMigrationStatusFixture(t)
    for _,suffix:=range []string{signedMigrationJSON,signedMigrationSignature}{
        if err:=os.Remove(f.candidate+suffix);err!=nil{t.Fatal(err)}
    }
    report,found:=preparedSignedLegacyMigrationStatus(
        context.Background(),f.root,f.candidate,"0.28.7",f.pub,true,
        goodLegacyPreflight,statusTestACL)
    if found || report!=""{t.Fatalf("absent permit should fall back to legacy mode: %q",report)}
}

func TestMotorMigrationStatusUsesSignedPermitInsteadOfMissingOldVersion(t *testing.T){
    f:=makeMigrationStatusFixture(t)
    // The installed button runs without UAC. It must report prerequisites
    // without pretending it can apply a newer DNS engine.
    report:=motorMigrationStatus(context.Background(),f.root,f.candidate,"0.28.7",f.pub,false,nil)
    if !strings.Contains(report,"permiso de migración presente") ||
        !strings.Contains(report,"falta verificación privilegiada") ||
        strings.Contains(report,"falta la constancia firmada"){
        t.Fatalf("signed permit not reached from installed update button: %q",report)
    }
}

func TestPreparedSignedMigrationCancellationNeverRunsPreflight(t *testing.T){
    f:=makeMigrationStatusFixture(t)
    ctx,cancel:=context.WithCancel(context.Background()); cancel()
    calls:=0
    report,found:=preparedSignedLegacyMigrationStatus(ctx,f.root,f.candidate,"0.28.7",f.pub,true,
        func()(string,error){calls++;return "",nil},statusTestACL)
    if !found || calls!=0 || strings.Contains(report,"permiso editorial firmado y respaldo original verificados"){
        t.Fatalf("cancelled bridge incorrectly authorized: %q (called=%d)",report,calls)
    }
}
