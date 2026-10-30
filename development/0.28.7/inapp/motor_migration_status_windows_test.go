//go:build windows

package main

import (
    "context"
    "crypto/ed25519"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestMotorMigrationStatusShowsPreciselyMissingLegacyCertificate(t *testing.T) {
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    if err:=os.Remove(filepath.Join(root,legacyUpgradeStatement));err!=nil{t.Fatal(err)}
    if report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,false,nil);
        !strings.Contains(report,"falta la constancia firmada") ||
            !strings.Contains(report,"sin reinstalar") {
        t.Fatalf("unhelpful migration blocker: %s",report)
    }
}
func TestMotorMigrationStatusShowsMissingLegacySignature(t *testing.T) {
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    if err:=os.Remove(filepath.Join(root,legacyUpgradeSignature));err!=nil{t.Fatal(err)}
    if report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,false,nil);
        !strings.Contains(report,"falta la firma") {
        t.Fatalf("missing identity signature accepted: %s",report)
    }
}
func TestMotorMigrationStatusRejectsTamperedResidentOrCandidate(t *testing.T) {
    t.Run("resident",func(t *testing.T){
        root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
        if err:=os.WriteFile(filepath.Join(root,dnsServiceFile),[]byte("altered exe"),0600);err!=nil{t.Fatal(err)}
        report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,false,nil)
        if !strings.Contains(report,"no coincide"){t.Fatalf("resident tampering accepted: %s",report)}
    })
    t.Run("candidate",func(t *testing.T){
        root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
        if err:=os.WriteFile(candidate,[]byte("modified next"),0600);err!=nil{t.Fatal(err)}
        report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,false,nil)
        if !strings.Contains(report,"no auténtico"){t.Fatalf("candidate tampering accepted: %s",report)}
    })
}
func TestMotorMigrationStatusRejectsWrongPublisherAndPanel(t *testing.T){
    root,candidate,_:=makeSignedLegacyUpgradeFixture(t)
    wrong:=make(ed25519.PublicKey,ed25519.PublicKeySize)
    if report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",wrong,false,nil);
        !strings.Contains(report,"no auténtico"){t.Fatalf("forged publisher accepted: %s",report)}
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    if report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.6",key,false,nil);
        !strings.Contains(report,"incompatibles"){t.Fatalf("old panel marked compatible: %s",report)}
}
func TestMotorMigrationStatusNeverClaimsInstalledForUserWithoutUAC(t *testing.T){
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,false,nil)
    if !strings.Contains(report,"falta comprobación privilegiada") ||
        !strings.Contains(report,"no se instaló nada"){
        t.Fatalf("unsigned/unprivileged upgrade incorrectly advertised: %s",report)
    }
}
func TestMotorMigrationStatusEnforcesPreflightEvenWhenPublisherSigned(t *testing.T){
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    called:=0
    report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,true,
        func()(string,error){called++;return "",errors.New("no DNS fallback")})
    if called!=1 || !strings.Contains(report,"no DNS fallback") ||
        !strings.Contains(report,"no se instalará"){
        t.Fatalf("failed rescue preflight bypassed: %s calls=%d",report,called)
    }
}
func TestMotorMigrationStatusSignedAndHealthyStillBlocksProduction(t *testing.T){
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    called:=0
    report:=motorMigrationStatus(context.Background(),root,candidate,"0.28.7",key,true,
        func()(string,error){called++;return "CI-only rescue and loopback healthy",nil})
    if called!=1 || !strings.Contains(report,"aplicación productiva aún bloqueada") ||
        !strings.Contains(report,"reinicio"){
        t.Fatalf("readiness improperly became production switch: %s calls=%d",report,called)
    }
    // Status does not make any task/DNS changes or rewrite the signed assets.
    for _,path:=range []string{candidate,candidate+".json",candidate+".sig",
        filepath.Join(root,legacyUpgradeStatement),filepath.Join(root,legacyUpgradeSignature)} {
        if _,err:=os.Stat(path);err!=nil{t.Fatalf("read-only status altered %s: %v",path,err)}
    }
}
func TestMotorMigrationStatusCancellationFailsClosed(t *testing.T){
    root,candidate,key:=makeSignedLegacyUpgradeFixture(t)
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    got:=motorMigrationStatus(ctx,root,candidate,"0.28.7",key,true,goodLegacyPreflight)
    if !strings.Contains(got,"cancelada") {t.Fatalf("cancelled status accepted: %s",got)}
}
