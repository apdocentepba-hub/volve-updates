//go:build windows

package main

import (
    "context"
    "encoding/base64"
    "time"
    "crypto/ed25519"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "volve-browser-protection/motorupdate"
)

// This is a production-identity READ-ONLY gate for the future DNS updater.
// It cannot change tasks, DNS, install files or start a candidate.
const legacyUpgradeStatement = "VOLVE_DNS_Legacy_Attestation.json"
const legacyUpgradeSignature = "VOLVE_DNS_Legacy_Attestation.sig"

type LegacyUpgradeEvidence struct {
    LegacyVersion string
    LegacySHA256 string
    CandidateVersion string
    CandidateSHA256 string
    LegacyExe string
    CandidateExe string
    PreflightReport string
}

// readBoundedProvenance does not follow links and never creates a file.
// Only publisher-signed provenance can identify an unversioned legacy binary.
func readBoundedProvenance(path string, maxBytes int64) ([]byte,error) {
    info,err:=os.Lstat(path)
    if err!=nil{return nil,err}
    if !info.Mode().IsRegular() || info.Size()<=0 || info.Size()>maxBytes {
        return nil,errors.New("atestación ausente, enlazada o fuera de límite")
    }
    return os.ReadFile(path)
}

// analyzeResidentUpgradeEvidence verifies independently signed legacy motor
// identity AND independently signed new motor bytes. The preflight is
// injected only so CI can exercise this logic without touching SYSTEM tasks.
func analyzeResidentUpgradeEvidence(
    ctx context.Context, root, candidate, panelVersion string,
    key ed25519.PublicKey, preflight func() (string,error),
) (LegacyUpgradeEvidence,error) {
    var evidence LegacyUpgradeEvidence
    if err:=ctx.Err();err!=nil{return evidence,err}
    if !filepath.IsAbs(root) || !filepath.IsAbs(candidate) || len(key)!=ed25519.PublicKeySize {
        return evidence,errors.New("ruta absoluta o clave del editor ausente")
    }
    if preflight==nil{return evidence,errors.New("preflight de motor no disponible")}
    // Preflight checks the REAL resident Task Scheduler identity, independent
    // rescue scripts, DNS-rescue journal and IPv4/IPv6. A valid signed JSON
    // alone can never bypass Windows checks in the production caller.
    report,err:=preflight()
    if err!=nil{return evidence,fmt.Errorf("motor residente no verificable: %w",err)}
    if err:=ctx.Err();err!=nil{return evidence,err}
    exe:=filepath.Join(root,dnsServiceFile)
    raw,err:=readBoundedProvenance(filepath.Join(root,legacyUpgradeStatement),4096)
    if err!=nil{return evidence,fmt.Errorf("falta atestación firmada de motor heredado: %w",err)}
    sig,err:=readBoundedProvenance(filepath.Join(root,legacyUpgradeSignature),256)
    if err!=nil{return evidence,fmt.Errorf("falta firma de motor heredado: %w",err)}
    legacyVersion,err:=motorupdate.VerifyLegacyMotorAttestation(
        exe,dnsServiceTask,"--dns-service",raw,sig,key,
    )
    if err!=nil{return evidence,fmt.Errorf("versión del motor heredado no demostrada: %w",err)}
    if err:=ctx.Err();err!=nil{return evidence,err}
    manifest,err:=motorupdate.VerifyStaged(candidate,key)
    if err!=nil{return evidence,fmt.Errorf("motor nuevo no firmado o adulterado: %w",err)}
    eligible,err:=motorupdate.IsEligible(legacyVersion,panelVersion,manifest)
    if err!=nil{return evidence,fmt.Errorf("compatibilidad de versiones no demostrada: %w",err)}
    if !eligible{
        return evidence,fmt.Errorf("motor nuevo %s no corresponde a una actualización permitida de %s (Centro %s)",
            manifest.Version,legacyVersion,panelVersion)
    }
    legacyBytesHash,err:=digestMotorFile(exe)
    if err!=nil{return evidence,err}
    if err:=ctx.Err();err!=nil{return evidence,err}
    // Be explicit: this report is a verified identification, NOT an
    // authorization to replace a live DNS server or a successful upgrade.
    evidence=LegacyUpgradeEvidence{
        LegacyVersion:legacyVersion,LegacySHA256:legacyBytesHash,
        CandidateVersion:manifest.Version,CandidateSHA256:manifest.SHA256,
        LegacyExe:exe,CandidateExe:candidate,PreflightReport:report,
    }
    return evidence,nil
}

func inspectResidentMotorUpgradeReadOnly(ctx context.Context,candidate string,key ed25519.PublicKey)(LegacyUpgradeEvidence,error){
    var empty LegacyUpgradeEvidence
    if !isAdmin(){return empty,errors.New("la evaluación del motor instalado requiere administrador; Windows permanece intacto")}
    root,err:=installRoot()
    if err!=nil{return empty,err}
    return analyzeResidentUpgradeEvidence(ctx,root,candidate,version,key,preflightMotorUpgradeReadOnly)
}

func formatLegacyUpgradeEvidence(e LegacyUpgradeEvidence)string{
    var b strings.Builder
    fmt.Fprintf(&b,"VOLVÉ — IDENTIDAD DE MOTOR ANTES DE ACTUALIZAR (SOLO LECTURA)\n")
    fmt.Fprintf(&b,"Motor heredado comprobado: %s, SHA-256: %s\n",e.LegacyVersion,e.LegacySHA256)
    fmt.Fprintf(&b,"Motor candidato firmado: %s, SHA-256: %s\n",e.CandidateVersion,e.CandidateSHA256)
    b.WriteString("Tarea SYSTEM, rescate y DNS: validación de preflight obligatoria.\n")
    b.WriteString("NO SE CAMBIARON TAREAS, DNS NI EJECUTABLES. NO AUTORIZA REEMPLAZAR EL MOTOR.\n")
    return b.String()
}


func runMotorUpgradeEvidenceCLI(candidate string) error {
    rawKey,err:=base64.StdEncoding.DecodeString(updaterPublicKey)
    if err!=nil || len(rawKey)!=ed25519.PublicKeySize{
        return errors.New("clave pública de actualización inválida")
    }
    ctx,cancel:=context.WithTimeout(context.Background(),35*time.Second)
    defer cancel()
    report,err:=inspectResidentMotorUpgradeReadOnly(ctx,candidate,ed25519.PublicKey(rawKey))
    if err!=nil{return err}
    fmt.Print(formatLegacyUpgradeEvidence(report))
    return nil
}
