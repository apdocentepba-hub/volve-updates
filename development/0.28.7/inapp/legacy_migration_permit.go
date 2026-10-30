package motorupdate

// Signed migration permit for one exact pre-release, unversioned DNS engine.
// The publisher explicitly authorizes a binary hash -> signed target version
// mapping; the local recovery receipt merely guarantees rollback bytes exist.
// A locally computed SHA-256 alone NEVER grants permission to change the motor.

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"
)

const maxMigrationPermitBytes = 4096

// LegacyMigrationPermit is only an authorization for a *specific* transition.
// It does not assert a historic version for the previous executable.
type LegacyMigrationPermit struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    FromTask string `json:"from_task"`
    FromArgs string `json:"from_args"`
    FromExecutable string `json:"from_executable"`
    FromSHA256 string `json:"from_sha256"`
    FromSize int64 `json:"from_size"`
    FromTaskXMLSHA256 string `json:"from_task_xml_sha256"`
    ToVersion string `json:"to_version"`
    ToSHA256 string `json:"to_sha256"`
    ToSize int64 `json:"to_size"`
    MinPanelVersion string `json:"min_panel_version"`
    IssuedUTC string `json:"issued_utc"`
    ExpiresUTC string `json:"expires_utc"`
}

// VerifiedLegacyMigrationProof is identity evidence ONLY, not permission to
// skip the independent SYSTEM watchdog or to invoke a production task switch.
type VerifiedLegacyMigrationProof struct {
    LegacySHA256 string
    LegacyTaskXMLSHA256 string
    CandidateVersion string
    CandidateSHA256 string
    ExpiresUTC string
}

func parseSignedMigrationPermit(raw, signature []byte,key ed25519.PublicKey)(LegacyMigrationPermit,error){
    var m LegacyMigrationPermit
    if len(key)!=ed25519.PublicKeySize{return m,errors.New("publisher key invalid")}
    if len(raw)<2 || len(raw)>maxMigrationPermitBytes || len(signature)<64 || len(signature)>256 {
        return m,errors.New("migration permit/signature missing or oversized")
    }
    sig,err:=base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(signature)))
    if err!=nil || len(sig)!=ed25519.SignatureSize || !ed25519.Verify(key,raw,sig) {
        return m,errors.New("publisher migration permit signature invalid")
    }
    dec:=json.NewDecoder(bytes.NewReader(raw))
    dec.DisallowUnknownFields()
    if err:=dec.Decode(&m);err!=nil{return LegacyMigrationPermit{},fmt.Errorf("migration permit schema invalid: %w",err)}
    var extra any
    if err:=dec.Decode(&extra);err!=io.EOF{return LegacyMigrationPermit{},errors.New("migration permit trailing bytes")}
    if m.Schema!=1 || m.Component!="dns-engine-legacy-migration" ||
        m.FromTask!=legacySystemTask || m.FromArgs!=legacyServiceArg ||
        m.FromExecutable!=legacyServiceName ||
        !hexRe.MatchString(m.FromSHA256) || m.FromSize<1 || m.FromSize>legacyBackupMaxExe ||
        !hexRe.MatchString(m.FromTaskXMLSHA256) ||
        !versionRe.MatchString(m.ToVersion) || !versionRe.MatchString(m.MinPanelVersion) ||
        !hexRe.MatchString(m.ToSHA256) || m.ToSize<1 || m.ToSize>legacyBackupMaxExe {
        return LegacyMigrationPermit{},errors.New("migration identity/versions not allowlisted")
    }
    issued,err:=time.Parse(time.RFC3339,m.IssuedUTC)
    if err!=nil{return LegacyMigrationPermit{},errors.New("permit issuance time invalid")}
    expires,err:=time.Parse(time.RFC3339,m.ExpiresUTC)
    if err!=nil{return LegacyMigrationPermit{},errors.New("permit expiration time invalid")}
    now:=time.Now().UTC()
    if issued.After(now.Add(5*time.Minute)) || expires.Before(now) ||
        !expires.After(issued) || expires.Sub(issued)>366*24*time.Hour {
        return LegacyMigrationPermit{},errors.New("migration permit expired, premature or unreasonably long")
    }
    return m,nil
}

// VerifySignedUnversionedLegacyMigration requires an explicit publisher
// signature, independently signed target and a still-intact backed-up *and*
// currently installed previous engine. The live SYSTEM task and DNS-health
// preflight MUST be supplied by the caller; no state is ever changed here.
//
// This proof must be rechecked immediately before any future task switch.
// An admin-readable local permit is not proof without ed25519 signature.
func VerifySignedUnversionedLegacyMigration(
    ctx context.Context,
    liveExe, backupDir, candidate, panelVersion string,
    permitJSON, permitSignature []byte, publisherKey ed25519.PublicKey,
    protectBackup func(string)error, livePreflight func()error,
) (VerifiedLegacyMigrationProof,error) {
    var empty VerifiedLegacyMigrationProof
    if err:=ctx.Err();err!=nil{return empty,err}
    if protectBackup==nil || livePreflight==nil{
        return empty,errors.New("missing trusted ACL or live SYSTEM/DNS preflight")
    }
    if !filepath.IsAbs(liveExe) || filepath.Base(liveExe)!=legacyServiceName ||
        !filepath.IsAbs(backupDir) || !filepath.IsAbs(candidate) {
        return empty,errors.New("legacy path or destination invalid")
    }
    // Installed managed motors must NEVER reenter the one-time legacy bridge.
    if _,err:=os.Lstat(filepath.Join(filepath.Dir(liveExe),installedReceiptName));err==nil{
        return empty,errors.New("managed motor already registered; legacy migration forbidden")
    }else if !errors.Is(err,os.ErrNotExist){return empty,err}
    permit,err:=parseSignedMigrationPermit(permitJSON,permitSignature,publisherKey)
    if err!=nil{return empty,err}
    candidateManifest,err:=VerifyStaged(candidate,publisherKey)
    if err!=nil{return empty,fmt.Errorf("candidate must be publisher signed: %w",err)}
    if candidateManifest.Version!=permit.ToVersion || candidateManifest.SHA256!=permit.ToSHA256 ||
        candidateManifest.Size!=permit.ToSize || candidateManifest.MinPanelVersion!=permit.MinPanelVersion{
        return empty,errors.New("signed candidate does not match signed migration destination")
    }
    if !versionRe.MatchString(panelVersion){return empty,errors.New("panel version unrecognized")}
    // Unknown historical versions are NEVER guessed from task name.
    // For this exact legacy task, a signed publisher bridge is only allowed
    // into the new updater generation (>=0.28.7); then enforce panel
    // compatibility independently. The signed hash pins the precise target.
    cutoff,err:=compareVersions(candidateManifest.Version,"0.28.7")
    if err!=nil || cutoff<0 {
        return empty,errors.New("legacy migration destination below first supported updater generation")
    }
    panelCmp,err:=compareVersions(panelVersion,candidateManifest.MinPanelVersion)
    if err!=nil || panelCmp<0 {
        return empty,errors.New("panel too old for signed candidate")
    }
    receipt,err:=VerifyUnversionedLegacyRecovery(backupDir,protectBackup)
    if err!=nil{return empty,fmt.Errorf("safe rollback backup unavailable: %w",err)}
    if receipt.ExeSHA256!=permit.FromSHA256 || receipt.ExeSize!=permit.FromSize ||
        receipt.XMLSHA256!=permit.FromTaskXMLSHA256{
        return empty,errors.New("signed old motor/task hash differs from protected rollback backup")
    }
    if err:=ctx.Err();err!=nil{return empty,err}
    // Running state is checked AFTER validating both signatures and backup.
    if err:=livePreflight();err!=nil{return empty,fmt.Errorf("live SYSTEM/rescue/DNS checks rejected: %w",err)}
    activeHash,activeSize,err:=legacyDigest(liveExe,legacyBackupMaxExe)
    if err!=nil{return empty,err}
    if activeHash!=permit.FromSHA256 || activeSize!=permit.FromSize{
        return empty,errors.New("running legacy executable changed since signed permit/backup")
    }
    if err:=ctx.Err();err!=nil{return empty,err}
    return VerifiedLegacyMigrationProof{
        LegacySHA256:permit.FromSHA256,
        LegacyTaskXMLSHA256:permit.FromTaskXMLSHA256,
        CandidateVersion:permit.ToVersion,
        CandidateSHA256:permit.ToSHA256,
        ExpiresUTC:permit.ExpiresUTC,
    },nil
}
