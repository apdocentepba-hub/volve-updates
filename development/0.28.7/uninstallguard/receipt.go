package uninstallguard

// Signed installed-receipt verification for a FUTURE 0.28.7 uninstaller.
//
// Authentication of an installer-written receipt is necessary but is NEVER
// sufficient to authorize a task, DNS, file, or policy change. The bytes must
// be signed by a separately pinned production publisher key, and the resulting
// installed objects still require a fresh privileged live ownership check.

import (
    "bytes"
    "crypto/ed25519"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "strings"

    "volve.local/installer/unifiedbundle"
)

const (
    maxSignedReceiptBytes = 64 * 1024
    completedReceiptState = "COMMITTED_REBOOT_WATCHDOG_VERIFIED"
)

type ReceiptFile struct {
    ID string `json:"id"`
    File string `json:"file"`
    Root string `json:"root"` // "install" or "data"; signed and mandatory
    Size int64 `json:"size"`
    SHA256 string `json:"sha256"`
}

type ReceiptTask struct {
    Name string `json:"name"`
    Principal string `json:"principal"`
    XMLSHA256 string `json:"xml_sha256"`
    ActionSHA256 string `json:"action_sha256"`
}

// InstalledReceipt is an editorial record created only AFTER the privileged
// installer has committed AND independently verified reboot recovery.
// Neither state nor embedded fingerprints alone establish live ownership.
type InstalledReceipt struct {
    Schema int `json:"schema"`
    Release string `json:"release"`
    Platform string `json:"platform"`
    State string `json:"state"`
    InstallationID string `json:"installation_id"`
    InstallRoot string `json:"install_root"`
    DataRoot string `json:"data_root"`
    Origin string `json:"origin"`
    OriginMotorSHA256 string `json:"origin_motor_sha256"`
    PackageManifestSHA256 string `json:"package_manifest_sha256"`
    OriginalDNSSnapshotSHA256 string `json:"original_dns_snapshot_sha256"`
    RecoveryJournalSHA256 string `json:"recovery_journal_sha256"`
    Files []ReceiptFile `json:"files"`
    Tasks []ReceiptTask `json:"tasks"`
}

func isSHA256(s string) bool {
    if len(s)!=64 || strings.ToLower(s)!=s {return false}
    _,err:=hex.DecodeString(s)
    return err==nil
}

func windowsAbsolutePath(p string) bool {
    if len(p)<4 || len(p)>1024 || p[1]!=':' || p[2]!='\\' ||
        !(p[0]>='A'&&p[0]<='Z') || strings.ContainsAny(p,"/\x00\r\n\t*?\"<>|") {
        return false
    }
    for _,segment:=range strings.Split(p[3:],"\\") {
        if segment==""||segment=="."||segment==".."||
            strings.Contains(segment,":")||strings.HasSuffix(segment,".")||strings.HasSuffix(segment," ") {return false}
    }
    return true
}

func validateReceipt(r InstalledReceipt) error {
    if r.Schema!=1 || r.Release!="0.28.7" || r.Platform!="windows-amd64" ||
        r.State!=completedReceiptState || len(r.InstallationID)!=32 {
        return errors.New("signed receipt version, completion state or installation ID invalid")
    }
    if _,err:=hex.DecodeString(r.InstallationID);err!=nil || strings.ToLower(r.InstallationID)!=r.InstallationID {
        return errors.New("installation ID must be exact lowercase hex")
    }
    if !windowsAbsolutePath(r.InstallRoot)||!windowsAbsolutePath(r.DataRoot)||
        strings.EqualFold(r.InstallRoot,r.DataRoot) {
        return errors.New("installed Windows roots are not canonical or independent")
    }
    if r.Origin!="FRESH" && r.Origin!="MIGRATED_FROM_0286"{
        return errors.New("unknown installed origin")
    }
    if (r.Origin=="FRESH" && r.OriginMotorSHA256!="") ||
        (r.Origin=="MIGRATED_FROM_0286"&&!isSHA256(r.OriginMotorSHA256)) {
        return errors.New("legacy original motor hash missing or inapplicable")
    }
    for _,hash:=range []string{r.PackageManifestSHA256,r.OriginalDNSSnapshotSHA256,r.RecoveryJournalSHA256}{
        if !isSHA256(hash){return errors.New("missing signed release, DNS or recovery journal hash")}
    }

    required:=unifiedbundle.RequiredFiles()
    if len(r.Files)!=len(required){return errors.New("signed receipt lacks exact eight release component identities")}
    previous:=""
    for _,f:=range r.Files {
        name,ok:=required[f.ID]
        if !ok || f.File!=name || (f.Root!="install" && f.Root!="data") || f.ID<=previous || f.Size<=0 || f.Size>1<<30 || !isSHA256(f.SHA256){
            return fmt.Errorf("signed installed component identity rejected: %q",f.ID)
        }
        previous=f.ID
    }
    if len(r.Tasks)==0 || len(r.Tasks)>8 {return errors.New("signed installed tasks missing or excessive")}
    previous=""
    for _,t:=range r.Tasks {
        if t.Principal!="SYSTEM" || !strings.HasPrefix(t.Name,"VOLVE-")||
            len(t.Name)>128 || t.Name<=previous || strings.ContainsAny(t.Name,"\\/:*?\"<>|\x00\r\n") ||
            !isSHA256(t.XMLSHA256)||!isSHA256(t.ActionSHA256){
            return errors.New("signed SYSTEM scheduled-task identity invalid")
        }
        switch strings.ToUpper(t.Name) {
        case "VOLVE-CATALOGO-0230","VOLVE-DNS-RESCUE-0270","VOLVE-DNS-SERVER-0270":
            return errors.New("legacy 0.28.6 task cannot be claimed as owned by 0.28.7")
        }
        previous=t.Name
    }
    return nil
}

// VerifySignedInstalledReceipt validates exact publisher-authenticated bytes,
// with a caller-supplied trusted public key from the product, never from a
// user-supplied receipt. This verifies a historical record, NOT live state.
func VerifySignedInstalledReceipt(raw,signature []byte,trusted ed25519.PublicKey)(InstalledReceipt,error) {
    var zero InstalledReceipt
    if len(trusted)!=ed25519.PublicKeySize||len(signature)!=ed25519.SignatureSize||
        len(raw)==0||len(raw)>maxSignedReceiptBytes {
        return zero,errors.New("external trusted publisher signature required")
    }
    if !ed25519.Verify(trusted,raw,signature) {
        return zero,errors.New("installed receipt publisher signature mismatch")
    }
    d:=json.NewDecoder(bytes.NewReader(raw))
    d.DisallowUnknownFields()
    var r InstalledReceipt
    if err:=d.Decode(&r);err!=nil{return zero,fmt.Errorf("signed receipt JSON invalid: %w",err)}
    var trailing any
    if d.Decode(&trailing)!=io.EOF{return zero,errors.New("extra signed receipt content")}
    canonical,err:=json.Marshal(r)
    if err!=nil||!bytes.Equal(canonical,raw) {
        return zero,errors.New("signed receipt is not strict canonical JSON")
    }
    if err:=validateReceipt(r);err!=nil{return zero,err}
    return r,nil
}

// ReviewWithSignedReceipt can remove only the editorial-receipt PREREQUISITE,
// not authorization. All destructive plan flags remain false. Original legacy
// tasks or a recovery journal take precedence even when receipt is valid.
func ReviewWithSignedReceipt(e Evidence,raw,signature []byte,trusted ed25519.PublicKey)(Plan,error) {
    plan,err:=Review(e)
    if err!=nil{return Plan{},err}
    if _,err=VerifySignedInstalledReceipt(raw,signature,trusted);err!=nil {
        return Plan{},err
    }
    if e.LegacyTasks>0 || e.RecoveryJournalPresent{return plan,nil}
    if e.OtherVolveTasks==0 || !e.ProgramFilesRoot || e.ProgramDataResidues==0{
        return plan,nil
    }
    plan.Mode="REVIEW_AUTHENTIC_INSTALLED_0287_RECEIPT_BUT_LIVE_OWNERSHIP_UNPROVEN"
    plan.Reason="Editorial installed receipt authentic; current task/process/file/DNS identity and a distinct uninstall authorization remain unverified."
    plan.Requirements=append([]string(nil),requiredProofs[1:]...)
    // No signed receipt ever grants permission to remove installed protection.
    return plan,nil
}
