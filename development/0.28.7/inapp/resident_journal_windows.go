//go:build windows

package main

// Windows adapter for the already-tested, create-only resident recovery
// journal. This never starts/stops DNS or registers a production SYSTEM task.
import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"

    "volve-browser-protection/motorupdate"
)

const localRecoveryJournal="motor-recovery-transaction"

func isNewResidentJournalNode(path string) bool {
    if !filepath.IsAbs(path) {return false}
    name:=filepath.Base(path)
    parent:=filepath.Dir(path)
    if name==localRecoveryJournal {
        return filepath.Base(parent)==localRecoveryFolder
    }
    if name==motorupdate.ResidentIntentFile || name==motorupdate.ResidentResultFile {
        return filepath.Base(parent)==localRecoveryJournal &&
            filepath.Base(filepath.Dir(parent))==localRecoveryFolder
    }
    return false
}

// The caller must have exclusively created this path (Mkdir or O_EXCL).
// No existing journals are repaired and the original motor is untouched.
func sealNewResidentJournalNode(path string) error {
    if !isNewResidentJournalNode(path) {
        return errors.New("refusing to seal an unrelated or already published recovery path")
    }
    return sealNewProtectedRecoveryNode(path)
}

// Both parent and journal subtree must be owned by SYSTEM/Administrators.
// For file callbacks, validate the entire journal directory and its content.
// Never silently "fix" weak permissions on an existing folder.
func checkSealedResidentJournalACL(path string) error {
    if !filepath.IsAbs(path) {return errors.New("journal ACL path must be absolute")}
    name:=filepath.Base(path)
    dir:=path
    if name==motorupdate.ResidentIntentFile || name==motorupdate.ResidentResultFile {
        dir=filepath.Dir(path)
    } else if name!=localRecoveryJournal {
        return errors.New("journal path not allowlisted")
    }
    if filepath.Base(dir)!=localRecoveryJournal ||
        filepath.Base(filepath.Dir(dir))!=localRecoveryFolder {
        return errors.New("journal directory outside expected recovery tree")
    }
    if err:=checkSealedLegacyRecoveryACL(filepath.Dir(dir));err!=nil {
        return fmt.Errorf("recovery parent not protected: %w",err)
    }
    if err:=checkSealedLegacyRecoveryACL(dir);err!=nil {
        return fmt.Errorf("recovery journal not protected: %w",err)
    }
    return nil
}

// ensureSecureResidentRecoveryJournalDir accepts a new empty directory or an
// existing trusted one, but never resets ownership, overwrites or clears data.
// The full installer root is supplied explicitly; no reliance on CWD or
// user-writable environmental variables.
func ensureSecureResidentRecoveryJournalDir(root string)(string,error) {
    if !isAdmin(){return "",errors.New("resident journal setup requires administrator")}
    parent,err:=ensureSecureLegacyRecoveryParent(root)
    if err!=nil{return "",err}
    dir:=filepath.Join(parent,localRecoveryJournal)
    if stat,err:=os.Lstat(dir);err==nil {
        if !stat.IsDir() || stat.Mode()&os.ModeSymlink!=0 {
            return "",errors.New("existing resident journal directory is redirected")
        }
    }else if errors.Is(err,os.ErrNotExist) {
        if err:=os.Mkdir(dir,0700);err!=nil{return "",err}
        if err:=sealNewResidentJournalNode(dir);err!=nil{
            return "",fmt.Errorf("could not seal freshly created recovery journal: %w",err)
        }
    }else{return "",err}
    if err:=checkSealedResidentJournalACL(dir);err!=nil{return "",err}
    return dir,nil
}

// armPreparedResidentJournal only arms metadata; a future SignedLegacySwitchDriver
// still MUST verify a real publisher permit and autonomous watchdog readiness
// before changing any task. Keeping this uncalled by the production panel is
// deliberate until step-2 integration and real reboot tests pass.
func armPreparedResidentJournal(ctx context.Context,root string,
 intent motorupdate.ResidentRecoveryIntent)(motorupdate.ResidentRecoveryIntent,error){
    var empty motorupdate.ResidentRecoveryIntent
    if err:=ctx.Err();err!=nil{return empty,err}
    if !isAdmin(){return empty,errors.New("arming a resident recovery journal requires administrator")}
    if !filepath.IsAbs(root){return empty,errors.New("install root must be absolute")}
    // Never arm a recovery journal for fabricated legacy bytes. The fallback
    // must already be present, immutable and independently hash-verified.
    // The signed permit, live task identity and watchdog still belong to the
    // future transactional driver and are NOT inferred from these hashes.
    backupDir:=filepath.Join(root,localRecoveryFolder,localRecoverySnapshot)
    original,err:=motorupdate.VerifyUnversionedLegacyRecovery(
        backupDir,checkSealedLegacyRecoveryACL)
    if err!=nil{return empty,fmt.Errorf("protected original DNS recovery missing: %w",err)}
    if intent.LegacySHA256!=original.ExeSHA256 ||
        intent.TaskXMLSHA256!=original.XMLSHA256 {
        return empty,errors.New("journal does not identify the sealed original motor and SYSTEM XML")
    }
    dir,err:=ensureSecureResidentRecoveryJournalDir(root)
    if err!=nil{return empty,err}
    // Re-read the protected fallback immediately before recording an intent.
    again,err:=motorupdate.VerifyUnversionedLegacyRecovery(
        backupDir,checkSealedLegacyRecoveryACL)
    if err!=nil || again!=original {
        return empty,errors.New("protected recovery changed while preparing journal")
    }
    return motorupdate.ArmResidentRecoveryIntent(ctx,dir,intent,
        sealNewResidentJournalNode,checkSealedResidentJournalACL)
}
