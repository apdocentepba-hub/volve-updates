package motorupdate

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"
)

const legacyBackupMaxExe = 80 << 20
const legacyBackupMaxTask = 1 << 20
const legacyBackupExe = "VOLVE_DNS_Legacy_Recovery.exe"
const legacyBackupXML = "VOLVE_DNS_Legacy_Task.xml"
const legacyBackupReceipt = "VOLVE_DNS_Legacy_Recovery.json"

// LegacyRecoveryRecord binds a LOCAL, unversioned fallback to the exact bytes
// and task snapshot observed before a migration. It does NOT claim publisher
// authenticity, a legacy version, a successful update or permission to switch.
// For security, a Windows caller must first validate the live SYSTEM task,
// independent rescue and DNS health, and provide an ACL verifier.
type LegacyRecoveryRecord struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    OriginalTask string `json:"original_task"`
    OriginalArgs string `json:"original_args"`
    OriginalName string `json:"original_name"`
    ExeSHA256 string `json:"exe_sha256"`
    ExeSize int64 `json:"exe_size"`
    XMLSHA256 string `json:"xml_sha256"`
    XMLSize int64 `json:"xml_size"`
    CapturedUTC string `json:"captured_utc"`
}

func legacyDigest(path string,max int64)(string,int64,error){
    info,err:=os.Lstat(path);if err!=nil{return "",0,err}
    if !info.Mode().IsRegular() || info.Size()<1 || info.Size()>max {
        return "",0,errors.New("original/copia no regular o tamaño excesivo")
    }
    f,err:=os.Open(path);if err!=nil{return "",0,err};defer f.Close()
    h:=sha256.New()
    n,err:=io.Copy(h,io.LimitReader(f,max+1));if err!=nil{return "",0,err}
    if n!=info.Size() || n>max{return "",0,errors.New("archivo cambió durante la lectura")}
    return hex.EncodeToString(h.Sum(nil)),n,nil
}

func writeSnapshotFile(path string, data []byte) error {
    f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
    if err!=nil{return err}
    if _,err=f.Write(data);err!=nil{f.Close();return err}
    if err=f.Sync();err!=nil{f.Close();return err}
    return f.Close()
}

// PrepareUnversionedLegacyRecovery is an EXPLICIT backup-only operation.
// The caller must supply an already-validated SYSTEM task XML and a callback
// that enforces trusted administrator/SYSTEM-only ACL on the destination parent
// and staging folder. Nothing runs, no task is changed, and DNS is untouched.
// For the production adapter, require admin and real preflight BEFORE calling.
func PrepareUnversionedLegacyRecovery(
    ctx context.Context, liveExe string, validatedTaskXML []byte,
    dest string, protect func(string)error,
) (LegacyRecoveryRecord,error) {
    return PrepareUnversionedLegacyRecoveryWithSealing(ctx,liveExe,validatedTaskXML,dest,protect,nil)
}

// PrepareUnversionedLegacyRecoveryWithSealing uses an optional OS-specific
// one-way ACL/owner sealer on ONLY the newly-created staging directory and
// files. It runs before the protected, no-overwrite rename into the final
// backup location. Production Windows callers must supply a sealer AND a
// strict verifier; legacy callers remain compatible but their output is not
// sufficient evidence for the independent production watchdog.
func PrepareUnversionedLegacyRecoveryWithSealing(
    ctx context.Context, liveExe string, validatedTaskXML []byte,
    dest string, protect func(string)error, sealNew func(string)error,
) (LegacyRecoveryRecord,error) {
    var empty LegacyRecoveryRecord
    if err:=ctx.Err();err!=nil{return empty,err}
    if protect==nil{return empty,errors.New("no ACL verifier supplied")}
    if !filepath.IsAbs(liveExe)||!filepath.IsAbs(dest)||
       filepath.Base(liveExe)!=legacyServiceName {
        return empty,errors.New("legacy motor or destination not allowlisted")
    }
    if len(validatedTaskXML)<100 || len(validatedTaskXML)>legacyBackupMaxTask {
        return empty,errors.New("SYSTEM task XML not validated/bounded")
    }
    parent:=filepath.Dir(dest)
    if err:=safeInventoryDirectory(parent);err!=nil{return empty,err}
    if err:=protect(parent);err!=nil{return empty,fmt.Errorf("unsafe recovery parent ACL: %w",err)}
    if err:=safeInventoryDirectory(filepath.Dir(liveExe));err!=nil{return empty,err}
    if _,err:=os.Lstat(dest);err==nil{return empty,errors.New("legacy backup already exists; refusing overwrite")
    }else if !errors.Is(err,os.ErrNotExist){return empty,err}
    oldHash,oldSize,err:=legacyDigest(liveExe,legacyBackupMaxExe)
    if err!=nil{return empty,err}
    tmp,err:=os.MkdirTemp(parent,".legacy-recovery-*")
    if err!=nil{return empty,err}
    defer os.RemoveAll(tmp)
    if sealNew!=nil {
        if err:=sealNew(tmp);err!=nil{return empty,fmt.Errorf("could not seal new staging directory: %w",err)}
    }
    if err:=protect(tmp);err!=nil{return empty,fmt.Errorf("unsafe staging ACL: %w",err)}
    copyPath:=filepath.Join(tmp,legacyBackupExe)
    in,err:=os.Open(liveExe);if err!=nil{return empty,err}
    out,err:=os.OpenFile(copyPath,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
    if err!=nil{in.Close();return empty,err}
    copied,copyErr:=io.Copy(out,io.LimitReader(in,legacyBackupMaxExe+1))
    if copyErr==nil{copyErr=out.Sync()}
    closeErr:=out.Close();readCloseErr:=in.Close()
    if copyErr!=nil{return empty,copyErr}
    if closeErr!=nil{return empty,closeErr}
    if readCloseErr!=nil{return empty,readCloseErr}
    if copied!=oldSize{return empty,errors.New("legacy executable changed while copying")}
    copyHash,copySize,err:=legacyDigest(copyPath,legacyBackupMaxExe)
    if err!=nil{return empty,err}
    newHash,newSize,err:=legacyDigest(liveExe,legacyBackupMaxExe)
    if err!=nil{return empty,err}
    if oldHash!=copyHash || oldHash!=newHash || oldSize!=copySize || oldSize!=newSize {
        return empty,errors.New("active legacy executable changed during snapshot; refusing to trust backup")
    }
    if err:=ctx.Err();err!=nil{return empty,err}
    xmlSum:=sha256.Sum256(validatedTaskXML)
    if err:=writeSnapshotFile(filepath.Join(tmp,legacyBackupXML),validatedTaskXML);err!=nil{return empty,err}
    r:=LegacyRecoveryRecord{
        Schema:1,Component:"dns-engine-legacy-recovery",
        OriginalTask:legacySystemTask,OriginalArgs:legacyServiceArg,
        OriginalName:legacyServiceName,ExeSHA256:oldHash,ExeSize:oldSize,
        XMLSHA256:hex.EncodeToString(xmlSum[:]),XMLSize:int64(len(validatedTaskXML)),
        CapturedUTC:time.Now().UTC().Format(time.RFC3339Nano),
    }
    raw,err:=json.Marshal(r);if err!=nil{return empty,err}
    if err:=writeSnapshotFile(filepath.Join(tmp,legacyBackupReceipt),append(raw,'\n'));err!=nil{return empty,err}
    if sealNew!=nil {
        // Never seal or replace the installed motor or an existing backup.
        // All three files were created with O_EXCL in this private staging
        // directory; refuse publication unless every descriptor is trusted.
        for _,name:=range []string{legacyBackupExe,legacyBackupXML,legacyBackupReceipt}{
            if err:=sealNew(filepath.Join(tmp,name));err!=nil{
                return empty,fmt.Errorf("could not seal new recovery artifact %s: %w",name,err)
            }
        }
        if err:=protect(tmp);err!=nil{
            return empty,fmt.Errorf("new snapshot ownership/DACL not trusted: %w",err)
        }
    }
    if err:=ctx.Err();err!=nil{return empty,err}
    if _,err:=os.Lstat(dest);err==nil{return empty,errors.New("another backup exists; refusing overwrite")
    }else if !errors.Is(err,os.ErrNotExist){return empty,err}
    if err:=os.Rename(tmp,dest);err!=nil{return empty,err}
    if err:=protect(dest);err!=nil{return empty,fmt.Errorf("backup saved but destination ACL verification failed: %w",err)}
    got,err:=VerifyUnversionedLegacyRecovery(dest,protect)
    if err!=nil{return empty,fmt.Errorf("backup saved but not verifiable: %w",err)}
    if got.ExeSHA256!=oldHash || got.XMLSHA256!=r.XMLSHA256{return empty,errors.New("saved recovery differs from source")}
    return r,nil
}

// VerifyUnversionedLegacyRecovery independently validates a durable,
// administrator-protected backup. The signed *new* candidate must be verified
// separately. A locally hashed old engine is a rollback source, not a
// publisher-signed release or trusted version number.
func VerifyUnversionedLegacyRecovery(dir string, protect func(string)error)(LegacyRecoveryRecord,error){
    var r LegacyRecoveryRecord
    if protect==nil{return r,errors.New("missing ACL verification")}
    if err:=safeInventoryDirectory(dir);err!=nil{return r,err}
    if err:=protect(dir);err!=nil{return r,err}
    receipt:=filepath.Join(dir,legacyBackupReceipt)
    info,err:=os.Lstat(receipt);if err!=nil{return r,err}
    if !info.Mode().IsRegular() || info.Size()<2 || info.Size()>4096{return r,errors.New("backup receipt not regular or bounded")}
    data,err:=os.ReadFile(receipt);if err!=nil{return r,err}
    dec:=json.NewDecoder(bytes.NewReader(data));dec.DisallowUnknownFields()
    if err:=dec.Decode(&r);err!=nil{return LegacyRecoveryRecord{},err}
    var extra any
    if err:=dec.Decode(&extra);err!=io.EOF{return LegacyRecoveryRecord{},errors.New("trailing backup receipt data")}
    if r.Schema!=1 || r.Component!="dns-engine-legacy-recovery" || r.OriginalTask!=legacySystemTask ||
       r.OriginalArgs!=legacyServiceArg || r.OriginalName!=legacyServiceName ||
       !hexRe.MatchString(r.ExeSHA256) || !hexRe.MatchString(r.XMLSHA256) ||
       r.ExeSize<=0 || r.ExeSize>legacyBackupMaxExe || r.XMLSize<100 || r.XMLSize>legacyBackupMaxTask {
        return LegacyRecoveryRecord{},errors.New("unrecognized backup identity or record")
    }
    if _,err:=time.Parse(time.RFC3339Nano,r.CapturedUTC);err!=nil{return LegacyRecoveryRecord{},err}
    exeHash,exeSize,err:=legacyDigest(filepath.Join(dir,legacyBackupExe),legacyBackupMaxExe)
    if err!=nil{return LegacyRecoveryRecord{},err}
    xmlHash,xmlSize,err:=legacyDigest(filepath.Join(dir,legacyBackupXML),legacyBackupMaxTask)
    if err!=nil{return LegacyRecoveryRecord{},err}
    if r.ExeSHA256!=exeHash || r.ExeSize!=exeSize || r.XMLSHA256!=xmlHash || r.XMLSize!=xmlSize {
        return LegacyRecoveryRecord{},errors.New("legacy engine or task XML backup changed since capture")
    }
    return r,nil
}
