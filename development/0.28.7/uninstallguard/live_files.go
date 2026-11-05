package uninstallguard

// Read-only comparison between the authenticated 0.28.7 receipt and actual
// installed file bytes. This does not grant ownership of processes, SYSTEM
// tasks, browser policies, DNS settings, or permission to uninstall.

import (
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "runtime"
)

type InstalledFilesAudit struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    Release string `json:"release"`
    InstallationID string `json:"installation_id"`
    CheckedFiles int `json:"checked_files"`
    MatchedFiles int `json:"matched_files"`
    Status string `json:"status"`
    TaskOwnershipVerified bool `json:"task_ownership_verified"`
    ProcessOwnershipVerified bool `json:"process_ownership_verified"`
    CanUninstall bool `json:"can_uninstall"`
    CanStopMotor bool `json:"can_stop_motor"`
    CanChangeDNS bool `json:"can_change_dns"`
    CanDeleteTasks bool `json:"can_delete_tasks"`
    CanDeleteFiles bool `json:"can_delete_files"`
}

// AuditSignedInstalledFilesReadOnly is a public Windows-only diagnostic. Even
// eight matching hashes are only partial evidence; a future privileged
// transaction must recheck every file and live owner under its protected lock.
func AuditSignedInstalledFilesReadOnly(ctx context.Context, raw, signature []byte, publisher ed25519.PublicKey) (InstalledFilesAudit,error) {
    if runtime.GOOS!="windows" {return InstalledFilesAudit{},errors.New("native Windows file ownership review required")}
    receipt,err:=VerifySignedInstalledReceipt(raw,signature,publisher)
    if err!=nil{return InstalledFilesAudit{},err}
    return auditReceiptFilesAtRoots(ctx,receipt,receipt.InstallRoot,receipt.DataRoot)
}

// auditReceiptFilesAtRoots accepts override roots ONLY as a test helper.
// Never expose a caller-selected root to a production CLI: actual roots must
// come from the signed receipt itself, as in AuditSignedInstalledFilesReadOnly.
func auditReceiptFilesAtRoots(ctx context.Context,receipt InstalledReceipt,installRoot,dataRoot string)(InstalledFilesAudit,error){
    var rejected InstalledFilesAudit
    if ctx==nil {return rejected,errors.New("non-nil read-only audit context required")}
    if err:=ctx.Err();err!=nil{return rejected,err}
    if err:=validateReceipt(receipt);err!=nil{return rejected,err}
    if !filepath.IsAbs(installRoot)||!filepath.IsAbs(dataRoot)||
        filepath.Clean(installRoot)!=installRoot||filepath.Clean(dataRoot)!=dataRoot||
        installRoot==dataRoot {return rejected,errors.New("uncanonical or duplicate audit roots")}
    // Check every path component, including the parents. Junction/symlink
    // walks could redirect reads outside a signed installation.
    for _,root:=range []string{installRoot,dataRoot}{
        if err:=rejectLinkedPath(root,true);err!=nil{return rejected,fmt.Errorf("linked or missing installation root refused: %w",err)}
    }
    a:=InstalledFilesAudit{
        Schema:1,Component:"VOLVE-0287-SIGNED-FILE-OWNERSHIP-READONLY",
        Release:"0.28.7",InstallationID:receipt.InstallationID,
        CheckedFiles:len(receipt.Files),
        Status:"READ_ONLY_FILE_HASHES_MATCH_TASKS_AND_PROCESS_UNVERIFIED",
    }
    for _,file:=range receipt.Files {
        if err:=ctx.Err();err!=nil{return rejected,err}
        root:=installRoot
        if file.Root=="data"{root=dataRoot}
        // The basename comes exclusively from the canonical signed
        // eight-component allowlist, NEVER from a user-supplied subpath.
        path:=filepath.Join(root,file.File)
        if filepath.Base(path)!=file.File{return rejected,errors.New("unsafe installed component path")}
        if err:=rejectLinkedPath(path,false);err!=nil{return rejected,fmt.Errorf("%s path refused: %w",file.ID,err)}
        hash,size,err:=hashStableRegularFile(ctx,path)
        if err!=nil{return rejected,fmt.Errorf("%s file audit refused: %w",file.ID,err)}
        expected,err:=hex.DecodeString(file.SHA256)
        if err!=nil||size!=file.Size||subtle.ConstantTimeCompare(hash[:],expected)!=1{
            return rejected,fmt.Errorf("%s installed bytes differ from authenticated receipt",file.ID)
        }
        a.MatchedFiles++
    }
    return a,nil
}

func rejectLinkedPath(path string,expectDirectory bool)error{
    clean:=filepath.Clean(path)
    if clean!=path||!filepath.IsAbs(path){return errors.New("noncanonical absolute path")}
    for p:=clean;;{
        info,err:=os.Lstat(p)
        if err!=nil{return err}
        if info.Mode()&os.ModeSymlink!=0{return fmt.Errorf("reparse/symlink detected: %s",p)}
        if p!=clean && !info.IsDir(){return errors.New("unexpected nondirectory ancestor")}
        if p==clean {
            if expectDirectory&&!info.IsDir(){return errors.New("root is not directory")}
            if !expectDirectory&&!info.Mode().IsRegular(){return errors.New("component is not regular file")}
        }
        parent:=filepath.Dir(p)
        if parent==p{break}
        p=parent
    }
    return nil
}

func hashStableRegularFile(ctx context.Context,path string)([sha256.Size]byte,int64,error){
    var zero [sha256.Size]byte
    before,err:=os.Lstat(path)
    if err!=nil{return zero,0,err}
    if !before.Mode().IsRegular() || before.Size()<=0 || before.Size()>1<<30{
        return zero,0,errors.New("component not a bounded regular file")
    }
    f,err:=os.Open(path)
    if err!=nil{return zero,0,err}
    defer f.Close()
    opened,err:=f.Stat()
    if err!=nil||!os.SameFile(before,opened){return zero,0,errors.New("component changed before read")}
    digest:=sha256.New()
    buf:=make([]byte,1<<20)
    count:=int64(0)
    for {
        if err:=ctx.Err();err!=nil{return zero,0,err}
        n,readErr:=f.Read(buf)
        if n>0 {
            count+=int64(n)
            if count>1<<30{return zero,0,errors.New("component exceeds size bound")}
            if _,err:=digest.Write(buf[:n]);err!=nil{return zero,0,err}
        }
        if readErr==io.EOF{break}
        if readErr!=nil{return zero,0,readErr}
    }
    after,err:=f.Stat()
    if err!=nil||!os.SameFile(before,after)||count!=before.Size()||
        after.Size()!=before.Size()||!after.ModTime().Equal(before.ModTime()){
        return zero,0,errors.New("component modified during hash")
    }
    current,err:=os.Lstat(path)
    if err!=nil||!os.SameFile(before,current)||current.Mode()&os.ModeSymlink!=0{
        return zero,0,errors.New("component replaced during inspection")
    }
    copy(zero[:],digest.Sum(nil))
    return zero,count,nil
}
