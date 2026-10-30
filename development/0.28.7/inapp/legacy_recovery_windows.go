//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"

    "volve-browser-protection/motorupdate"
)

const localRecoveryFolder="legacy-engine-recovery"
const localRecoverySnapshot="original-before-upgrade"

// checkLegacyRecoveryACL accepts ONLY Administrators/SYSTEM on the rollback
// directory. An administrator-owned backup isn't a publisher attestation.
// Its purpose is to remain a durable source of bytes for an independent
// recovery transaction. No task or DNS state is changed.
// Native Windows PowerShell may emit a CLIXML progress prelude while first
// loading modules. Accept only an entire standalone success-token line,
// never a substring embedded inside an error or diagnostic message.
func hasStandaloneRollbackToken(output, token string) bool {
    lines:=strings.Split(strings.ReplaceAll(output,"\r","\n"),"\n")
    for _,line:=range lines {
        if strings.TrimSpace(line)==token {return true}
    }
    return false
}

// checkLegacyRecoveryACL inspects the recovery directory AND each immediate
// file/subdirectory. A directory-only DACL check is insufficient: a standard
// account may gain write access to a recovery executable, XML or receipt via
// an explicit file ACE without changing the containing directory's DACL.
//
// This verifier is read-only. It does not repair permissions or grant access.
// Recovery snapshot integrity hashes are checked separately by motorupdate.
func checkLegacyRecoveryACL(dir string) error {
    if !filepath.IsAbs(dir) { return errors.New("rollback path must be absolute") }
    info,err:=os.Lstat(dir)
    if err!=nil { return err }
    if !info.IsDir() || info.Mode()&os.ModeSymlink!=0 {
        return errors.New("rollback directory cannot be a junction or file")
    }
    entries,err:=os.ReadDir(dir)
    if err!=nil { return err }
    // Recovery has exactly three data files; the parent has one snapshot
    // directory. Fail closed on surprising extra entries instead of accepting
    // an unlimited untrusted directory enumeration.
    if len(entries)>8 { return errors.New("unexpected number of rollback entries") }
    paths:=[]string{dir}
    for _,entry:=range entries {
        path:=filepath.Join(dir,entry.Name())
        fi,statErr:=os.Lstat(path)
        if statErr!=nil { return statErr }
        if fi.Mode()&os.ModeSymlink!=0 || (!fi.IsDir() && !fi.Mode().IsRegular()) {
            return errors.New("rollback entry cannot be a link or special file")
        }
        paths=append(paths,path)
    }
    quoted:=make([]string,0,len(paths))
    for _,path:=range paths { quoted=append(quoted,psQuote(path)) }
    script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
      `$paths=@(`+strings.Join(quoted,",")+`);`+
      `$allowed=@('S-1-5-18','S-1-5-32-544');`+
      `foreach($p in $paths){`+
      ` $attr=[IO.File]::GetAttributes($p);`+
      ` if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Unsafe rollback reparse point: '+$p)};`+
      ` if([IO.Directory]::Exists($p)){$a=[IO.Directory]::GetAccessControl($p)}`+
      ` else{$a=[IO.File]::GetAccessControl($p)};`+
      ` if($p -eq $paths[0] -and [IO.Path]::GetFileName($p) -eq 'legacy-engine-recovery' -and -not $a.AreAccessRulesProtected){throw 'Recovery parent DACL must be protected'};`+
      ` foreach($ace in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){`+
      `  if($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){continue};`+
      `  if($ace.IdentityReference.Value -notin $allowed){throw ('Unsafe rollback ACL: '+$ace.IdentityReference.Value+' on '+$p)}`+
      ` };`+
      ` $granted=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|`+
      `  Where-Object{$_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow}|`+
      `  ForEach-Object{$_.IdentityReference.Value});`+
      ` foreach($sid in $allowed){if($sid -notin $granted){throw ('Missing rollback ACL: '+$sid+' on '+$p)}};`+
      `};Write-Output 'ROLLBACK_ACL_OK'`
    out,err:=runPS(script)
    if err!=nil { return fmt.Errorf("rollback ACL not trusted: %w",err) }
    if !hasStandaloneRollbackToken(out,"ROLLBACK_ACL_OK") {
        return fmt.Errorf("ambiguous ACL verification: %q",out)
    }
    return nil
}

func ensureSecureLegacyRecoveryParent(root string)(string,error){
    if !filepath.IsAbs(root){return "",errors.New("install root is not absolute")}
    info,err:=os.Lstat(root)
    if err!=nil{return "",err}
    if !info.IsDir() || info.Mode()&os.ModeSymlink!=0{return "",errors.New("install root is redirected")}
    parent:=filepath.Join(root,localRecoveryFolder)
    newFolder:=false
    if info,err:=os.Lstat(parent);err==nil{
        if !info.IsDir() || info.Mode()&os.ModeSymlink!=0{
            return "",errors.New("existing rollback folder is redirected")
        }
    }else if errors.Is(err,os.ErrNotExist){
        if err:=os.Mkdir(parent,0700);err!=nil{return "",err}
        newFolder=true
    }else{return "",err}
    // Never rewrite ACLs on an existing folder. A newly-created folder is
    // explicitly sealed with an Administrators owner and protected DACL.
    if newFolder {
        if err:=sealNewLegacyRecoveryNode(parent);err!=nil{
            return "",fmt.Errorf("failed sealing new rollback parent: %w",err)
        }
    }
    if err:=checkSealedLegacyRecoveryACL(parent);err!=nil{return "",err}
    return parent,nil
}

// prepareInstalledLegacyRecovery is a separate EXPLICIT privileged operation.
// Its preflight verifies the installed real SYSTEM motor, independent rescue
// task/scripts/journal and DNS IPv4+IPv6. The exact original Task Scheduler
// XML is fetched and verified AGAIN immediately before the snapshot.
// The migration cannot proceed automatically merely because this returns OK.
func prepareInstalledLegacyRecovery(ctx context.Context)(motorupdate.LegacyRecoveryRecord,error){
    var empty motorupdate.LegacyRecoveryRecord
    if !isAdmin(){return empty,errors.New("rollback preparation requires administrator")}
    root,err:=installRoot();if err!=nil{return empty,err}
    if err:=ctx.Err();err!=nil{return empty,err}
    if _,err:=preflightMotorUpgradeReadOnly();err!=nil{return empty,fmt.Errorf("rescue/DNS preflight failed: %w",err)}
    original:=filepath.Join(root,dnsServiceFile)
    task,exists,err:=taskQuery(dnsServiceTask)
    if err!=nil{return empty,err}
    if !exists{return empty,errors.New("original DNS SYSTEM task not found")}
    if err:=verifySystemTaskXML(task,original,"--dns-service");err!=nil{
        return empty,fmt.Errorf("original SYSTEM task identity mismatch: %w",err)
    }
    parent,err:=ensureSecureLegacyRecoveryParent(root)
    if err!=nil{return empty,err}
    target:=filepath.Join(parent,localRecoverySnapshot)
    record,err:=motorupdate.PrepareUnversionedLegacyRecoveryWithSealing(
        ctx,original,task,target,checkSealedLegacyRecoveryACL,sealNewLegacyRecoveryNode)
    if err!=nil{return empty,err}
    // Do not misreport as ready for a production switch if the running DNS
    // stopped responding or the rescue changed during snapshot.
    if _,err:=preflightMotorUpgradeReadOnly();err!=nil{
        return empty,fmt.Errorf("rollback snapshot saved but post-snapshot health failed: %w",err)
    }
    return record,nil
}

func printLegacyRecoveryPreparation() error {
    ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
    defer cancel()
    result,err:=prepareInstalledLegacyRecovery(ctx)
    if err!=nil{return err}
    fmt.Printf("VOLVÉ: RESGUARDO LOCAL DEL MOTOR ANTERIOR\nSHA-256: %s\n"+
      "Archivo y tarea SYSTEM respaldados y verificados. Versión heredada NO certificada. "+
      "No se cambió el motor DNS, sus tareas ni la red. Reemplazo productivo sigue BLOQUEADO.\n",
      result.ExeSHA256)
    return nil
}

func verifyInstalledLegacyRecovery() error {
    if !isAdmin(){return errors.New("backup verification requires administrator")}
    root,err:=installRoot();if err!=nil{return err}
    parent:=filepath.Join(root,localRecoveryFolder)
    if err:=checkSealedLegacyRecoveryACL(parent);err!=nil{
        return fmt.Errorf("recovery parent directory insecure: %w",err)
    }
    target:=filepath.Join(parent,localRecoverySnapshot)
    r,err:=motorupdate.VerifyUnversionedLegacyRecovery(target,checkSealedLegacyRecoveryACL)
    if err!=nil{return err}
    fmt.Printf("VOLVÉ: RESPALDO LOCAL INTACTO\nSHA-256: %s\nTarea: %s\n"+
      "NO se atribuye una versión antigua ni autoriza cambiar tareas.\n",r.ExeSHA256,r.OriginalTask)
    return nil
}
