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

func checkLegacyRecoveryACL(dir string) error {
    if !filepath.IsAbs(dir){return errors.New("rollback path must be absolute")}
    info,err:=os.Lstat(dir);if err!=nil{return err}
    if !info.IsDir() || info.Mode()&os.ModeSymlink!=0 {
        return errors.New("rollback directory cannot be a junction or file")
    }
    script:=`$ErrorActionPreference='Stop';$p=`+psQuote(dir)+`;`+
      `$a=Get-Acl -LiteralPath $p -ErrorAction Stop;`+
      `$allowed=@('S-1-5-18','S-1-5-32-544');`+
      `foreach($entry in $a.Access){`+
      ` if($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){continue};`+
      ` $sid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;`+
      ` if($sid -notin $allowed){throw ('Unsafe rollback ACL: '+$sid)}`+
      `};`+
      `$granted=@($a.Access|Where-Object{$_.AccessControlType -eq 'Allow'}|`+
      `ForEach-Object{$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value});`+
      `foreach($sid in $allowed){if($sid -notin $granted){throw ('Missing rollback ACL: '+$sid)}};`+
      `Write-Output 'ROLLBACK_ACL_OK'`
    out,err:=runPS(script)
    if err!=nil{return fmt.Errorf("rollback ACL not trusted: %w",err)}
    if !hasStandaloneRollbackToken(out,"ROLLBACK_ACL_OK"){return fmt.Errorf("ambiguous ACL verification: %q",out)}
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
    // Never rewrite ACLs on an existing folder. Reject it instead.
    if newFolder {
        script:=`$ErrorActionPreference='Stop';$p=`+psQuote(parent)+`;`+
          `& icacls.exe $p '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null;`+
          `if($LASTEXITCODE -ne 0){throw 'Cannot protect legacy rollback directory'};`+
          `Write-Output 'ROLLBACK_ACL_CREATED'`
        out,e:=runPS(script)
        if e!=nil || !hasStandaloneRollbackToken(out,"ROLLBACK_ACL_CREATED"){
            return "",fmt.Errorf("failed protecting rollback folder: %v, output %q",e,out)
        }
    }
    if err:=checkLegacyRecoveryACL(parent);err!=nil{return "",err}
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
    record,err:=motorupdate.PrepareUnversionedLegacyRecovery(ctx,original,task,target,checkLegacyRecoveryACL)
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
    target:=filepath.Join(root,localRecoveryFolder,localRecoverySnapshot)
    r,err:=motorupdate.VerifyUnversionedLegacyRecovery(target,checkLegacyRecoveryACL)
    if err!=nil{return err}
    fmt.Printf("VOLVÉ: RESPALDO LOCAL INTACTO\nSHA-256: %s\nTarea: %s\n"+
      "NO se atribuye una versión antigua ni autoriza cambiar tareas.\n",r.ExeSHA256,r.OriginalTask)
    return nil
}
