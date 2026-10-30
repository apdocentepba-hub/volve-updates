//go:build windows

package main

import (
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "regexp"
    "strings"

    "volve-browser-protection/motorupdate"
)

// This is a real Windows Task Scheduler action switch, extracted from the
// disposable CI task driver. There is deliberately NO CLI or panel caller for
// the resident task: it must only be called by the future privileged upgrade
// transaction AFTER independent SYSTEM rollback is installed and verified.
var motorPilotTask = regexp.MustCompile(`^VOLVE-CI-ManagedMotor-[0-9]{12,20}$`)

func ownedMotorTaskName(name string) bool {
    return name==dnsServiceTask || motorPilotTask.MatchString(name)
}

// switchVerifiedMotorTaskAction refuses to change an unrecognized SYSTEM task,
// refuses an unsigned candidate, and checks the final task XML. It does NOT
// stop/start the actual service or modify DNS, so it is not by itself a live
// motor upgrade.
func switchVerifiedMotorTaskAction(
    ctx context.Context, name, oldExe, oldArgs, candidate, newArgs string, key ed25519.PublicKey,
) error {
    if err:=ctx.Err();err!=nil{return err}
    if !ownedMotorTaskName(name) {return errors.New("tarea motor fuera de lista autorizada")}
    if !filepath.IsAbs(oldExe) || !filepath.IsAbs(candidate) {return errors.New("rutas de motor no absolutas")}
    if name==dnsServiceTask && (oldArgs!="--dns-service" || newArgs!="--dns-service") {
        return errors.New("argumentos del motor productivo no autorizados")
    }
    // Authenticity is always checked using the pinned key before any task
    // mutation; a valid new EXE name alone is never sufficient.
    if _,err:=motorupdate.VerifyStaged(candidate,key);err!=nil{
        return fmt.Errorf("motor candidato no firmado o modificado: %w",err)
    }
    raw,exists,err:=taskQuery(name)
    if err!=nil{return err}
    if !exists{return errors.New("tarea SYSTEM del motor no encontrada")}
    if err:=verifySystemTaskXML(raw,oldExe,oldArgs);err!=nil{
        return fmt.Errorf("tarea original SYSTEM no reconocida: %w",err)
    }
    if err:=ctx.Err();err!=nil{return err}
    // PowerShell single-quote arguments are escaped by the existing psQuote
    // helper. Avoid executing the candidate: only its startup action changes.
    script:="$ErrorActionPreference='Stop';"+
        "$action=New-ScheduledTaskAction -Execute "+psQuote(candidate)
    if newArgs!=""{script+=" -Argument "+psQuote(newArgs)}
    script+=";Set-ScheduledTask -TaskName "+psQuote(name)+" -Action $action -ErrorAction Stop | Out-Null"
    if out,err:=runPS(script);err!=nil{
        return fmt.Errorf("no se pudo conmutar tarea SYSTEM (%s): %w",out,err)
    }
    newXML,exists,err:=taskQuery(name)
    if err!=nil{return err}
    if !exists{return errors.New("tarea desapareció después del cambio")}
    if err:=verifySystemTaskXML(newXML,candidate,newArgs);err!=nil{
        return fmt.Errorf("tarea nueva distinta al motor firmado: %w",err)
    }
    return nil
}

// restoreVerifiedMotorTaskXML reimports ONLY a previously authenticated exact
// task snapshot and checks the restored identity. The independent watchdog
// must call this even if the parent updater is killed; not yet wired to live DNS.
func restoreVerifiedMotorTaskXML(
    ctx context.Context,name,backupFile,expectedSHA,expectedExe,expectedArgs string,
) error {
    if err:=ctx.Err();err!=nil{return err}
    if !ownedMotorTaskName(name){return errors.New("nombre de recuperación no autorizado")}
    if !filepath.IsAbs(backupFile)||!filepath.IsAbs(expectedExe)||len(expectedSHA)!=64{
        return errors.New("parámetros de recuperación inválidos")
    }
    info,err:=os.Lstat(backupFile)
    if err!=nil{return err}
    if !info.Mode().IsRegular() || info.Size()<100 || info.Size()>1<<20{
        return errors.New("respaldo XML ausente o fuera de límite")
    }
    raw,err:=os.ReadFile(backupFile);if err!=nil{return err}
    h:=sha256.Sum256(raw)
    if !strings.EqualFold(hex.EncodeToString(h[:]),expectedSHA){
        return errors.New("respaldo XML no coincide con SHA-256 previo")
    }
    if err:=verifySystemTaskXML(raw,expectedExe,expectedArgs);err!=nil{
        return fmt.Errorf("respaldo SYSTEM no corresponde a la tarea original: %w",err)
    }
    if err:=ctx.Err();err!=nil{return err}
    script:="$ErrorActionPreference='Stop';"+
        "$xml=[IO.File]::ReadAllText("+psQuote(backupFile)+");"+
        "Register-ScheduledTask -TaskName "+psQuote(name)+" -Xml $xml -Force -ErrorAction Stop | Out-Null"
    if out,err:=runPS(script);err!=nil{
        return fmt.Errorf("falló recuperación de tarea SYSTEM: %s: %w",out,err)
    }
    result,exists,err:=taskQuery(name)
    if err!=nil{return err}
    if !exists{return errors.New("tarea no encontrada tras restaurar")}
    if err:=verifySystemTaskXML(result,expectedExe,expectedArgs);err!=nil{
        return fmt.Errorf("tarea restaurada no coincide con respaldo: %w",err)
    }
    return nil
}
