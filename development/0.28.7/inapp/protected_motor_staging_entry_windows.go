//go:build windows

package main

// Explicitly invoked administrator-only PREPARATION. It never changes any
// VOLVE task, service, DNS adapter, browser policy, release channel or engine
// receipt. A signed bundle staged here is NOT an installed motor. Production
// task switching remains mechanically disabled pending independently signed
// migration authorization and durable out-of-process SYSTEM watchdog.
import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "volve-browser-protection/motorupdate"
 "volve-browser-protection/releaseupdate"
)

func rejectRedirectedInstalledParents(installed string)error{
 if installed==""||!filepath.IsAbs(installed)||filepath.Clean(installed)!=installed||
   strings.HasPrefix(installed,`\\`)||strings.ContainsRune(installed,0){
  return errors.New("installed root must be a canonical local absolute Windows directory")
 }
 vol:=filepath.VolumeName(installed)
 if vol==""{return errors.New("installed engine root lacks a Windows volume")}
 start:=vol+string(os.PathSeparator)
 rest:=strings.TrimPrefix(installed,start)
 if rest==installed||rest==""{return errors.New("invalid or volume-root installation path")}
 current:=start
 for _,part:=range strings.Split(rest,string(os.PathSeparator)){
  if part==""{continue}
  current=filepath.Join(current,part)
  st,err:=os.Lstat(current);if err!=nil{return err}
  if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{
   return fmt.Errorf("installed root ancestor is redirected or not directory: %s",part)
  }
 }
 return nil
}

// An existing inventory is NEVER repaired or overwritten. A new one is
// created ONLY after the candidate signature has passed and the native
// process holds the protected Windows SYSTEM/Admin transition mutex.
func ensureNewOrVerifiedProtectedEngineRoot(installed,inventory string,
 acl motorupdate.ProtectedTargetFileOps,
)error{
 if err:=rejectRedirectedInstalledParents(installed);err!=nil{return err}
 if inventory!=filepath.Join(installed,"installed-engines"){
  return errors.New("refusing noncanonical protected inventory path")
 }
 if st,err:=os.Lstat(inventory);err==nil{
  if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{
   return errors.New("existing protected motor inventory is redirected or not a directory")
  }
  // A weak existing ACL must cause a STOP, never an ACL repair.
  return acl.VerifyProtected(inventory)
 }else if !errors.Is(err,os.ErrNotExist){return err}
 if err:=os.Mkdir(inventory,0700);err!=nil{return err}
 // Never silently remove a partial root on error; retain it for an
 // administrator's inspection, without any installed engine receipt.
 if err:=sealNewProtectedRecoveryNode(inventory);err!=nil{
  return fmt.Errorf("new inventory root NTFS DACL could not be sealed: %w",err)
 }
 return acl.VerifyProtected(inventory)
}

// The only native mutation in this routine is create-only staging under the
// sealed installed-engines tree. Signature is checked once BEFORE any writes
// and again by PrepareProtectedVersionedMotor before/after each bundle copy.
func stageSignedMotorWithProtectedWindowsLease(
 ctx context.Context,installed,candidate string,publisher ed25519.PublicKey,
)(string,error){
 if !isAdmin(){return "",errors.New("elevated Administrator required")}
 if err:=ctx.Err();err!=nil{return "",err}
 if err:=rejectRedirectedInstalledParents(installed);err!=nil{return "",err}
 if !filepath.IsAbs(candidate)||filepath.Clean(candidate)!=candidate{
  return "",errors.New("staged motor must have a canonical absolute path")
 }
 manifest,err:=motorupdate.VerifyStaged(candidate,publisher)
 if err!=nil{return "",fmt.Errorf("untrusted publisher motor candidate: %w",err)}
 if manifest.Component!="dns-engine"{return "",errors.New("candidate is not an independently signed DNS motor")}
 eligible,err:=releaseupdate.CompareVersions(version,manifest.MinPanelVersion)
 if err!=nil||eligible<0{
  return "",errors.New("installed Centro does not meet signed motor's minimum version")
 }
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return "",fmt.Errorf("SYSTEM/Admin global motor transition lock unavailable: %w",err)}
 if release==nil{return "",errors.New("native Windows motor transition lock returned no finalizer")}
 defer release()
 inventory,ops,err:=nativeProtectedMotorTargetOpsForRoot(installed)
 if err!=nil{return "",err}
 if err:=ensureNewOrVerifiedProtectedEngineRoot(installed,inventory,ops);err!=nil{
  return "",fmt.Errorf("protected installed-engines root refused: %w",err)
 }
 path,err:=motorupdate.PrepareProtectedVersionedMotor(ctx,candidate,inventory,publisher,ops)
 if err!=nil{return "",err}
 return path,nil
}

// This admin-only command is NOT connected to the normal "Actualizar VOLVÉ"
// button. No privilege prompt is issued; the user must explicitly invoke it
// in a suitable test environment. It only stages publisher-signed bytes.
func runProtectedMotorStageCLI(candidate string)error{
 key,err:=base64.StdEncoding.Strict().DecodeString(updaterPublicKey)
 if err!=nil||len(key)!=ed25519.PublicKeySize{
  return errors.New("publisher public key unavailable; nothing prepared")
 }
 root,err:=installRoot()
 if err!=nil{return fmt.Errorf("installed VOLVÉ directory unavailable: %w",err)}
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Minute)
 defer cancel()
 prepared,err:=stageSignedMotorWithProtectedWindowsLease(ctx,root,candidate,ed25519.PublicKey(key))
 if err!=nil{return err}
 _,err=fmt.Fprintf(os.Stdout,
  `MOTOR DNS FIRMADO: COPIA PROTEGIDA PREPARADA: %s
NO INSTALADO. NO ACTIVADO. NO SE MODIFICARON DNS NI TAREAS SYSTEM.
`,prepared)
 return err
}
