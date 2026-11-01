//go:build windows

package main

// Explicit read-only bridge from the Windows installation to an UNSIGNED
// publisher review packet. It is neither a migration permit nor a switch
// driver; no file, task, DNS adapter, ACL or release channel is modified.
import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "time"

 "volve-browser-protection/motorupdate"
)

type livePublisherReviewProbes struct{
 Preflight func()(string,error)
 RunningMotor func(context.Context,string,string)error
 TaskXML func(context.Context,string)([]byte,error)
 ProtectBackup func(string)error
}

// buildInstalledPublisherReviewReadOnly accepts injected probes ONLY for lab
// tests. Its real CLI caller binds them to SYSTEM/Task Scheduler identity,
// signed-source byte checks and the strict Windows ACL verifier.
// Checks are repeated inside the underlying review builder to detect drift.
func buildInstalledPublisherReviewReadOnly(ctx context.Context,root,candidate,panelVersion string,
 pub ed25519.PublicKey,elevated bool,probes livePublisherReviewProbes,
)(motorupdate.LegacyPublisherReviewPacket,error){
 var empty motorupdate.LegacyPublisherReviewPacket
 if err:=ctx.Err();err!=nil{return empty,err}
 if !elevated{return empty,errors.New("administrator token required for publisher review")}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  !filepath.IsAbs(candidate)||len(pub)!=ed25519.PublicKeySize {
  return empty,errors.New("verified absolute installed root, candidate and editorial public key mandatory")
 }
 if probes.Preflight==nil||probes.RunningMotor==nil||
  probes.TaskXML==nil||probes.ProtectBackup==nil{
  return empty,errors.New("independent native Windows inspection probes unavailable")
 }
 exe:=filepath.Join(root,dnsServiceFile)
 parent:=filepath.Join(root,localRecoveryFolder)
 backup:=filepath.Join(parent,localRecoverySnapshot)
 // A trusted parent is mandatory: a writable parent can redirect the
 // original snapshot between checks even if each file itself is sealed.
 if err:=probes.ProtectBackup(parent);err!=nil{return empty,fmt.Errorf("recovery parent ACL rejected: %w",err)}
 old,err:=motorupdate.VerifyUnversionedLegacyRecovery(backup,probes.ProtectBackup)
 if err!=nil{return empty,fmt.Errorf("sealed legacy original unavailable: %w",err)}
 if old.ExeSHA256==""||old.XMLSHA256==""{return empty,errors.New("sealed legacy hashes unavailable")}
 return motorupdate.BuildLegacyPublisherReviewPacketReadOnly(ctx,exe,backup,candidate,panelVersion,
  pub,probes.ProtectBackup,func()error{
   if err:=ctx.Err();err!=nil{return err}
   if _,err:=probes.Preflight();err!=nil{return fmt.Errorf("live SYSTEM and DNS preflight: %w",err)}
   // Query the *current* SYSTEM scheduled task XML, not a caller-provided
   // expectation or the backed-up XML. Require the very same raw XML SHA.
   observed,err:=probes.TaskXML(ctx,exe)
   if err!=nil{return fmt.Errorf("live task XML not observable: %w",err)}
   if len(observed)==0||len(observed)>1<<20{
    return errors.New("live SYSTEM task XML missing or oversized")
   }
   sha:=sha256.Sum256(observed)
   if hex.EncodeToString(sha[:])!=old.XMLSHA256{
    return errors.New("live SYSTEM task XML differs from protected original")
   }
   if err:=probes.RunningMotor(ctx,exe,old.ExeSHA256);err!=nil{
    return fmt.Errorf("running SYSTEM motor identity/port53 rejected: %w",err)
   }
   return nil
  })
}

// Real native task lookup: the scheduled action and principal are separately
// checked by the existing read-only Task Scheduler verifier. A task that is
// absent (as seen in some older 0.28.6 installations) fails closed.
func readPublisherReviewLiveTaskXML(ctx context.Context,exe string)([]byte,error){
 if err:=ctx.Err();err!=nil{return nil,err}
 xml,exists,err:=taskQuery(dnsServiceTask)
 if err!=nil{return nil,err}
 if !exists{return nil,errors.New("VOLVE-DNS-SERVER-0270 not installed or inaccessible")}
 if err:=verifySystemTaskXML(xml,exe,"--dns-service");err!=nil{return nil,err}
 return xml,nil
}

// This CLI is deliberately NOT attached to the normal update button:
// running expensive privileged checks or UAC during a status check would be
// unsafe and misleading. It emits hashes only to the invoking administrator,
// never uploads/sends the document or writes it to disk.
func runInstalledPublisherReviewCLI(candidate string)error {
 if !isAdmin(){return errors.New("publisher review requires Administrator; no changes were made")}
 rawKey,err:=base64.StdEncoding.Strict().DecodeString(updaterPublicKey)
 if err!=nil||len(rawKey)!=ed25519.PublicKeySize{return errors.New("installed publisher public key invalid")}
 root,err:=installRoot()
 if err!=nil{return fmt.Errorf("installed root not verified: %w",err)}
 ctx,cancel:=context.WithTimeout(context.Background(),55*time.Second)
 defer cancel()
 packet,err:=buildInstalledPublisherReviewReadOnly(ctx,root,candidate,version,
  ed25519.PublicKey(rawKey),true,livePublisherReviewProbes{
   Preflight:preflightMotorUpgradeReadOnly,
   TaskXML:readPublisherReviewLiveTaskXML,
   RunningMotor:verifyResidentRunningMotorReadOnly,
   ProtectBackup:checkSealedLegacyRecoveryACL,
  })
 if err!=nil{return fmt.Errorf("cannot issue unsigned publisher review: %w",err)}
 output,err:=json.MarshalIndent(packet,"","  ")
 if err!=nil{return err}
 // A review packet NEVER contains a private key, user filename or grant.
 _,err=fmt.Fprintln(os.Stdout,string(output))
 return err
}
