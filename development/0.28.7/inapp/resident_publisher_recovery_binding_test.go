package motorupdate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

type signedRecoveryFixture struct{
 root,journal,backup string
 pem LegacyMigrationPermit
 permit,sig []byte
 pub ed25519.PublicKey
 priv ed25519.PrivateKey
}
func makeSignedRecoveryFixture(t *testing.T,expired bool)signedRecoveryFixture{
 t.Helper()
 root:=t.TempDir()
 parent:=filepath.Join(root,"legacy-engine-recovery")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 live:=filepath.Join(root,legacyServiceName)
 if err:=os.WriteFile(live,[]byte("MZ_VOLVE_0286_SYNTHETIC_UNVERSIONED_MOTOR"),0600);err!=nil{t.Fatal(err)}
 xml:=[]byte(strings.Repeat("<Task><Principal>SYSTEM</Principal><Command>VOLVE_DNS_Server_0270.exe</Command></Task>",2))
 backup:=filepath.Join(parent,"original-before-upgrade")
 readonlyProtect:=func(string)error{return nil} // fixture only; production demands real SYSTEM/Admin ACL
 record,err:=PrepareUnversionedLegacyRecovery(context.Background(),live,xml,backup,readonlyProtect)
 if err!=nil{t.Fatal(err)}
 journal:=filepath.Join(parent,"motor-recovery-transaction")
 if err:=os.Mkdir(journal,0700);err!=nil{t.Fatal(err)}
 newSHA:=sha256.Sum256([]byte("MZ_V0_28_7_TARGET_SIGNED_SYNTHETIC"))
 target:=hex.EncodeToString(newSHA[:])
 _,err=ArmResidentRecoveryIntent(context.Background(),journal,ResidentRecoveryIntent{
  Schema:1,Component:"dns-engine-recovery-intent",Task:legacySystemTask,
  LegacySHA256:record.ExeSHA256,TaskXMLSHA256:record.XMLSHA256,
  TargetSHA256:target,TargetVersion:"0.28.7",
 },readonlyProtect,readonlyProtect)
 if err!=nil{t.Fatal(err)}
 issued:=time.Now().UTC().Add(-90*time.Minute)
 expires:=time.Now().UTC().Add(90*time.Minute)
 if expired{
  issued=time.Now().UTC().Add(-72*time.Hour)
  expires=time.Now().UTC().Add(-48*time.Hour)
 }
 pem:=LegacyMigrationPermit{
  Schema:1,Component:"dns-engine-legacy-migration",
  FromTask:legacySystemTask,FromArgs:legacyServiceArg,FromExecutable:legacyServiceName,
  FromSHA256:record.ExeSHA256,FromSize:record.ExeSize,
  FromTaskXMLSHA256:record.XMLSHA256,
  ToVersion:"0.28.7",ToSHA256:target,ToSize:321,
  MinPanelVersion:"0.28.7",
  IssuedUTC:issued.Format(time.RFC3339),ExpiresUTC:expires.Format(time.RFC3339),
 }
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 raw,err:=json.Marshal(pem)
 if err!=nil{t.Fatal(err)}
 sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
 return signedRecoveryFixture{root:root,journal:journal,backup:backup,pem:pem,
  permit:raw,sig:sig,pub:pub,priv:priv}
}
func (f signedRecoveryFixture) resign(t *testing.T,p LegacyMigrationPermit) signedRecoveryFixture{
 t.Helper()
 var err error
 f.permit,err=json.Marshal(p)
 if err!=nil{t.Fatal(err)}
 f.sig=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,f.permit)))
 f.pem=p
 return f
}
func(f signedRecoveryFixture) verify()error{
 allow:=func(string)error{return nil}
 _,err:=VerifyResidentPublisherRecoveryBinding(context.Background(),
  f.journal,f.backup,f.permit,f.sig,f.pub,allow,allow)
 return err
}

func TestSignedPublisherBootRecoveryAcceptsExpiredPermitButNeverNewMigration(t *testing.T){
 f:=makeSignedRecoveryFixture(t,true)
 if err:=f.verify();err!=nil{t.Fatalf("expired previously signed bridge stranded authorized recovery: %v",err)}
 if _,err:=parseSignedMigrationPermit(f.permit,f.sig,f.pub);err==nil{
  t.Fatal("expired signature incorrectly authorized a NEW upgrade")
 }
}

func TestSignedPublisherBootRecoveryRejectsForgedOrUnboundEvidence(t *testing.T){
 for _,scenario:=range []string{
  "forged-signature","wrong-publisher-key","wrong-original-SHA","wrong-XML-SHA",
  "wrong-target-SHA","wrong-target-version","wrong-old-size",
  "tampered-sealed-exe","tampered-XML","journal-terminal","missing-journal",
  "invalid-directory","future-issued-permit","unsupported-target",
 }{
  t.Run(scenario,func(t *testing.T){
   f:=makeSignedRecoveryFixture(t,false)
   switch scenario{
   case "forged-signature":f.sig=[]byte(strings.Repeat("A",88))
   case "wrong-publisher-key":f.pub,_ ,_=ed25519.GenerateKey(rand.Reader)
   case "wrong-original-SHA":p:=f.pem;p.FromSHA256=strings.Repeat("a",64);f=f.resign(t,p)
   case "wrong-XML-SHA":p:=f.pem;p.FromTaskXMLSHA256=strings.Repeat("b",64);f=f.resign(t,p)
   case "wrong-target-SHA":p:=f.pem;p.ToSHA256=strings.Repeat("c",64);f=f.resign(t,p)
   case "wrong-target-version":p:=f.pem;p.ToVersion="0.28.8";f=f.resign(t,p)
   case "wrong-old-size":p:=f.pem;p.FromSize++;f=f.resign(t,p)
   case "tampered-sealed-exe":
    if err:=os.WriteFile(filepath.Join(f.backup,legacyBackupExe),[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
   case "tampered-XML":
    if err:=os.WriteFile(filepath.Join(f.backup,legacyBackupXML),[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
   case "journal-terminal":
    allow:=func(string)error{return nil}
    if err:=FinishResidentRecoveryIntent(context.Background(),f.journal,"restored",allow,allow);err!=nil{t.Fatal(err)}
   case "missing-journal":
    if err:=os.Remove(filepath.Join(f.journal,ResidentIntentFile));err!=nil{t.Fatal(err)}
   case "invalid-directory":
    f.backup=f.root
   case "future-issued-permit":
    p:=f.pem
    p.IssuedUTC=time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)
    p.ExpiresUTC=time.Now().UTC().Add(48*time.Hour).Format(time.RFC3339)
    f=f.resign(t,p)
   case "unsupported-target":
    p:=f.pem;p.ToVersion="0.28.6";f=f.resign(t,p)
   }
   if err:=f.verify();err==nil{t.Fatal("untrusted signed recovery binding accepted")}
  })
 }
}

func TestSignedPublisherBootRecoveryRequiresProtectedCallbacksAndCancellation(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil}
 if _,err:=VerifyResidentPublisherRecoveryBinding(context.Background(),
 f.journal,f.backup,f.permit,f.sig,f.pub,nil,allow);err==nil{
  t.Fatal("missing trusted journal ACL callback accepted")
 }
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 if _,err:=VerifyResidentPublisherRecoveryBinding(ctx,
 f.journal,f.backup,f.permit,f.sig,f.pub,allow,allow);err==nil{
  t.Fatal("cancelled recovery obtained approval")
 }
}
