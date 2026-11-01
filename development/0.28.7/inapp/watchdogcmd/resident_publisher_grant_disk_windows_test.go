//go:build windows

package main

// Genuine NTFS ACL + independent Windows process rehearsal of the durable,
// publisher-signed rescue grant. Only temporary synthetic files under a
// disposable hosted Windows runner; no production task, motor, or DNS writes.
import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func windowsDurableGrantFixture(t *testing.T)(string,[]byte,[]byte,ed25519.PublicKey){
 t.Helper()
 root,journal,_,_:=chainFixture(t,false)
 pending,err:=auditResidentJournal(context.Background(),journal)
 if err!=nil{t.Fatal(err)}
 backup,err:=auditResidentRollback(context.Background(),root)
 if err!=nil{t.Fatal(err)}
 issued:=time.Now().UTC().Add(-time.Hour)
 permit:=motorupdate.LegacyMigrationPermit{
  Schema:1,Component:"dns-engine-legacy-migration",
  FromTask:"VOLVE-DNS-SERVER-0270",FromArgs:"--dns-service",FromExecutable:residentLegacyExe,
  FromSHA256:backup.LegacySHA256,FromTaskXMLSHA256:backup.TaskXMLSHA256,
  FromSize:0,
  ToVersion:pending.Intent.TargetVersion,ToSHA256:pending.Intent.TargetSHA256,
  ToSize:2048,MinPanelVersion:"0.28.7",
  IssuedUTC:issued.Format(time.RFC3339),ExpiresUTC:issued.Add(2*time.Hour).Format(time.RFC3339),
 }
 actual,err:=os.Stat(filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe))
 if err!=nil{t.Fatal(err)}
 permit.FromSize=actual.Size()
 raw,err:=json.Marshal(permit)
 if err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 signature:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
 return root,raw,signature,pub
}

func durableWindowsACL(path string)error{
 return checkResidentJournalNTFS(context.Background(),path)
}
func TestDurableWindowsGrantNTFSFreshProcessAndACLTamper(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("requires disposable GitHub Windows VM with admin token")
 }
 root,permit,signature,key:=windowsDurableGrantFixture(t)
 seal:=func(path string)error{hardenedTestACL(t,path,path);return nil}
 if err:=motorupdate.PersistResidentDurablePublisherGrant(context.Background(),
  root,permit,signature,key,seal,durableWindowsACL,durableWindowsACL,durableWindowsACL);err!=nil{
  t.Fatalf("protected signed grant could not persist into Windows NTFS: %v",err)
 }
 cmd:=exec.Command(os.Args[0],"-test.run=^TestDurableWindowsGrantReadInIndependentChild$","-test.v")
 cmd.Env=append(os.Environ(),"VOLVE_CI_SIGNED_BOOT_GRANT_CHILD=1",
  "VOLVE_CI_SIGNED_BOOT_GRANT_ROOT="+root,
  "VOLVE_CI_SIGNED_BOOT_GRANT_KEY="+base64.StdEncoding.EncodeToString(key))
 out,err:=cmd.CombinedOutput()
 if err!=nil||!strings.Contains(string(out),"VOLVE_DURABLE_NTFS_BOOT_VERIFIED"){
  t.Fatalf("fresh watchdog process could not authenticate protected grant: %v %s",err,out)
 }
 grant:=filepath.Join(root,residentRecoveryParent,"publisher-authorization")
 target:=filepath.Join(grant,"migration-permit.sig")
 tamper,err:=exec.Command("icacls.exe",target,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("cannot create disposable untrusted grant ACL fixture: %v %s",err,tamper)}
 if _,err:=motorupdate.LoadResidentDurablePublisherGrant(context.Background(),
  root,key,durableWindowsACL,durableWindowsACL,durableWindowsACL);err==nil{
  t.Fatal("ordinary user writable signature was trusted after independent NTFS ACL check")
 }
 if err:=motorupdate.PersistResidentDurablePublisherGrant(context.Background(),
  root,permit,signature,key,seal,durableWindowsACL,durableWindowsACL,durableWindowsACL);err==nil{
  t.Fatal("signed grant with broken ACL was silently replaced")
 }
}

func TestDurableWindowsGrantReadInIndependentChild(t *testing.T){
 if os.Getenv("VOLVE_CI_SIGNED_BOOT_GRANT_CHILD")!="1"{return}
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Fatal("standalone publisher grant audit is only running from protected CI fixture")
 }
 root:=os.Getenv("VOLVE_CI_SIGNED_BOOT_GRANT_ROOT")
 key,err:=base64.StdEncoding.DecodeString(os.Getenv("VOLVE_CI_SIGNED_BOOT_GRANT_KEY"))
 if err!=nil{t.Fatal(err)}
 observed,err:=motorupdate.LoadResidentDurablePublisherGrant(context.Background(),root,
  key,durableWindowsACL,durableWindowsACL,durableWindowsACL)
 if err!=nil{t.Fatalf("independent process rejected signed grant/NTFS: %v",err)}
 if len(observed.Permit)==0||len(observed.Signature)==0{t.Fatal("missing publisher data")}
 t.Log("VOLVE_DURABLE_NTFS_BOOT_VERIFIED")
}

func TestDurableWindowsGrantNoMissingPublisherKey(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("hosted CI fixture")
 }
 root,_,_,_:=windowsDurableGrantFixture(t)
 _,err:=motorupdate.LoadResidentDurablePublisherGrant(context.Background(),root,nil,
  durableWindowsACL,durableWindowsACL,durableWindowsACL)
 if err==nil||errors.Is(err,os.ErrNotExist){t.Fatal("publisher key required even before loading an on-disk grant")}
}
