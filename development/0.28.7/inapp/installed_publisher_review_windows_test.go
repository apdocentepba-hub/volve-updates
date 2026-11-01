//go:build windows

package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func reviewInstalledFixture(t *testing.T)(migrationStatusFixture,livePublisherReviewProbes,*[3]int){
 t.Helper()
 f:=makeMigrationStatusFixture(t)
 counts:=new([3]int)
 probes:=livePublisherReviewProbes{
  Preflight:func()(string,error){counts[0]++;return "CI disposable task and DNS checked",nil},
  RunningMotor:func(_ context.Context,exe,expected string)error{
   counts[1]++
   if exe!=filepath.Join(f.root,dnsServiceFile)||len(expected)!=64{return errors.New("unexpected live DNS identity")}
   return nil
  },
  TaskXML:func(_ context.Context,exe string)([]byte,error){
   counts[2]++
   if exe!=filepath.Join(f.root,dnsServiceFile){return nil,errors.New("wrong legacy task exe")}
   return os.ReadFile(filepath.Join(f.backup,"VOLVE_DNS_Legacy_Task.xml"))
  },
  ProtectBackup:func(string)error{return nil}, // ONLY CI: real caller verifies sealed DACL.
 }
 return f,probes,counts
}

func TestInstalledPublisherReviewBridgeRequiresRepeatedLiveSYSTEMTaskXMLAndDNS(t *testing.T){
 f,p,calls:=reviewInstalledFixture(t)
 out,err:=buildInstalledPublisherReviewReadOnly(context.Background(),f.root,f.candidate,"0.28.7",f.pub,true,p)
 if err!=nil{t.Fatal(err)}
 if out.Component!=motorupdate.LegacyPublisherReviewComponent||
  out.Disposition!="REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT"||
  out.InspectedPanelVersion!="0.28.7"||
  calls[0]!=2||calls[1]!=2||calls[2]!=2{
  t.Fatalf("review not independently reverified or permission accidentally granted: %+v calls=%+v",out,calls)
 }
 if _,err:=os.Stat(filepath.Join(f.root,dnsServiceFile));err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(filepath.Join(f.backup,"VOLVE_DNS_Legacy_Recovery.json"));err!=nil{t.Fatal(err)}
}

func TestInstalledPublisherReviewBridgeRejectsUnsafeLiveWindows(t *testing.T){
 for _,kind:=range []string{
  "non-admin","wrong-key","wrong-install-root","missing-signed-candidate",
  "missing-preflight","missing-running-reader","missing-task-XML-reader",
  "missing-ACL-probe","weak-parent-ACL","changed-live-task-XML",
  "missing-task","wrong-PID","preflight-unavailable",
  "task-mutated-between-reads","running-motor-gone-between-reads",
  "cancelled","old-motor-tampered","managed-installation",
 } {
  t.Run(kind,func(t *testing.T){
   f,p,calls:=reviewInstalledFixture(t)
   elevated:=true
   pub:=f.pub
   root:=f.root
   ctx:=context.Background()
   switch kind{
   case "non-admin":elevated=false
   case "wrong-key":pub,_,_=ed25519.GenerateKey(rand.Reader)
   case "wrong-install-root":root="untrusted-relative-folder"
   case "missing-signed-candidate":_ = os.Remove(f.candidate+".sig")
   case "missing-preflight":p.Preflight=nil
   case "missing-running-reader":p.RunningMotor=nil
   case "missing-task-XML-reader":p.TaskXML=nil
   case "missing-ACL-probe":p.ProtectBackup=nil
   case "weak-parent-ACL":p.ProtectBackup=func(path string)error{
    if path==filepath.Join(f.root,localRecoveryFolder){return os.ErrPermission};return nil
   }
   case "changed-live-task-XML":p.TaskXML=func(context.Context,string)([]byte,error){return []byte("other task"),nil}
   case "missing-task":p.TaskXML=func(context.Context,string)([]byte,error){return nil,os.ErrNotExist}
   case "wrong-PID":p.RunningMotor=func(context.Context,string,string)error{return errors.New("wrong DNS owner PID")}
   case "preflight-unavailable":p.Preflight=func()(string,error){return "",os.ErrPermission}
   case "task-mutated-between-reads":
    base:=p.TaskXML
    p.TaskXML=func(ctx context.Context,exe string)([]byte,error){
     b,err:=base(ctx,exe)
     if err==nil&&calls[2]==1 {b=append(b,[]byte(" changed")...)}
     return b,err
    }
   case "running-motor-gone-between-reads":
    p.RunningMotor=func(context.Context,string,string)error{
     calls[1]++
     if calls[1]>1{return errors.New("SYSTEM DNS motor stopped")}
     return nil
    }
   case "cancelled":c,cancel:=context.WithCancel(ctx);cancel();ctx=c
   case "old-motor-tampered":_ = os.WriteFile(filepath.Join(f.root,dnsServiceFile),[]byte("tampered"),0600)
   case "managed-installation":
    engine:=filepath.Join(f.root,"installed-engines")
    if err:=os.Mkdir(engine,0700);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(engine,"VOLVE_Motor_Current.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
   }
   out,err:=buildInstalledPublisherReviewReadOnly(ctx,root,f.candidate,"0.28.7",pub,elevated,p)
   if err==nil||out.Component!=""{t.Fatalf("case %s falsely accepted unsigned review: %+v, err=%v",kind,out,err)}
  })
 }
}

func TestInstalledPublisherReviewNativeTaskObserverIsReadOnlyAndFailClosed(t *testing.T){
 // On an ordinary GitHub-hosted Windows VM the production task is absent.
 // If a runner happens to carry this exact task, do not attempt any writes.
 ctx:=context.Background()
 xml,exists,err:=taskQuery(dnsServiceTask)
 if err!=nil{t.Logf("Task Scheduler unavailable; read-only check failed closed: %v",err);return}
 if !exists{
  root:=t.TempDir()
  _,err:=readPublisherReviewLiveTaskXML(ctx,filepath.Join(root,dnsServiceFile))
  if err==nil{t.Fatal("missing production task accepted as legitimate signed motor")}
  t.Log("READ ONLY: actual Windows Scheduler has no VOLVE-DNS-SERVER-0270; publisher evidence appropriately unavailable")
  return
 }
 if len(xml)==0||len(xml)>1<<20{t.Fatal("unexpected existing system task XML size")}
 t.Log("READ ONLY: existing VOLVE task observed; no task or DNS changes attempted")
}

func TestInstalledPublisherReviewNeverPrintsGrantWithoutPublisherPermit(t *testing.T){
 f,p,_:=reviewInstalledFixture(t)
 pkt,err:=buildInstalledPublisherReviewReadOnly(context.Background(),f.root,f.candidate,"0.28.7",f.pub,true,p)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(pkt.Disposition,"APPROVED")||pkt.Component=="dns-engine-legacy-migration"{
  t.Fatal("review-only status falsely represented as signed publisher permit")
 }
}
