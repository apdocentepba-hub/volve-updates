package motorupdate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "strings"
 "testing"
 "time"
)

func TestFreshActivationAdmissionSeparatesFreshFromMigration(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Unix(1800000000,0)
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64)}
 grant:=freshActivationAdmission{1,freshActivationComponent,freshActivationOperation,pins,now.Unix(),now.Add(time.Minute).Unix()}
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 sign:=func(g freshActivationAdmission)([]byte,[]byte){t.Helper();raw,e:=json.Marshal(g);if e!=nil{t.Fatal(e)};return raw,[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))}
 raw,sig:=sign(grant)
 if got,e:=verifyFreshActivationAdmission(context.Background(),raw,sig,pub,pins,host,now);e!=nil||got!=grant{t.Fatal("valid fresh admission refused",e)}
 for _,name:=range []string{"package","motor","archive","dns","watchdog","approval","transaction","migration","catalog","occupied","uninspected","expired","signature","noncanonical","zero"}{
  t.Run(name,func(t *testing.T){
   g,p,h,at:=grant,pins,host,now
   switch name{
   case "package":p.SignedPackageSHA256=strings.Repeat("7",64)
   case "motor":p.MotorSHA256=strings.Repeat("7",64)
   case "archive":p.OriginalReviewSHA256=strings.Repeat("7",64)
   case "dns":p.OriginalDNSJournalSHA256=strings.Repeat("7",64)
   case "watchdog":p.WatchdogTaskXMLSHA256=strings.Repeat("7",64)
   case "approval":p.OwnerApprovalSHA256=strings.Repeat("7",64)
   case "transaction":p.TransactionID=strings.Repeat("7",32)
   case "migration":g.Component=dnsActivationGrantComponent;g.Operation=dnsActivationGrantOperation
   case "catalog":h.VOLVETaskCount=1;h.VerifiedCatalogTask=&VerifiedFreshCatalogTask{Name:"VOLVE-CATALOGO-0230",TaskPath:"\\",ActionCount:1,ActionVerified:true,PrincipalVerified:true,DefinitionSHA256:strings.Repeat("7",64)}
   case "occupied":h.UDP53IPv4OwnerCount=1
   case "uninspected":h.InspectedRecoveryState=false
   case "expired":at=now.Add(time.Minute)
   case "zero":p.OwnerApprovalSHA256=strings.Repeat("0",64);g.Evidence=p
   }
   r,s:=sign(g)
   if name=="signature"{s[0]='!'}
   if name=="noncanonical"{r=append(r,' ');s=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,r)))}
   if got,e:=verifyFreshActivationAdmission(context.Background(),r,s,pub,p,h,at);e==nil||got!=(freshActivationAdmission{}){t.Fatal("unsafe fresh admission accepted")}
  })
 }
 t.Log("PASS VOLVE_FRESH_ADMISSION_BINDS_SEVEN_PINS_REJECTS_MIGRATION_AND_CATALOG")
}
