//go:build windows

package motorupdate

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "strings"
 "testing"
)

func TestWindowsFreshRecoveryPermitDistinctScope(t *testing.T){
 ctx:=context.Background()
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 permit:=freshRecoveryPermit{1,freshRecoveryPermitComponent,freshRecoveryOperation,pins}
 raw,err:=json.Marshal(permit);if err!=nil{t.Fatal(err)}
 sig:=ed25519.Sign(priv,raw)
 if got,err:=verifyFreshRecoveryPermit(ctx,raw,sig,pub,pins);err!=nil||got!=permit{t.Fatal("valid recovery-only permit rejected",err)}
 for _,name:=range []string{"activation-scope","foreign-transaction","foreign-dns","foreign-motor","foreign-watchdog","foreign-owner","noncanonical","wrong-key","bad-signature"}{
  t.Run(name,func(t *testing.T){
   g,p:=permit,pins
   key:=pub
   switch name{
   case "activation-scope":g.Component=freshActivationComponent;g.Operation=freshActivationOperation
   case "foreign-transaction":p.TransactionID=strings.Repeat("b",32)
   case "foreign-dns":p.OriginalDNSJournalSHA256=strings.Repeat("f",64)
   case "foreign-motor":p.MotorSHA256=strings.Repeat("f",64)
   case "foreign-watchdog":p.WatchdogExecutableSHA256=strings.Repeat("f",64)
   case "foreign-owner":p.OwnerApprovalSHA256=strings.Repeat("f",64)
   case "wrong-key":key,_,err=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
   }
   r,err:=json.Marshal(g);if err!=nil{t.Fatal(err)}
   if name=="noncanonical"{r=append(r,' ')}
   s:=ed25519.Sign(priv,r);if name=="bad-signature"{s[0]^=1}
   if got,err:=verifyFreshRecoveryPermit(ctx,r,s,key,p);err==nil||got!=(freshRecoveryPermit{}){t.Fatal("unsafe recovery accepted")}
  })
 }
 t.Log("PASS VOLVE_FRESH_RECOVERY_PERMIT_DISTINCT_SCOPE_NO_ACTIVATION_EXPIRY")
}
