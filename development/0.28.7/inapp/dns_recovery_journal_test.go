package motorupdate

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "strings"
 "testing"
)

func dnsOriginalFixture() []DNSServerState {
 return []DNSServerState{
  {InterfaceGUID:testAdapterGUID,Family:DNSIPv6,Mode:DNSAutomatic},
  {InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
 }
}

func TestDNSRecoveryJournalExactRoundTripAndWriteFreePreview(t *testing.T){
 ctx:=context.Background()
 raw,pin,err:=BuildDNSOriginalJournal(ctx,dnsOriginalFixture())
 if err!=nil{t.Fatal(err)}
 if len(pin)!=64||len(raw)==0{t.Fatal("recovery data was not externally pinnable")}
 records,err:=VerifyDNSOriginalJournal(ctx,raw,pin)
 if err!=nil{t.Fatal(err)}
 if len(records)!=2||records[0].Original.Family!=DNSIPv4||
  records[1].Original.Family!=DNSIPv6{t.Fatalf("wrong canonical order: %+v",records)}
 if records[0].Original.Servers[0]!="9.9.9.9"||
  records[0].Original.Servers[1]!="1.1.1.1"||
  records[0].Expected.Servers[0]!="127.0.0.1"||
  records[1].Expected.Servers[0]!="::1"||
  records[1].Original.Mode!=DNSAutomatic{
  t.Fatalf("exact IPv4/IPv6 original recovery state was lost: %+v",records)
 }
 backend:=newDNSFake(records...)
 preview,err:=ReviewDNSRestoreWithoutWrites(ctx,records,backend)
 if err!=nil{t.Fatal(err)}
 if preview.ReviewedFamilies!=2||preview.WouldRestore!=2||
  preview.AlreadyOriginal!=0||preview.PerformedWrites||
  preview.InstallAuthorized||preview.RestoreAuthorized||
  len(backend.applied)!=0{
  t.Fatalf("preview modified Windows or granted a write: %+v",preview)
 }
 // This exercises the independently existing restoration contract only in
 // a FAKE backend. It is NOT a real Windows DNS change or post-reboot test.
 if err:=RestoreVOLVEDNSAfterFailure(ctx,records,backend);err!=nil{t.Fatal(err)}
 if !sameDNSState(backend.current[DNSIPv4],records[0].Original)||
  !sameDNSState(backend.current[DNSIPv6],records[1].Original){
  t.Fatal("simulated rollback did not restore exact original IPv4/IPv6")
 }
 preview,err=ReviewDNSRestoreWithoutWrites(ctx,records,backend)
 if err!=nil{t.Fatal(err)}
 if preview.AlreadyOriginal!=2||preview.WouldRestore!=0||len(backend.applied)!=2{
  t.Fatal("post-rollback preview changed an already-restored adapter")
 }
}

func TestDNSRecoveryJournalRejectsTamperingAndMissingExternalPin(t *testing.T){
 ctx:=context.Background()
 raw,pin,err:=BuildDNSOriginalJournal(ctx,dnsOriginalFixture())
 if err!=nil{t.Fatal(err)}
 tampered:=append([]byte(nil),raw...)
 idx:=bytes.Index(tampered,[]byte("9.9.9.9"))
 if idx<0{t.Fatal("static original DNS not recorded")}
 tampered[idx]='8'
 for name,tc:=range map[string]struct{raw []byte;pin string}{
  "different-payload-same-pin":{tampered,pin},
  "empty-pin":{raw,""},
  "short-pin":{raw,"f00"},
  "other-valid-pin":{raw,strings.Repeat("0",64)},
  "trailing-data":{append(append([]byte(nil),raw...),[]byte("{}")...),pin},
  "oversized":{bytes.Repeat([]byte("x"),dnsRecoveryJournalMaxBytes+1),pin},
 }{
  t.Run(name,func(t *testing.T){
   if _,err:=VerifyDNSOriginalJournal(ctx,tc.raw,tc.pin);err==nil{
    t.Fatal("untrusted or corrupted DNS recovery journal accepted")
   }
  })
 }
 // Even with a newly recomputed SHA pin, a forged noncanonical encoding
 // or extra JSON field may not become a valid journal.
 changed:=bytes.Replace(raw,[]byte(`"schema":1`),[]byte(`"schema":1,"extra":"field"`),1)
 h:=sha256.Sum256(changed)
 if _,err:=VerifyDNSOriginalJournal(ctx,changed,hex.EncodeToString(h[:]));err==nil{
  t.Fatal("unknown journal field accepted with a matching hash")
 }
 pretty:=new(bytes.Buffer)
 if err:=json.Indent(pretty,raw,"","  ");err!=nil{t.Fatal(err)}
 h=sha256.Sum256(pretty.Bytes())
 if _,err:=VerifyDNSOriginalJournal(ctx,pretty.Bytes(),hex.EncodeToString(h[:]));err==nil{
  t.Fatal("noncanonical whitespace accepted")
 }
}

func TestDNSRecoveryJournalRejectsUnknownOrIncompleteOriginals(t *testing.T){
 fixtures:=dnsOriginalFixture()
 cases:=map[string][]DNSServerState{
  "one-family":{fixtures[0]},
  "duplicate-family":{fixtures[0],fixtures[0]},
  "invalid-guid":{{InterfaceGUID:"Ethernet",Family:DNSIPv4,Mode:DNSAutomatic},fixtures[0]},
  "unknown-mode":{{InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:"guess"},fixtures[0]},
  "original-localhost":{{InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"127.0.0.1"}},fixtures[0]},
  "no-static-servers":{{InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic},fixtures[0]},
  "multicast-static":{{InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"224.0.0.1"}},fixtures[0]},
  "zero-static":{{InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"0.0.0.0"}},fixtures[0]},
 }
 for name,states:=range cases{t.Run(name,func(t *testing.T){
  if _,_,err:=BuildDNSOriginalJournal(context.Background(),states);err==nil{
   t.Fatal("incomplete or untrusted original DNS state received a recovery receipt")
  }
 })}
}

func TestDNSRecoveryPreviewRejectsExternalDNSAndNeverApplies(t *testing.T){
 originals:=dnsOriginalFixture()
 raw,pin,err:=BuildDNSOriginalJournal(context.Background(),originals)
 if err!=nil{t.Fatal(err)}
 records,err:=VerifyDNSOriginalJournal(context.Background(),raw,pin)
 if err!=nil{t.Fatal(err)}
 backend:=newDNSFake(records...)
 backend.current[DNSIPv6]=DNSServerState{
  InterfaceGUID:testAdapterGUID,Family:DNSIPv6,Mode:DNSStatic,
  Servers:[]string{"2001:4860:4860::8888"},
 }
 preview,err:=ReviewDNSRestoreWithoutWrites(context.Background(),records,backend)
 if err==nil||len(backend.applied)!=0||preview.ReviewedFamilies!=0{
  t.Fatalf("external DNS modified or partial approval returned: %+v err=%v",preview,err)
 }
}

func TestDNSRecoveryJournalCancellationFailsClosed(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,_,err:=BuildDNSOriginalJournal(ctx,dnsOriginalFixture());!errors.Is(err,context.Canceled){
  t.Fatal("cancelled snapshot did not fail closed",err)
 }
 raw,pin,err:=BuildDNSOriginalJournal(context.Background(),dnsOriginalFixture())
 if err!=nil{t.Fatal(err)}
 if _,err:=VerifyDNSOriginalJournal(ctx,raw,pin);!errors.Is(err,context.Canceled){
  t.Fatal("cancelled signature check did not fail closed",err)
 }
 records,err:=VerifyDNSOriginalJournal(context.Background(),raw,pin)
 if err!=nil{t.Fatal(err)}
 backend:=newDNSFake(records...)
 if _,err:=ReviewDNSRestoreWithoutWrites(ctx,records,backend);!errors.Is(err,context.Canceled){
  t.Fatal("cancelled preview did not fail closed",err)
 }
 if len(backend.applied)!=0{t.Fatal("cancelled preview wrote DNS")}
}

func TestDNSRecoveryJournalRejectsUnpinnedReorderedAndDuplicateRecords(t *testing.T){
 raw,pin,err:=BuildDNSOriginalJournal(context.Background(),dnsOriginalFixture())
 if err!=nil{t.Fatal(err)}
 var j DNSRecoveryJournal
 if err:=json.Unmarshal(raw,&j);err!=nil{t.Fatal(err)}
 j.Records[0],j.Records[1]=j.Records[1],j.Records[0]
 scrambled,err:=json.Marshal(j)
 if err!=nil{t.Fatal(err)}
 h:=sha256.Sum256(scrambled)
 if _,err:=VerifyDNSOriginalJournal(context.Background(),scrambled,hex.EncodeToString(h[:]));err==nil{
  t.Fatal("externally pinned but noncanonically ordered records accepted")
 }
 if _,err:=VerifyDNSOriginalJournal(context.Background(),raw,pin);err!=nil{t.Fatal(err)}
 j.Records[1]=j.Records[0]
 repeated,err:=json.Marshal(j)
 if err!=nil{t.Fatal(err)}
 h=sha256.Sum256(repeated)
 if _,err:=VerifyDNSOriginalJournal(context.Background(),repeated,hex.EncodeToString(h[:]));err==nil{
  t.Fatal("duplicate adapter/family records accepted")
 }
}
