package motorupdate

// A complete, exact DNS-only original-state journal for the future Windows
// SYSTEM installer. The journal records private adapter GUIDs and original
// DNS servers: it MUST remain local in an access-controlled recovery folder.
// Nothing here writes files, installs, enables DNS, or creates a SYSTEM task.
//
// IMPORTANT: SHA-256 integrity is NOT publisher authentication. The expected
// SHA-256 MUST be independently pinned in a protected/signed owner receipt.
// This API alone does not grant permission to change the machine.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "sort"
 "strings"
)

const dnsRecoveryJournalMaxBytes = 65536
const dnsRecoveryJournalMaxRecords = 64
const dnsRecoveryJournalComponent = "volve-dns-original-state-v1"

type DNSRecoveryJournal struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Records []DNSRestoreRecord `json:"records"`
}

type DNSRecoveryDryRun struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 ReviewedFamilies int `json:"reviewed_families"`
 AlreadyOriginal int `json:"already_original"`
 WouldRestore int `json:"would_restore"`
 PerformedWrites bool `json:"performed_writes"`
 InstallAuthorized bool `json:"install_authorized"`
 RestoreAuthorized bool `json:"restore_authorized"`
}

func validateDNSRecoveryRecords(records []DNSRestoreRecord) error {
 if len(records)<2||len(records)>dnsRecoveryJournalMaxRecords{
  return errors.New("DNS journal must contain a bounded set of IPv4 and IPv6 records")
 }
 seen:=map[string]bool{}
 families:=map[string]map[DNSAddressFamily]bool{}
 for _,r:=range records{
  if err:=validDNSState(r.Original);err!=nil{return fmt.Errorf("invalid original DNS state: %w",err)}
  if err:=validDNSState(r.Expected);err!=nil{return fmt.Errorf("invalid expected DNS state: %w",err)}
  if !strings.EqualFold(r.Original.InterfaceGUID,r.Expected.InterfaceGUID)||
   r.Original.Family!=r.Expected.Family||
   r.Expected.Mode!=DNSStatic||len(r.Expected.Servers)!=1{
   return errors.New("DNS recovery journal has mismatched adapter, family or local target")
  }
  local:="127.0.0.1"
  if r.Original.Family==DNSIPv6{local="::1"}
  if ip:=net.ParseIP(r.Expected.Servers[0]);ip==nil||!ip.Equal(net.ParseIP(local)){
   return errors.New("DNS recovery target is not the exact local VOLVE server")
  }
  if sameDNSState(r.Original,r.Expected) {
   return errors.New("original DNS state is indistinguishable from VOLVE target")
  }
  if len(r.Original.Servers)>16{
   return errors.New("unreasonable original DNS server list")
  }
  for _,server:=range r.Original.Servers{
   ip:=net.ParseIP(server)
   if ip==nil||ip.IsUnspecified()||ip.IsMulticast(){
    return errors.New("original DNS server is not a usable unicast address")
   }
  }
  guid:=strings.ToLower(r.Original.InterfaceGUID)
  key:=guid+"|"+string(r.Original.Family)
  if seen[key]{return errors.New("duplicate DNS adapter/family journal record")}
  seen[key]=true
  if families[guid]==nil{families[guid]=map[DNSAddressFamily]bool{}}
  families[guid][r.Original.Family]=true
 }
 for _,v:=range families {
  if !v[DNSIPv4]||!v[DNSIPv6]{
   return errors.New("one or more adapter GUIDs lack a complete IPv4/IPv6 pair")
  }
 }
 return nil
}

func sortedDNSRecoveryRecords(records []DNSRestoreRecord) []DNSRestoreRecord {
 ordered:=make([]DNSRestoreRecord,len(records))
 for i,r:=range records{
  ordered[i]=r
  ordered[i].Original.Servers=append([]string(nil),r.Original.Servers...)
  ordered[i].Expected.Servers=append([]string(nil),r.Expected.Servers...)
 }
 sort.Slice(ordered,func(i,j int)bool{
  a:=strings.ToLower(ordered[i].Original.InterfaceGUID)+"|"+string(ordered[i].Original.Family)
  b:=strings.ToLower(ordered[j].Original.InterfaceGUID)+"|"+string(ordered[j].Original.Family)
  return a<b
 })
 return ordered
}

// BuildDNSOriginalJournal takes ONLY independently observed adapter DNS
// assignment states, before VOLVE is connected. Its bytes are a PROPOSED
// private recovery payload, not a durable/ACL-sealed backup or write permit.
func BuildDNSOriginalJournal(ctx context.Context, originals []DNSServerState)([]byte,string,error){
 if ctx==nil{return nil,"",errors.New("missing journal context")}
 if err:=ctx.Err();err!=nil{return nil,"",err}
 if len(originals)<2||len(originals)>dnsRecoveryJournalMaxRecords{
  return nil,"",errors.New("DNS original inventory is incomplete or excessive")
 }
 records:=make([]DNSRestoreRecord,0,len(originals))
 for _,original:=range originals{
  local:="127.0.0.1"
  if original.Family==DNSIPv6{local="::1"}
  records=append(records,DNSRestoreRecord{
   Original:original,
   Expected:DNSServerState{
    InterfaceGUID:original.InterfaceGUID,Family:original.Family,
    Mode:DNSStatic,Servers:[]string{local},
   },
  })
 }
 if err:=validateDNSRecoveryRecords(records);err!=nil{return nil,"",err}
 payload:=DNSRecoveryJournal{Schema:1,Component:dnsRecoveryJournalComponent,Records:sortedDNSRecoveryRecords(records)}
 raw,err:=json.Marshal(payload)
 if err!=nil{return nil,"",err}
 if len(raw)>dnsRecoveryJournalMaxBytes{return nil,"",errors.New("recovery journal exceeds maximum size")}
 if err:=ctx.Err();err!=nil{return nil,"",err}
 sum:=sha256.Sum256(raw)
 return raw,hex.EncodeToString(sum[:]),nil
}

// VerifyDNSOriginalJournal insists on a full externally pinned SHA-256 and
// canonical encoding. Never obtain the trusted pin from the same unchecked
// journal file. Validation is a prerequisite, NOT a recovery authorization.
func VerifyDNSOriginalJournal(ctx context.Context,raw []byte,externallyTrustedSHA256 string)([]DNSRestoreRecord,error){
 if ctx==nil{return nil,errors.New("missing journal context")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if len(raw)<2||len(raw)>dnsRecoveryJournalMaxBytes{return nil,errors.New("DNS recovery payload missing or oversized")}
 expected,err:=hex.DecodeString(externallyTrustedSHA256)
 if err!=nil||len(expected)!=sha256.Size{return nil,errors.New("missing externally trusted DNS journal digest")}
 sum:=sha256.Sum256(raw)
 if subtle.ConstantTimeCompare(sum[:],expected)!=1{return nil,errors.New("DNS recovery journal differs from externally pinned original")}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 var value DNSRecoveryJournal
 if err:=dec.Decode(&value);err!=nil{return nil,fmt.Errorf("invalid DNS recovery journal: %w",err)}
 if value.Schema!=1||value.Component!=dnsRecoveryJournalComponent{return nil,errors.New("unrecognized recovery journal version")}
 if err:=validateDNSRecoveryRecords(value.Records);err!=nil{return nil,err}
 ordered:=sortedDNSRecoveryRecords(value.Records)
 canonical,err:=json.Marshal(DNSRecoveryJournal{
  Schema:1,Component:dnsRecoveryJournalComponent,Records:ordered,
 })
 if err!=nil||!bytes.Equal(raw,canonical){
  return nil,errors.New("noncanonical or trailing DNS recovery journal payload")
 }
 if err:=ctx.Err();err!=nil{return nil,err}
 return ordered,nil
}

// ReviewDNSRestoreWithoutWrites repeats the real current-state checks across
// ALL adapters and both families, without ever calling backend.Apply.
// A result cannot be used to skip the separate privileged SYSTEM authorization
// or to bypass the guarded RestoreVOLVEDNSAfterFailure transaction.
func ReviewDNSRestoreWithoutWrites(ctx context.Context,records []DNSRestoreRecord,backend DNSAdapterBackend)(DNSRecoveryDryRun,error){
 var empty DNSRecoveryDryRun
 if ctx==nil{return empty,errors.New("missing read-only recovery context")}
 if backend==nil{return empty,errors.New("missing live DNS inventory backend")}
 if err:=ctx.Err();err!=nil{return empty,err}
 if err:=validateDNSRecoveryRecords(records);err!=nil{return empty,err}
 reviewed:=0
 originals:=0
 changes:=0
 for _,r:=range sortedDNSRecoveryRecords(records){
  if err:=ctx.Err();err!=nil{return empty,err}
  current,err:=backend.Read(ctx,r.Original.InterfaceGUID,r.Original.Family)
  if err!=nil{return empty,fmt.Errorf("DNS original-state preflight unavailable: %w",err)}
  if err:=validDNSState(current);err!=nil{return empty,err}
  switch {
  case sameDNSState(current,r.Original):originals++
  case sameDNSState(current,r.Expected):changes++
  default:return empty,errors.New("external DNS change detected; refuse to plan recovery")
  }
  reviewed++
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 return DNSRecoveryDryRun{
  Schema:1,Component:"volve-dns-restore-read-only-review",
  ReviewedFamilies:reviewed,AlreadyOriginal:originals,WouldRestore:changes,
  PerformedWrites:false,InstallAuthorized:false,RestoreAuthorized:false,
 },nil
}
