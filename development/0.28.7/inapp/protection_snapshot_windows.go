//go:build windows

package motorupdate

// A read-only PARTIAL baseline of four existing protection surfaces that a
// future installer must preserve: hosts file, browser policies, catalog task,
// and per-adapter IPv4/IPv6 DNS assignment mode/static servers. Motor/task
// recovery and durable restoration are separate evidence.
// Only fingerprints/counts are returned; this is NOT a durable restore backup.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net/netip"
 "os"
 "path/filepath"
 "strings"
)

const windowsHostsFileMaxBytes = 4 << 20
const catalogTaskAbsentMarker = "volve-catalog-task-absent/v1"

type WindowsHostsFileEvidence struct {
 SHA256 string
 BlockedRuleCount int
}
type WindowsHostsFileInspect func(context.Context)(WindowsHostsFileEvidence,error)

type WindowsProtectionSnapshotInspectors struct {
 Hosts WindowsHostsFileInspect
 Browser WindowsBrowserPolicyInspect
 Tasks WindowsFreshTaskInspect
 DNS WindowsReadOnlyPowerShell
}

func DefaultWindowsHostsFileInspect(ctx context.Context)(WindowsHostsFileEvidence,error){
 var empty WindowsHostsFileEvidence
 if ctx==nil{return empty,errors.New("hosts inspection requires non-nil context")}
 if err:=ctx.Err();err!=nil{return empty,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){
  return empty,errors.New("trusted local Windows SystemRoot unavailable")
 }
 path:=filepath.Join(root,"System32","drivers","etc","hosts")
 return inspectWindowsHostsFileAtReadOnly(ctx,path)
}

// inspectWindowsHostsFileAtReadOnly hashes the exact bytes while checking
// that the path still identifies the same regular file after reading.
func inspectWindowsHostsFileAtReadOnly(ctx context.Context,path string)(WindowsHostsFileEvidence,error){
 evidence,_,err:=captureWindowsHostsFileAtReadOnly(ctx,path)
 return evidence,err
}

// captureOriginalWindowsHostsBackup is deliberately local and read-only.
// The caller must provide the independently verified before-state; merely
// hashing newly read bytes does not establish that they are the original.
// The returned bytes are sensitive and must never enter JSON, logs or a
// remote artifact. A separate protected durable store is still required.
func captureOriginalWindowsHostsBackup(ctx context.Context,path string,expected WindowsHostsFileEvidence)([]byte,error){
 if ctx==nil{return nil,errors.New("hosts backup requires non-nil context")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if !protectionDigest.MatchString(strings.ToLower(expected.SHA256))||
  expected.BlockedRuleCount<0||expected.BlockedRuleCount>1_000_000{
  return nil,errors.New("independent original hosts evidence missing or malformed")
 }
 observed,raw,err:=captureWindowsHostsFileAtReadOnly(ctx,path)
 if err!=nil{return nil,err}
 if !strings.EqualFold(observed.SHA256,expected.SHA256)||observed.BlockedRuleCount!=expected.BlockedRuleCount{
  return nil,errors.New("hosts differs from independently observed original")
 }
 if err:=verifyOriginalWindowsHostsBackup(raw,expected);err!=nil{return nil,err}
 if err:=ctx.Err();err!=nil{return nil,err}
 return raw,nil
}

// Reuse after reopening a protected backup. No restoration or file writes.
func verifyOriginalWindowsHostsBackup(raw []byte,expected WindowsHostsFileEvidence)error{
 if raw==nil||len(raw)>windowsHostsFileMaxBytes||
  !protectionDigest.MatchString(strings.ToLower(expected.SHA256))||
  expected.BlockedRuleCount<0||expected.BlockedRuleCount>1_000_000{
  return errors.New("original hosts backup or independent evidence invalid")
 }
 sum:=sha256.Sum256(raw)
 if !strings.EqualFold(hex.EncodeToString(sum[:]),expected.SHA256)||
  countWindowsHostsBlockedRules(raw)!=expected.BlockedRuleCount{
  return errors.New("original hosts backup integrity mismatch")
 }
 return nil
}

func captureWindowsHostsFileAtReadOnly(ctx context.Context,path string)(WindowsHostsFileEvidence,[]byte,error){
 var empty WindowsHostsFileEvidence
 if ctx==nil{return empty,nil,errors.New("hosts capture requires non-nil context")}
 if err:=ctx.Err();err!=nil{return empty,nil,err}
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path||strings.HasPrefix(path,`\\`){
  return empty,nil,errors.New("hosts file path must be canonical and local")
 }
 before,err:=os.Lstat(path)
 if err!=nil{return empty,nil,fmt.Errorf("Windows hosts file unavailable: %w",err)}
 if !before.Mode().IsRegular()||before.Mode()&os.ModeSymlink!=0||
  before.Size()<0||before.Size()>windowsHostsFileMaxBytes{
  return empty,nil,errors.New("hosts file is linked, special or oversized")
 }
 f,err:=os.Open(path)
 if err!=nil{return empty,nil,err}
 defer f.Close()
 opened,err:=f.Stat()
 if err!=nil{return empty,nil,err}
 if !opened.Mode().IsRegular()||!os.SameFile(before,opened){
  return empty,nil,errors.New("hosts file identity changed before read")
 }
 raw,err:=io.ReadAll(io.LimitReader(f,windowsHostsFileMaxBytes+1))
 if err!=nil{return empty,nil,err}
 if len(raw)>windowsHostsFileMaxBytes{return empty,nil,errors.New("hosts file grew beyond read limit")}
 afterHandle,err:=f.Stat()
 if err!=nil{return empty,nil,err}
 afterPath,err:=os.Lstat(path)
 if err!=nil{return empty,nil,err}
 if !afterPath.Mode().IsRegular()||afterPath.Mode()&os.ModeSymlink!=0||
  !os.SameFile(opened,afterHandle)||!os.SameFile(opened,afterPath)||
  opened.Size()!=afterHandle.Size()||opened.Size()!=afterPath.Size()||
  !opened.ModTime().Equal(afterHandle.ModTime())||!opened.ModTime().Equal(afterPath.ModTime())||
  int64(len(raw))!=afterPath.Size(){
  return empty,nil,errors.New("hosts file changed or was replaced during read")
 }
 if err:=ctx.Err();err!=nil{return empty,nil,err}
 sum:=sha256.Sum256(raw)
 count:=countWindowsHostsBlockedRules(raw)
 if count<0||count>1_000_000{return empty,nil,errors.New("hosts file candidate rule count outside safe range")}
 return WindowsHostsFileEvidence{SHA256:hex.EncodeToString(sum[:]),BlockedRuleCount:count},raw,nil
}

// countWindowsHostsBlockedRules counts non-localhost names mapped to loopback
// or unspecified addresses. It returns no names or line contents. This is a
// conservative candidate count for comparison, not proof of DNS enforcement.
func countWindowsHostsBlockedRules(raw []byte)int{
 count:=0
 for _,line:=range strings.Split(string(raw),"\n"){
  line=strings.TrimSpace(strings.SplitN(line,"#",2)[0])
  if line==""{continue}
  fields:=strings.Fields(line)
  if len(fields)<2{continue}
  ip,err:=netip.ParseAddr(fields[0])
  if err!=nil||(!ip.IsLoopback()&&!ip.IsUnspecified()){continue}
  for _,rawName:=range fields[1:]{
   name:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawName)),".")
   if name==""||name=="localhost"||name=="localhost.localdomain"||
    name=="local"||strings.HasSuffix(name,".localhost"){
    continue
   }
   count++
  }
 }
 return count
}

// InspectWindowsProtectionSnapshotReadOnly binds hosts bytes, the three
// browser-policy registry fingerprints and the exact VOLVE catalog task
// definition into one complete comparison baseline. A missing catalog task
// is represented by a fixed sentinel hash; any unknown or unpinned VOLVE
// task blocks capture. The result stays in memory and is not a restore source.
func InspectWindowsProtectionSnapshotReadOnly(
 ctx context.Context,
 expectedCatalogExecutable,expectedCatalogArguments string,
 inspectors WindowsProtectionSnapshotInspectors,
)(ProtectionSnapshot,WindowsBrowserPolicyEvidence,error){
 var zero ProtectionSnapshot
 var emptyBrowser WindowsBrowserPolicyEvidence
 if ctx==nil{return zero,emptyBrowser,errors.New("protection snapshot context required")}
 if err:=ctx.Err();err!=nil{return zero,emptyBrowser,err}
 if inspectors.Hosts==nil||inspectors.Browser==nil||inspectors.Tasks==nil||inspectors.DNS==nil{
  return zero,emptyBrowser,errors.New("hosts, browser and Task Scheduler inspectors are all required")
 }
 hosts,err:=inspectors.Hosts(ctx)
 if err!=nil{return zero,emptyBrowser,fmt.Errorf("hosts baseline unavailable: %w",err)}
 if !protectionDigest.MatchString(strings.ToLower(hosts.SHA256))||
  hosts.BlockedRuleCount<0||hosts.BlockedRuleCount>1_000_000{
  return zero,emptyBrowser,errors.New("hosts baseline hash or candidate count invalid")
 }
 browser,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,inspectors.Browser)
 if err!=nil{return zero,emptyBrowser,fmt.Errorf("browser policy baseline unavailable: %w",err)}
 tasks,err:=InspectWindowsVOLVETasksReadOnly(ctx,expectedCatalogExecutable,expectedCatalogArguments,inspectors.Tasks)
 if err!=nil{return zero,emptyBrowser,fmt.Errorf("VOLVE catalog task baseline unavailable: %w",err)}
 dns,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,inspectors.DNS)
 if err!=nil{return zero,emptyBrowser,fmt.Errorf("original DNS assignment provenance unavailable: %w",err)}
 var catalogDigest string
 switch {
 case tasks.VOLVETaskCount==0&&len(tasks.UnknownTaskNames)==0&&tasks.VerifiedCatalogTask==nil:
  sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
  catalogDigest=hex.EncodeToString(sum[:])
 case tasks.VOLVETaskCount==1&&len(tasks.UnknownTaskNames)==0&&allowedFreshAuxiliaryTask(tasks.VerifiedCatalogTask):
  catalogDigest=strings.ToLower(tasks.VerifiedCatalogTask.DefinitionSHA256)
 default:
  return zero,emptyBrowser,errors.New("VOLVE catalog task is present but not uniquely publisher-pinned, or unknown VOLVE tasks exist")
 }
 byName:=map[string]string{}
 for _,record:=range browser.Records{byName[record.Name]=strings.ToLower(record.ContentSHA256)}
 snapshot:=ProtectionSnapshot{
  HostsSHA256:strings.ToLower(hosts.SHA256),
  HostsBlockedRuleCount:hosts.BlockedRuleCount,
  ChromePoliciesSHA256:byName["chrome"],
  EdgePoliciesSHA256:byName["edge"],
  FirefoxPoliciesSHA256:byName["firefox"],
  CatalogTaskDefinitionSHA256:catalogDigest,
  DNSAdaptersSHA256:dns.SHA256,
 }
 if !validProtectionSnapshot(snapshot){
  return zero,emptyBrowser,errors.New("complete hosts/browser/catalog protection baseline could not be assembled")
 }
 if err:=ctx.Err();err!=nil{return zero,emptyBrowser,err}
 return snapshot,browser,nil
}

func DefaultWindowsProtectionSnapshotInspectors()WindowsProtectionSnapshotInspectors{
 return WindowsProtectionSnapshotInspectors{
  Hosts:DefaultWindowsHostsFileInspect,
  Browser:DefaultWindowsBrowserPolicyInspect,
  Tasks:DefaultWindowsFreshTaskInspect,
  DNS:DefaultWindowsReadOnlyPowerShell,
 }
}
