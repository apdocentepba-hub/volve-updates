//go:build windows && volveci

package main

// Disposable-VM ONLY: the actual production DNS engine runs on loopback:53,
// proves six responses, seals a receipt, then terminates ungracefully with 83.
// This is a REAL test executable but NOT a release, official signed candidate,
// or permit to update the installed VOLVE 0.28.6 motor.
import (
 "bytes"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "time"
)

const ciCandidateFailFlag="--ci-failing-candidate-dns53"
// The failing test candidate is deliberately a distinct binary from the
// stable Full-CI motor; the normal VM binary has this value unset.
var ciCandidateBuildIdentity="UNSET"
const ciCandidateProof="ci-candidate-dns53-confirmed.json"

func init() {
 if len(os.Args)<2 || os.Args[1]!=ciCandidateFailFlag{return}
 if len(os.Args)!=4 {
  fmt.Fprintln(os.Stderr,"CI candidate refused: exact root and VM-only token required")
  os.Exit(2)
 }
 if err:=runCIFailingCandidateDNS53(os.Args[2],os.Args[3]);err!=nil{
  fmt.Fprintln(os.Stderr,"CI candidate aborted before intended failure:",err)
  os.Exit(1)
 }
 // The process deliberately aborts without a graceful commit or task
 // restoration. The independent SYSTEM watchdog must recover after reboot.
 os.Exit(83)
}

func ciCandidateDNSQuery(ip,domain string,expected int)error {
 network,address:="udp4","127.0.0.1:53"
 if ip=="::1"{network,address="udp6","[::1]:53"}
 conn,err:=net.DialTimeout(network,address,250*time.Millisecond)
 if err!=nil{return err}
 defer conn.Close()
 if err:=conn.SetDeadline(time.Now().Add(350*time.Millisecond));err!=nil{return err}
 id:=uint16(time.Now().UnixNano())
 packet:=[]byte{byte(id>>8),byte(id),1,0,0,1,0,0,0,0,0,0}
 for _,part:=range strings.Split(domain,"."){
  if part==""||len(part)>63{return errors.New("invalid CI DNS label")}
  packet=append(packet,byte(len(part)))
  packet=append(packet,[]byte(part)...)
 }
 packet=append(packet,0,0,1,0,1)
 if _,err:=conn.Write(packet);err!=nil{return err}
 reply:=make([]byte,2048)
 n,err:=conn.Read(reply);if err!=nil{return err}
 if n<len(packet)||!bytes.Equal(reply[0:2],packet[0:2]) ||
    reply[2]&0x80==0 || reply[2]&0x02!=0 ||
    binary.BigEndian.Uint16(reply[4:6])!=1 ||
    !bytes.Equal(reply[12:len(packet)],packet[12:]) ||
    int(reply[3]&0x0F)!=expected {
  return fmt.Errorf("candidate DNS reply failed contract for %s %s",ip,domain)
 }
 return nil
}
func ciCandidateSixDNS()error{
 for _,ip:=range []string{"127.0.0.1","::1"}{
  for _,entry:=range []struct{domain string;rcode int}{
   {"stake.com",3},{"betwarrior.bet.ar",3},{"example.org",0},
  }{
   if err:=ciCandidateDNSQuery(ip,entry.domain,entry.rcode);err!=nil{return err}
  }
 }
 return nil
}
func runCIFailingCandidateDNS53(root,token string)error{
 if ciCandidateBuildIdentity!="VOLVE-0287-VM-FAIL-CANDIDATE"{
  return errors.New("only dedicated CI failing-candidate binary may run this destructive rehearsal")
 }
 if err:=assertCIFreshVM(root,token);err!=nil{return err}
 // The candidate must be a distinct SYSTEM-run executable in a disposable
 // VM; do not permit this CLI from an interactive administrator shell.
 who,err:=exec.Command("whoami.exe","/user").Output()
 if err!=nil||!strings.Contains(string(who),"S-1-5-18"){
  return errors.New("CI failing DNS candidate must run under actual SYSTEM token")
 }
 if err:=verifyCIFreshCatalog(root);err!=nil{return err}
 if filepath.Base(root)=="" || root=="" {return errors.New("invalid VM root")}
 proof:=filepath.Join(root,ciCandidateProof)
 if _,err:=os.Lstat(proof);err==nil{return errors.New("candidate receipt exists: never overwrite")}
 // The production DNS engine and 400k+ parser are the same routines as
 // normal VOLVE; no adapter/network settings are modified by this test.
 serviceDone:=make(chan error,1)
 go func(){serviceDone<-runCIFreshDNS53WithDuration(root,token,90*time.Second)}()
 var last error=errors.New("DNS probe did not start")
 deadline:=time.Now().Add(24*time.Second)
 for time.Now().Before(deadline){
  select {
  case err:=<-serviceDone:
   return fmt.Errorf("real CI DNS service terminated before candidate proof: %w",err)
  default:
  }
  if err:=ciCandidateSixDNS();err==nil{
   path,err:=os.Executable();if err!=nil{return err}
   f,err:=os.Open(path);if err!=nil{return err}
   h:=sha256.New()
   _,err=io.Copy(h,f)
   closeErr:=f.Close()
   if err!=nil{return err};if closeErr!=nil{return closeErr}
   receipt:=struct{
    Schema int `json:"schema"`
    Kind string `json:"kind"`
    PID int `json:"pid"`
    MotorSHA256 string `json:"motor_sha256"`
    DNSChecks int `json:"dns_checks"`
    CreatedUTC string `json:"created_utc"`
    SimulatedExitCode int `json:"simulated_exit_code"`
    PublisherSigned bool `json:"publisher_signed"`
   }{
    1,"VOLVE_CI_REAL_CANDIDATE_FAIL_DNS53",os.Getpid(),
    hex.EncodeToString(h.Sum(nil)),6,time.Now().UTC().Format(time.RFC3339Nano),83,false,
   }
   raw,err:=json.Marshal(receipt);if err!=nil{return err}
   pf,err:=os.OpenFile(proof,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
   if err!=nil{return err}
   _,err=pf.Write(raw)
   if err==nil{err=pf.Sync()}
   closeErr=pf.Close()
   if err!=nil{return err};if closeErr!=nil{return closeErr}
   fmt.Println("CI_REAL_DNS53_CANDIDATE_CONFIRMED_6_OF_6: intentional exit 83")
   return nil
  }else{last=err}
  time.Sleep(180*time.Millisecond)
 }
 return fmt.Errorf("real VM candidate did not prove six DNS queries: %w",last)
}
