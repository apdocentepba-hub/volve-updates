//go:build windows && volveci

package main

// CI-ONLY native executable extension. Not compiled into user releases.
// Runs the production dual-stack DNS service as the scheduled SYSTEM process
// on a disposable Windows VM. Never alters adapters, hosts or policy.
import (
 "bufio"
 "crypto/sha256"
 "encoding/binary"
 "io"
 "context"
 "errors"
 "fmt"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strings"
 "time"
)

const ciFreshToken = "VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY"
var ciFreshRootPattern = regexp.MustCompile("^VOLVE-CI-FreshDNS53-[0-9]{6,20}$")

func init(){
 if len(os.Args)<2 || (os.Args[1]!="--ci-fresh-dns53" &&
     os.Args[1]!="--ci-boot-dns53" && os.Args[1]!="--ci-prepare-full-catalog"){return}
 if len(os.Args)!=4{fmt.Fprintln(os.Stderr,"CI DNS53: invalid arguments");os.Exit(2)}
 // The boot VM kit is already an ACL-protected directory before Scheduler
 // is registered. Explicitly seed a create-only deterministic catalog in
 // that folder, WITHOUT starting a DNS listener or modifying any adapter.
 if os.Args[1]=="--ci-prepare-full-catalog" {
  if err:=assertCIFreshVM(os.Args[2],os.Args[3]);err!=nil{
   fmt.Fprintln(os.Stderr,"CI Full catalog preflight refused:",err);os.Exit(1)
  }
  if err:=writeCIFreshCatalog(os.Args[2]);err!=nil{
   fmt.Fprintln(os.Stderr,"CI Full catalog bootstrap refused:",err);os.Exit(1)
  }
  fmt.Println("PASS: CI-only Full DNS catalog created and verified before SYSTEM task startup")
  os.Exit(0)
 }
 // The ordinary hosted CI remains bounded to 95 seconds. Only a positively
 // attested isolated VM may use the longer boot/recovery observation window.
 duration:=95*time.Second
 if os.Args[1]=="--ci-boot-dns53"{duration=30*time.Minute}
 if err:=runCIFreshDNS53WithDuration(os.Args[2],os.Args[3],duration);err!=nil{
  fmt.Fprintln(os.Stderr,"CI DNS53 refused/failed:",err);os.Exit(1)
 }
 os.Exit(0)
}

func assertCIFreshVM(root, token string)error{
 if token!=ciFreshToken {return errors.New("missing explicit VM-only authorization")}
 if !filepath.IsAbs(root) || !ciFreshRootPattern.MatchString(filepath.Base(root)){
  return errors.New("test root is not a dedicated absolute CI path")
 }
 // Check actual Windows VM hardware, independently of user-editable env vars.
 output,err:=exec.Command("powershell.exe","-NoProfile","-NonInteractive","-Command",
  "$m=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $m.Manufacturer+' '+$m.Model").Output()
 if err!=nil{return fmt.Errorf("cannot attest VM: %w",err)}
 identity:=strings.ToLower(string(output))
 if !strings.Contains(identity,"virtual machine") && !strings.Contains(identity,"vmware") &&
  !strings.Contains(identity,"kvm") && !strings.Contains(identity,"hyper-v") &&
  !strings.Contains(identity,"qemu") && !strings.Contains(identity,"virtualbox"){
  return errors.New("machine is not attested as a virtual machine")
 }
 return nil
}

// The fixture is deterministic. Reusing a prior test installation is allowed
// ONLY with byte-for-byte equality to the expected catalog; no mutable
// installer receipt or stale "installed" flag can authorize running it.
func expectedCIFreshCatalogSHA()([32]byte,error){
 h:=sha256.New()
 if err:=streamCIFreshCatalog(h);err!=nil{return [32]byte{},err}
 var digest [32]byte
 copy(digest[:],h.Sum(nil))
 return digest,nil
}
func streamCIFreshCatalog(writer io.Writer)error{
 w:=bufio.NewWriterSize(writer,1<<20)
 for i:=0;i<400002;i++{
  if _,err:=fmt.Fprintf(w,"vm-ci-dns-%06d.bet.ar\n",i);err!=nil{return err}
 }
 for _,host:=range []string{"stake.com","betwarrior.bet.ar","www.betwarrior.bet.ar"}{
  if _,err:=fmt.Fprintln(w,host);err!=nil{return err}
 }
 return w.Flush()
}
func verifyCIFreshCatalog(root string)error{
 info,err:=os.Lstat(root)
 if err!=nil || !info.IsDir() || info.Mode()&os.ModeSymlink!=0{
  return errors.New("existing test installation root is not a normal directory")
 }
 file:=filepath.Join(root,"catalog","feeds","hagezi_gambling_full.txt")
 fi,err:=os.Lstat(file)
 if err!=nil || !fi.Mode().IsRegular() || fi.Size()<1000000 || fi.Size()>30000000{
  return errors.New("existing catalog missing, linked or wrong size")
 }
 fd,err:=os.Open(file);if err!=nil{return err}
 defer fd.Close()
 h:=sha256.New()
 if _,err=io.Copy(h,fd);err!=nil{return err}
 expected,err:=expectedCIFreshCatalogSHA();if err!=nil{return err}
 var actual [32]byte
 copy(actual[:],h.Sum(nil))
 if actual!=expected{return errors.New("test catalog modified: DNS service refused")}
 return nil
}

func writeCIFreshCatalog(root string)error{
 folder:=filepath.Join(root,"catalog","feeds")
 if err:=os.MkdirAll(folder,0700);err!=nil{return err}
 f,err:=os.OpenFile(filepath.Join(folder,"hagezi_gambling_full.txt"),
  os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 defer f.Close()
 if err:=streamCIFreshCatalog(f);err!=nil{return err}
 if err:=f.Sync();err!=nil{return err}
 return verifyCIFreshCatalog(root)
}


// ciFreshAllowedUpstreamResponse is a DETERMINISTIC CI fixture, not Internet.
// It returns one real DNS A answer only for example.org, using TEST-NET-3.
// All other valid questions have NOERROR with zero answers; blocked domains
// must NEVER reach this upstream fixture in the real motor integration test.
func ciFreshAllowedUpstreamResponse(query []byte)([]byte,error){
 if len(query)<17 || binary.BigEndian.Uint16(query[4:6])!=1 {
  return nil,errors.New("CI upstream: invalid DNS question header")
 }
 offset:=12
 labels:=make([]string,0,8)
 for {
  if offset>=len(query){return nil,errors.New("CI upstream: truncated DNS name")}
  count:=int(query[offset]);offset++
  if count==0{break}
  if count>63 || (count&0xC0)!=0 || offset+count>len(query) {
   return nil,errors.New("CI upstream: invalid DNS name")
  }
  labels=append(labels,strings.ToLower(string(query[offset:offset+count])))
  offset+=count
  if offset>255{return nil,errors.New("CI upstream: oversized DNS name")}
 }
 if offset+4>len(query){return nil,errors.New("CI upstream: incomplete DNS question")}
 qtype:=binary.BigEndian.Uint16(query[offset:offset+2])
 qclass:=binary.BigEndian.Uint16(query[offset+2:offset+4])
 offset+=4
 reply:=append([]byte(nil),query[:offset]...)
 reply[2],reply[3]=0x81,0x80 // standard response, recursive available
 for i:=6;i<12;i++{reply[i]=0} // no unaudited answers, authority or OPT
 // A unique reserved .test name permits a cache-independent observation
 // through the real Windows configured resolver in the nested guest.
 // No external DNS lookup or production behavior is added.
 domain:=strings.Join(labels,".")
 allowedChallenge:=len(labels)==3 && len(labels[0])==32 && labels[1]=="volve-motor-ci" && labels[2]=="test"
 if allowedChallenge{
  for _,c:=range labels[0]{if !(c>='a'&&c<='f'||c>='0'&&c<='9'){allowedChallenge=false;break}}
 }
 if (domain=="example.org" || allowedChallenge) && qtype==1 && qclass==1 {
  reply[7]=1 // one actual A record, not merely NOERROR
  reply=append(reply,0xC0,0x0C,0,1,0,1,0,0,0,60,0,4,203,0,113,7)
 }
 return reply,nil
}

func runCIFreshDNS53(root,token string)error{
 return runCIFreshDNS53WithDuration(root,token,95*time.Second)
}
func runCIFreshDNS53WithDuration(root,token string,duration time.Duration)error{
 if duration<90*time.Second || duration>30*time.Minute {
  return errors.New("CI DNS53 test duration outside bounded laboratory window")
 }
 if err:=assertCIFreshVM(root,token);err!=nil{return err}
 // The scheduled task is intentionally restartable, like a real resident
 // installation. First launch prepares the full catalog; later starts verify
 // the exact same bytes and refuse any corruption before binding UDP/53.
 if info,err:=os.Lstat(root);err==nil {
  if !info.IsDir() || info.Mode()&os.ModeSymlink!=0{return errors.New("invalid existing lab root")}
  if err:=verifyCIFreshCatalog(root);err!=nil{return err}
 }else if os.IsNotExist(err) {
  if err:=writeCIFreshCatalog(root);err!=nil{return err}
 }else{return fmt.Errorf("cannot inspect lab root: %w",err)}
 upstream,err:=net.ListenPacket("udp4","127.0.0.1:0")
 if err!=nil{return err}
 defer upstream.Close()
 go func(){
  b:=make([]byte,2048)
  for{
   n,peer,e:=upstream.ReadFrom(b)
   if e!=nil{return}
   if n<12{continue}
   // The previous fixture set RCODE=NOERROR but returned zero records:
   // that was NOT evidence of a usable allowed-domain resolution.
   response,e:=ciFreshAllowedUpstreamResponse(b[:n])
   if e!=nil{continue}
   _,_=upstream.WriteTo(response,peer)
  }
 }()
 ctx,cancel:=context.WithTimeout(context.Background(),duration)
 defer cancel()
 // This is the same production entrypoint used by --dns-service:
 // real 400k+ catalog and IPv4/IPv6 UDP/TCP on LOCAL port 53.
 return runDNSServiceAt(ctx,root,53,[]string{upstream.LocalAddr().String()},nil)
}
