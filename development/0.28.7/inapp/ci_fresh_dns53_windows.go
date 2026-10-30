//go:build windows && volveci

package main

// CI-ONLY native executable extension. Not compiled into user releases.
// Runs the production dual-stack DNS service as the scheduled SYSTEM process
// on a disposable Windows VM. Never alters adapters, hosts or policy.
import (
 "bufio"
 "crypto/sha256"
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
 if len(os.Args)<2 || os.Args[1]!="--ci-fresh-dns53"{return}
 if len(os.Args)!=4{fmt.Fprintln(os.Stderr,"CI DNS53: invalid arguments");os.Exit(2)}
 if err:=runCIFreshDNS53(os.Args[2],os.Args[3]);err!=nil{
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

func runCIFreshDNS53(root,token string)error{
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
   response:=append([]byte(nil),b[:n]...)
   response[2],response[3]=0x81,0x80
   _,_=upstream.WriteTo(response,peer)
  }
 }()
 ctx,cancel:=context.WithTimeout(context.Background(),95*time.Second)
 defer cancel()
 // This is the same production entrypoint used by --dns-service:
 // real 400k+ catalog and IPv4/IPv6 UDP/TCP on LOCAL port 53.
 return runDNSServiceAt(ctx,root,53,[]string{upstream.LocalAddr().String()},nil)
}
