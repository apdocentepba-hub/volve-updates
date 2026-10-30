//go:build windows && volveci

package main

// CI-ONLY native executable extension. Not compiled into user releases.
// Runs the production dual-stack DNS service as the scheduled SYSTEM process
// on a disposable Windows VM. Never alters adapters, hosts or policy.
import (
 "bufio"
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
 if _,err:=os.Lstat(root);err==nil{return errors.New("existing test root: refusing overwrite")}
 if !os.IsNotExist(err){return fmt.Errorf("cannot verify test root: %w",err)}
 return nil
}

func writeCIFreshCatalog(root string)error{
 folder:=filepath.Join(root,"catalog","feeds")
 if err:=os.MkdirAll(folder,0700);err!=nil{return err}
 f,err:=os.OpenFile(filepath.Join(folder,"hagezi_gambling_full.txt"),
  os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 defer f.Close()
 w:=bufio.NewWriterSize(f,1<<20)
 for i:=0;i<400002;i++{
  if _,err:=fmt.Fprintf(w,"vm-ci-dns-%06d.bet.ar\n",i);err!=nil{return err}
 }
 for _,host:=range []string{"stake.com","betwarrior.bet.ar","www.betwarrior.bet.ar"}{
  if _,err:=fmt.Fprintln(w,host);err!=nil{return err}
 }
 if err:=w.Flush();err!=nil{return err}
 return f.Sync()
}

func runCIFreshDNS53(root,token string)error{
 if err:=assertCIFreshVM(root,token);err!=nil{return err}
 if err:=writeCIFreshCatalog(root);err!=nil{return err}
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
