//go:build windows

package main

// CI-only executable. Never installs tasks, changes DNS, accesses product
// installation or grants privileges. A separate disposable Windows workflow
// invokes it both interactively (must reject) and as LocalSystem (must pass).
import (
 "errors"
 "context"
 "time"
 "fmt"
 "os"
 "os/user"
 "path/filepath"

 motorupdate "volve-ci-system-dns-readonly"
)

func run()error{
 if (len(os.Args)!=2&&len(os.Args)!=4)||!filepath.IsAbs(os.Args[1]){
  return errors.New("CI witness requires absolute path and optional sealed journal/snapshot")
 }
 if err:=motorupdate.VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{
  return fmt.Errorf("real Windows access token is not LocalSystem: %w",err)
 }
 current,err:=user.Current()
 if err!=nil{return err}
 if current.Uid!="S-1-5-18" {return errors.New("Windows SID changed unexpectedly")}
 // Security evidence is only written after the ACTUAL process token
 // was resolved to SID S-1-5-18 and, when requested, every filesystem
 // security descriptor passed the strict read-only Windows NTFS audit.
 marker:="VOLVE_CI_WINDOWS_SYSTEM_SID_S-1-5-18"
 if len(os.Args)==4 {
  ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
  defer cancel()
  journal,snapshot:=os.Args[2],os.Args[3]
  verify,err:=motorupdate.NewWindowsDNSProtectedACLVerifier(
   ctx,journal,snapshot,motorupdate.DefaultWindowsDNSProtectedACLInspect)
  if err!=nil{return fmt.Errorf("NTFS journal gate refused: %w",err)}
  for _,path:=range []string{
   filepath.Dir(journal),journal,
   filepath.Join(journal,motorupdate.ResidentIntentFile),snapshot,
  }{
   if err:=verify(path);err!=nil{return fmt.Errorf("real SYSTEM NTFS ACL rejected %s: %w",filepath.Base(path),err)}
  }
  marker="VOLVE_CI_WINDOWS_SYSTEM_SID_AND_SEALED_NTFS"
 }
 return os.WriteFile(os.Args[1],[]byte(marker),0600)
}

func main(){
 if err:=run();err!=nil{
  fmt.Fprintln(os.Stderr,err)
  os.Exit(83)
 }
 fmt.Println("PASS: Windows process token is real LocalSystem S-1-5-18")
}
