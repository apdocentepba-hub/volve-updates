//go:build windows

package main

// CI-only executable. Never installs tasks, changes DNS, accesses product
// installation or grants privileges. A separate disposable Windows workflow
// invokes it both interactively (must reject) and as LocalSystem (must pass).
import (
 "errors"
 "fmt"
 "os"
 "os/user"
 "path/filepath"

 motorupdate "volve-ci-system-dns-readonly"
)

func run()error{
 if len(os.Args)!=2||!filepath.IsAbs(os.Args[1]){
  return errors.New("CI witness path must be absolute")
 }
 if err:=motorupdate.VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{
  return fmt.Errorf("real Windows access token is not LocalSystem: %w",err)
 }
 current,err:=user.Current()
 if err!=nil{return err}
 if current.Uid!="S-1-5-18" {return errors.New("Windows SID changed unexpectedly")}
 // The security witness is only written after the *actual process token*
 // was independently resolved to SID S-1-5-18.
 return os.WriteFile(os.Args[1],[]byte("VOLVE_CI_WINDOWS_SYSTEM_SID_S-1-5-18"),0600)
}

func main(){
 if err:=run();err!=nil{
  fmt.Fprintln(os.Stderr,err)
  os.Exit(83)
 }
 fmt.Println("PASS: Windows process token is real LocalSystem S-1-5-18")
}
