//go:build linux || darwin || freebsd

package signedstage

// CI-only advisory OS file locks are kernel-released if the owning process
// exits unexpectedly. The persistent lock pathname is never treated as a
// recovered transaction; no installed VOLVE files are touched.
import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
)

func acquireStageLock(destination string)(func(),error){
 sum:=sha256.Sum256([]byte(destination))
 path:=filepath.Join(filepath.Dir(destination),".VOLVE-CI-0287-stage-"+hex.EncodeToString(sum[:])+".lock")
 info,err:=os.Lstat(path)
 if err==nil {
  if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0{return nil,errors.New("unsafe CI staging lock pathname")}
 } else if !os.IsNotExist(err) {return nil,err}
 file,err:=os.OpenFile(path,os.O_CREATE|os.O_RDWR,0600)
 if err!=nil{return nil,err}
 after,err:=file.Stat()
 if err!=nil||!after.Mode().IsRegular(){
  file.Close()
  return nil,errors.New("unsafe opened CI stage lock file")
 }
 if err:=syscall.Flock(int(file.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);err!=nil{
  file.Close()
  return nil,fmt.Errorf("another inactive CI stage or recovery owns mutex: %w",err)
 }
 return func(){_ = syscall.Flock(int(file.Fd()),syscall.LOCK_UN);_ = file.Close()},nil
}
