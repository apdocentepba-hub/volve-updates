// CI-only staging logic. No execution, activation or production authority.
package main

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io/fs"
 "os"
 "path/filepath"
 "strings"
)

var capsuleNames = [...]string{
 "VOLVE-CI-ActualMotor.exe",
 "VOLVE-CI-ActualMotorProbe.test.exe",
 "ci_private_motor_integration.ps1",
}

func stageCapsule(root string, payload fs.FS, pins []string) error {
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||payload==nil||len(pins)!=len(capsuleNames){return errors.New("invalid capsule staging inputs")}
 dir,err:=os.Lstat(root)
 if err!=nil{return err}
 if !dir.IsDir()||dir.Mode()&os.ModeSymlink!=0{return errors.New("not a real staging directory")}
 entries,err:=fs.ReadDir(payload,".")
 if err!=nil{return err}
 if len(entries)!=len(capsuleNames){return errors.New("unexpected embedded payload count")}
 data:=make([][]byte,len(capsuleNames))
 for i,name:=range capsuleNames{
  expected,err:=hex.DecodeString(pins[i])
  if err!=nil||len(expected)!=sha256.Size||strings.ToUpper(pins[i])!=pins[i]{return errors.New("invalid external component pin")}
  fi,err:=fs.Stat(payload,name)
  if err!=nil{return err}
  if !fi.Mode().IsRegular()||fi.Size()<=0||fi.Size()>128<<20{return errors.New("invalid embedded component")}
  raw,err:=fs.ReadFile(payload,name)
  if err!=nil{return err}
  h:=sha256.Sum256(raw)
  if int64(len(raw))!=fi.Size()||strings.ToUpper(hex.EncodeToString(h[:]))!=pins[i]{return fmt.Errorf("embedded component hash mismatch: %s",name)}
  data[i]=raw
  if _,err=os.Lstat(filepath.Join(root,name));!os.IsNotExist(err){return fmt.Errorf("staging destination must be absent: %s",name)}
 }
 // Never overwrite an existing file, even if it appears after preflight.
 // On partial failure preserve the evidence in this disposable guest.
 // The host destroys the guest; a failed capsule must never be retried
 // into the same directory, nor recursively remove arbitrary paths.
 for i,name:=range capsuleNames{
  dest:=filepath.Join(root,name)
  f,err:=os.OpenFile(dest,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if err!=nil{return err}
  n,writeErr:=f.Write(data[i])
  syncErr:=f.Sync()
  closeErr:=f.Close()
  if err=errors.Join(writeErr,syncErr,closeErr);err!=nil{return err}
  if n!=len(data[i]){return errors.New("partial component write")}
  raw,err:=os.ReadFile(dest)
  if err!=nil{return err}
  digest:=sha256.Sum256(raw)
  if strings.ToUpper(hex.EncodeToString(digest[:]))!=pins[i]{return errors.New("staged component readback mismatch")}
 }
 return nil
}
