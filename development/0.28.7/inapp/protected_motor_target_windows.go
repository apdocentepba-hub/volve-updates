//go:build windows

package main

// Native NTFS adapter for the create-only signed motor preparation. The
// installed root comes exclusively from the existing VOLVE state resolver,
// not from a downloaded manifest or UI field. No production caller exists:
// a future privileged transaction MUST first authenticate the publisher
// permit, acquire the shared SYSTEM mutex and arm independent recovery.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "time"

 "volve-browser-protection/motorupdate"
)

var protectedMotorVersionDirName=regexp.MustCompile(`^motor-([0-9]+)\.([0-9]+)\.([0-9]+)$`)

func pinnedProtectedMotorDestination(installedRoot,path string,rootAllowed bool)bool{
 if !filepath.IsAbs(installedRoot)||filepath.Clean(installedRoot)!=installedRoot||
  !filepath.IsAbs(path)||filepath.Clean(path)!=path{return false}
 inv:=filepath.Join(installedRoot,"installed-engines")
 if strings.EqualFold(path,inv){return rootAllowed}
 node:=path
 parent:=filepath.Dir(node)
 if strings.EqualFold(parent,inv){
  return protectedMotorVersionDirName.MatchString(filepath.Base(node))
 }
 dir:=parent
 if !strings.EqualFold(filepath.Dir(dir),inv){return false}
 matched:=protectedMotorVersionDirName.FindStringSubmatch(filepath.Base(dir))
 if matched==nil{return false}
 base:="VOLVE_DNS_Motor_"+matched[1]+"_"+matched[2]+"_"+matched[3]+".exe"
 filename:=filepath.Base(node)
 return filename==base||filename==base+".json"||filename==base+".sig"
}

// nativeProtectedMotorTargetOps binds the stage API's two callbacks to real
// SYSTEM+Administrators-only NTFS descriptors. The returned root must ALREADY
// exist with a trusted DACL; the adapter never creates it, starts a motor,
// changes scheduler tasks, writes a receipt or modifies the network.
func nativeProtectedMotorTargetOps()(string,motorupdate.ProtectedTargetFileOps,error){
 var empty motorupdate.ProtectedTargetFileOps
 if !isAdmin(){return "",empty,errors.New("motor target preparation requires elevated administrator")}
 installed,err:=installRoot()
 if err!=nil{return "",empty,fmt.Errorf("installed VOLVE root unavailable: %w",err)}
 return nativeProtectedMotorTargetOpsForRoot(installed)
}

// Native ACL verification is factored independently from the installed-root
// resolver so Windows CI can exercise the EXACT production DACL callbacks
// against a disposable temporary directory without impersonating an actual
// VOLVE installation or creating a productive motor.
func nativeProtectedMotorTargetOpsForRoot(installed string)(string,motorupdate.ProtectedTargetFileOps,error){
 var empty motorupdate.ProtectedTargetFileOps
 if !isAdmin(){return "",empty,errors.New("motor target preparation requires elevated administrator")}
 if !filepath.IsAbs(installed)||filepath.Clean(installed)!=installed{
  return "",empty,errors.New("installed motor root is not canonical")
 }
 root:=filepath.Join(installed,"installed-engines")
 verify:=func(node string)error{
  if !pinnedProtectedMotorDestination(installed,node,true){
   return errors.New("protected motor ACL target outside publisher-pinned engine tree")
  }
  info,err:=os.Lstat(node)
  if err!=nil{return err}
  if info.Mode()&os.ModeSymlink!=0||(!info.IsDir()&&!info.Mode().IsRegular()){
   return errors.New("motor NTFS node is a junction, symlink or special file")
  }
  ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
  defer cancel()
  result,err:=motorupdate.DefaultWindowsDNSProtectedACLInspect(ctx,node)
  if err!=nil{return fmt.Errorf("SYSTEM/Admin NTFS owner or protected DACL not verified: %w",err)}
  if !hasStandaloneRollbackToken(result,"VOLVE_DNS_RECOVERY_NTFS_ACL_VALID"){
   return errors.New("Windows protected motor ACL validation returned an ambiguous result")
  }
  return nil
 }
 ops:=motorupdate.ProtectedTargetFileOps{
  // Only the protected staging function may call SealNew, immediately after
  // successful Mkdir or O_EXCL; this function is NOT a general ACL fixer.
  SealNew:func(node string)error{
   if !pinnedProtectedMotorDestination(installed,node,false){
    return errors.New("motor ACL sealing outside new version directory or fixed signed bundle refused")
   }
   return sealNewProtectedRecoveryNode(node)
  },
  VerifyProtected:verify,
 }
 return root,ops,nil
}
