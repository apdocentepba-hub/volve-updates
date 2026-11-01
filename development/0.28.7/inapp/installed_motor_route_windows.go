//go:build windows

package main

// Explicit administrator-only, read-only Windows motor-path diagnosis.
// No download, task edit, network change, process launch or maintenance
// operation: the existing update button does NOT call this command.
import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "time"

 "volve-browser-protection/motorupdate"
)

type InstalledMotorRouteReport struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Decision motorupdate.MotorInstallRouteReport `json:"decision"`
 Notice string `json:"notice"`
}

func inspectInstalledMotorRouteReadOnly(ctx context.Context,installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
)(InstalledMotorRouteReport,error){
 var zero InstalledMotorRouteReport
 if err:=ctx.Err();err!=nil{return zero,err}
 // The catalog executable and exact arguments cannot be guessed from the
 // filename, version, or mutable Task Scheduler action. Until a future
 // publisher-pinned catalog definition is available, an observed catalog task
 // is intentionally UNVERIFIED, not evidence that a fresh install is safe.
 decision,err:=motorupdate.InspectWindowsMotorRouteReadOnly(ctx,installedRoot,"","",readers)
 if err!=nil{return zero,err}
 if err:=motorupdate.RequireMotorRouteReviewOnly(decision);err!=nil{return zero,err}
 return InstalledMotorRouteReport{
  Schema:1, Component:"dns-engine-install-route-audit-only",
  Decision:decision,
  Notice:"READ ONLY. This diagnosis neither proves browser policies nor authorizes DNS motor installation, upgrade, recovery or removal.",
 },nil
}

func printInstalledMotorRouteReadOnly() error {
 if !isAdmin(){return errors.New("Windows Administrator is required for full read-only inspection; no change was made")}
 root,err:=installRoot()
 if err!=nil{return fmt.Errorf("cannot resolve existing installation root: %w",err)}
 ctx,cancel:=context.WithTimeout(context.Background(),75*time.Second)
 defer cancel()
 output,err:=inspectInstalledMotorRouteReadOnly(ctx,root,motorupdate.DefaultWindowsMotorRouteInspectors())
 if err!=nil{return fmt.Errorf("Windows motor-path evidence incomplete; no changes made: %w",err)}
 raw,err:=json.MarshalIndent(output,"","  ")
 if err!=nil{return err}
 _,err=fmt.Fprintln(os.Stdout,string(raw))
 return err
}
