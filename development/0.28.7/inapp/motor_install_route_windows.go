//go:build windows

package motorupdate

import (
 "context"
 "errors"
)

// WindowsMotorRouteInspectors supplies the six independent non-mutating
// readers. Production always supplies the DefaultWindowsFresh* inspectors;
// injected functions exist solely for isolated tests.
type WindowsMotorRouteInspectors struct {
 Host WindowsFreshPartialHostInspectors
 Port53 WindowsFreshPort53Inspect
 RecoveryACL WindowsFreshRecoveryACLInspect
}

// InspectWindowsMotorRouteReadOnly does not infer signed identity from a
// filename or classify browser-policy protection as absent. No action
// switches, starts, disables, repairs, registers or deletes anything.
func InspectWindowsMotorRouteReadOnly(
 ctx context.Context, trustedInstalledRoot, expectedCatalogExe, expectedCatalogArgs string,
 readers WindowsMotorRouteInspectors,
)(MotorInstallRouteReport,error){
 var zero MotorInstallRouteReport
 if err:=ctx.Err();err!=nil{return zero,err}
 if trustedInstalledRoot=="" || readers.Port53==nil || readers.RecoveryACL==nil {
  return zero,errors.New("trusted installed root, port53 and recovery inspectors are required")
 }
 census,err:=InspectWindowsFreshSixOfSixReadOnly(ctx,trustedInstalledRoot,
  expectedCatalogExe,expectedCatalogArgs,readers.Host,readers.Port53,readers.RecoveryACL)
 if err!=nil{return zero,err}
 e:=census.Host.Host.Host.Evidence
 unknownTasks:=census.Host.Host.Host.TaskNames
 route,err:=ClassifyMotorInstallRouteReadOnly(ctx,e,unknownTasks)
 if err!=nil{return zero,err}
 if err:=RequireMotorRouteReviewOnly(route);err!=nil{return zero,err}
 return route,nil
}

func DefaultWindowsMotorRouteInspectors()WindowsMotorRouteInspectors{
 return WindowsMotorRouteInspectors{
  Host:WindowsFreshPartialHostInspectors{
   Admin:DefaultWindowsFreshAdminInspect,
   Tasks:DefaultWindowsFreshTaskInspect,
   Services:DefaultWindowsFreshServiceInspect,
   DNS:DefaultWindowsFreshDNSAdapterInspect,
  },
  Port53:DefaultWindowsFreshPort53Inspect,
  RecoveryACL:DefaultWindowsFreshRecoveryACLInspect,
 }
}
