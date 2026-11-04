// Command mixedbundle is only a Windows GitHub-hosted CI evidence gate.
// It embeds two CI-built executable files and a pinned HISTORIC motor into
// an INACTIVE, partially synthetic test bundle. Never distribute its output.
package main
import(
 "context"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "runtime"
 "time"
 mixed "volve.local/installer/realmaterialslab"
)
func main(){
 centro:=flag.String("centro","","actual native Centro built in same CI job")
 watchdog:=flag.String("watchdog","","actual independent watchdog built in same CI job")
 motor:=flag.String("historic-motor","","pinned 0.28.7 historic DNS motor, not the final setup")
 sidecar:=flag.String("motor-manifest","","publisher-signed old motor manifest")
 signature:=flag.String("motor-signature","","publisher-signed old motor signature")
 audit:=flag.String("audit","","independent audit of 2 real CI builds + 1 historic motor")
 root:=flag.String("out","","fresh CI-only real-file mixed signing root")
 inactive:=flag.String("inactive","","fresh CI-only inactive version")
 flag.Parse()
 temp:=os.Getenv("RUNNER_TEMP")
 if runtime.GOOS!="windows"||os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||temp==""||
  *root!=filepath.Join(temp,"VOLVE-CI-MIXED-REAL-5")||
  *inactive!=filepath.Join(temp,"VOLVE-CI-VERSION-0287-MIXED"){
  fmt.Fprintln(os.Stderr,"REFUSED: trusted hosted disposable Windows CI and exact temporary paths required")
  os.Exit(2)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 result,err:=mixed.BuildMixedLab(ctx,mixed.Sources{
  Centro:*centro,Watchdog:*watchdog,Motor:*motor,MotorManifest:*sidecar,MotorSignature:*signature,
  AuditJSON:*audit,Root:*root,Inactive:*inactive,
 })
 if err!=nil{fmt.Fprintln(os.Stderr,"REFUSED: cannot bind real Windows materials:",err);os.Exit(1)}
 if result.AssetsFromRealSources!=5||result.AssetsSynthetic!=2||result.RealPEFiles!=3||
  result.StagedComponents!=7||result.ApprovedForRelease{
  fmt.Fprintln(os.Stderr,"CRITICAL: mixed CI material classification changed");os.Exit(1)
 }
 fmt.Printf("PASS VOLVE_REAL_MATERIALS_MIXED_CI_INACTIVE_STAGE actual_source_files=%d synthetic_roles=%d native_PE=%d total=%d RELEASE_APPROVED=false NO_INSTALL NO_DNS NO_TASKS\n",
  result.AssetsFromRealSources,result.AssetsSynthetic,result.RealPEFiles,result.StagedComponents)
}
