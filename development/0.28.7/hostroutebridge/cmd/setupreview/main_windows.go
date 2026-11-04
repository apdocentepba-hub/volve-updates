//go:build windows

// setupreview is the first executable, strictly READ-ONLY entrypoint for the
// future VOLVE single-file setup. It is deliberately CI-only until the actual
// publisher identity, SYSTEM installation transaction and boot rollback pass.
package main

import (
    "context"
    "crypto/ed25519"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "os"
    "strings"
    "time"

    motorupdate "volve-browser-protection/motorupdate"
    bridge "volve.local/installer/singlefile/hostroutebridge"
)

type report struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    Review bridge.Review `json:"review"`
    Plan bridge.InstallerPlanReadOnly `json:"plan"`
    ExecutableAction string `json:"executable_action"`
    ReleaseApproved bool `json:"release_approved"`
}

// execute NEVER installs, changes DNS, touches tasks or creates files. The
// Windows OS inventory is genuine; the CI publisher identity is ephemeral.
// This command must never be used as a production installation authorization.
func execute(ctx context.Context, args []string, output io.Writer) error {
    if ctx == nil || output == nil {
        return errors.New("context and output are required")
    }
    if err := ctx.Err(); err != nil { return err }
    if os.Getenv("GITHUB_ACTIONS") != "true" ||
       os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
        return errors.New("refused: disposable GitHub Windows CI required")
    }
    fs := flag.NewFlagSet("setupreview", flag.ContinueOnError)
    fs.SetOutput(io.Discard)
    exe := fs.String("exe", "", "signed CI-only single-file executable")
    pub := fs.String("pubkey", "", "independently supplied CI Ed25519 key")
    cert := fs.String("certsha", "", "independently supplied CI signer certificate SHA256")
    digest := fs.String("filehash", "", "independently supplied CI executable SHA256")
    root := fs.String("installed-root", "", "real Windows inventory root (must already exist)")
    if err := fs.Parse(args); err != nil { return fmt.Errorf("invalid preflight arguments: %w",err) }
    if fs.NArg()!=0 { return errors.New("extra arguments refused") }
    if *exe=="" || *root=="" || !hex64(*cert) || !hex64(*digest) {
        return errors.New("complete external publisher pins, EXE and root required")
    }
    key,err := hex.DecodeString(*pub)
    if err!=nil || len(key)!=ed25519.PublicKeySize {
        return errors.New("missing or invalid independently trusted Ed25519 key")
    }
    review, plan,err := bridge.InspectAndPlanWindowsHostReadOnly(
        ctx,*exe,ed25519.PublicKey(key),*cert,*digest,*root,
        motorupdate.DefaultWindowsMotorRouteInspectors(),
    )
    if err!=nil{return fmt.Errorf("signed Windows setup preview refused: %w",err)}
    // An inventory route is not a signed release permit. Fail closed if any
    // earlier layer ever changes this no-write contract without review.
    if review.InstallAuthorized || review.UpgradeAuthorized || review.CanModifyDNS ||
       plan.CanInstall || plan.CanUpgrade || plan.CanChangeDNS || plan.CanChangeTasks ||
       !review.WindowsPublisherAndPackageVerified || !plan.SignedPackageVerified ||
       review.InventoriesChecked!=6 || plan.CompleteHostInventories!=6 ||
       review.BrowserPolicyLocationsChecked!=14 ||
       plan.BrowserPolicyLocationsChecked!=14 ||
       review.BrowserPolicyReviewRequired!=plan.BrowserPolicyReviewRequired ||
       review.PackageParts!=7 || plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT" {
        return errors.New("critical: preview attempted to authorize product mutation")
    }
    return json.NewEncoder(output).Encode(report{
        Schema:1,Component:"volve-0287-windows-setup-preflight-ci",
        Review:review,Plan:plan,
        ExecutableAction:"NONE_REVIEW_ONLY_NO_INSTALL_NO_DNS_NO_TASKS",
        ReleaseApproved:false,
    })
}
func hex64(s string) bool {
    if len(s)!=64 || strings.ToLower(s)!=s{return false}
    _,err:=hex.DecodeString(s);return err==nil
}
func main(){
    ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second)
    defer cancel()
    if err:=execute(ctx,os.Args[1:],os.Stdout);err!=nil{
        fmt.Fprintln(os.Stderr,"VOLVE_SETUP_PREFLIGHT_REFUSED:",err)
        os.Exit(1)
    }
}
