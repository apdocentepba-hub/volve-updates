//go:build windows

package hostroutebridge

import (
    "context"
    "crypto/ed25519"
    "encoding/hex"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    motorupdate "volve-browser-protection/motorupdate"
)

type signedWindowsLab struct {
    exe string
    key ed25519.PublicKey
    certPin string
    exePin string
}

func labEvidence(t *testing.T) signedWindowsLab {
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS") != "true" ||
       os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
        t.Skip("only disposable GitHub Windows CI has synthetic signing fixtures")
    }
    env := func(name string) string {
        value := os.Getenv(name)
        if value == "" { t.Fatalf("mandatory signed Windows CI fixture missing: %s",name) }
        return value
    }
    key,err := hex.DecodeString(env("VOLVE_CI_ED25519_PUB"))
    if err != nil || len(key) != ed25519.PublicKeySize { t.Fatal("invalid signed fixture key") }
    return signedWindowsLab{
        exe:env("VOLVE_CI_AUTHENTICODE_OS_BINARY"),
        key:ed25519.PublicKey(key),
        certPin:env("VOLVE_CI_AUTHENTICODE_CERT_SHA256"),
        exePin:env("VOLVE_CI_AUTHENTICODE_FILE_SHA256"),
    }
}

func TestSixInventoryActualWindowsBridgeOnlyReturnsReview(t *testing.T) {
    fixture := labEvidence(t)
    ctx,cancel := context.WithTimeout(context.Background(),90*time.Second)
    defer cancel()
    root := t.TempDir() // no production VOLVE root, but real Windows inventories
    review,err := ReviewReadOnly(ctx,fixture.exe,fixture.key,
        fixture.certPin,fixture.exePin,root,motorupdate.DefaultWindowsMotorRouteInspectors())
    if err != nil {t.Fatal(err)}
    if review.Schema!=1||review.Release!="0.28.7"||review.PackageParts!=8||
        !review.WindowsPublisherAndPackageVerified||review.InventoriesChecked!=6 {
        t.Fatalf("dual-signature or real six-inventory proof incomplete: %+v",review)
    }
    if review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS||
        review.Status!="REVIEW_ONLY_NEVER_INSTALL_OR_MIGRATE"||
        review.Route=="" || review.Reason=="" {
        t.Fatalf("bridge made an unsafe product decision: %+v",review)
    }
    t.Logf("PASS VOLVE_BUNDLE_PLUS_6_WINDOWS_INVENTORIES route=%s NO_INSTALL NO_DNS_CHANGE",review.Route)
}

func TestSignedBridgeRefusesWrongPinsAndMissingInventory(t *testing.T) {
    fixture := labEvidence(t)
    ctx,cancel := context.WithTimeout(context.Background(),90*time.Second)
    defer cancel()
    root := t.TempDir()
    wrong := strings.Repeat("0",64)
    if wrong==fixture.certPin {wrong=strings.Repeat("1",64)}
    allReaders := motorupdate.DefaultWindowsMotorRouteInspectors()
    // All negative tests must return NO report at all. They may not fall back
    // to a "fresh installation" route or substitute an unverified inventory.
    attempts := []struct {
        name string
        exe string
        key ed25519.PublicKey
        cert string
        file string
        installedRoot string
        readers motorupdate.WindowsMotorRouteInspectors
    }{
        {"wrong-publisher",fixture.exe,fixture.key,wrong,fixture.exePin,root,allReaders},
        {"wrong-EXE",fixture.exe,fixture.key,fixture.certPin,wrong,root,allReaders},
        {"wrong-Ed25519",fixture.exe,ed25519.PublicKey(make([]byte,32)),fixture.certPin,fixture.exePin,root,allReaders},
        {"missing-root",fixture.exe,fixture.key,fixture.certPin,fixture.exePin,filepath.Join(root,"missing"),allReaders},
        {"missing-port53-inspector",fixture.exe,fixture.key,fixture.certPin,fixture.exePin,root,motorupdate.WindowsMotorRouteInspectors{}},
    }
    for _,tc := range attempts {
        t.Run(tc.name,func(t *testing.T){
            review,err := ReviewReadOnly(ctx,tc.exe,tc.key,tc.cert,tc.file,tc.installedRoot,tc.readers)
            if err==nil||review.Component!=""||review.WindowsPublisherAndPackageVerified||
                review.InventoriesChecked!=0||review.Route!=""||review.CanModifyDNS {
                t.Fatalf("unsafe or partial review returned: %+v, err=%v",review,err)
            }
        })
    }
}

func TestSignedBridgeRejectsCancellationAndRelativePath(t *testing.T) {
    fixture := labEvidence(t)
    ctx,cancel := context.WithCancel(context.Background())
    cancel()
    review,err := ReviewReadOnly(ctx,fixture.exe,fixture.key,fixture.certPin,fixture.exePin,
        t.TempDir(),motorupdate.DefaultWindowsMotorRouteInspectors())
    if err==nil||review.Component!=""{t.Fatalf("cancelled inspection produced report: %+v",review)}
    review,err=ReviewReadOnly(context.Background(),"relative.exe",fixture.key,
        fixture.certPin,fixture.exePin,t.TempDir(),motorupdate.DefaultWindowsMotorRouteInspectors())
    if err==nil||review.Component!=""{t.Fatalf("relative PE allowed: %+v",review)}
}
