//go:build windows

// Package hostroutebridge links the two independent, read-only prerequisites
// of a future single-EXE VOLVE installer: release trust and Windows inventory.
// It never installs, activates, repairs, migrates or deletes any component.
package hostroutebridge

import (
    "context"
    "crypto/ed25519"
    "errors"
    "fmt"
    "os"
    "path/filepath"

    motorupdate "volve-browser-protection/motorupdate"
    singlefile "volve.local/installer/singlefile"
)

const (
    bridgeSchema = 1
    wantedRelease = "0.28.7"
    wantedPlatform = "windows-amd64"
)

// Review is deliberately NOT an installation permit, regardless of route.
// Browser policies, signed migration authorization, NTFS SYSTEM lease and
// durable recovery are intentionally not inferred from this census.
type Review struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    Release string `json:"release"`
    PackageParts int `json:"package_parts"`
    WindowsPublisherAndPackageVerified bool `json:"windows_publisher_and_package_verified"`
    InventoriesChecked int `json:"inventories_checked"`
    Route motorupdate.MotorInstallRoute `json:"route"`
    Reason string `json:"reason"`
    InstallAuthorized bool `json:"install_authorized"`
    UpgradeAuthorized bool `json:"upgrade_authorized"`
    CanModifyDNS bool `json:"can_modify_dns"`
    Status string `json:"status"`
}

// ReviewReadOnly first verifies the Windows Authenticode certificate and
// exact EXE SHA256 using EXTERNAL pins, then verifies the embedded Ed25519
// manifest. Only afterward does it run the project's existing six-inventory
// Windows host census (files, tasks, services, DNS, port53, recovery).
//
// Readers are explicit for test injection; a privileged production inspector
// would use DefaultWindowsMotorRouteInspectors. No authorization is returned.
func ReviewReadOnly(
    ctx context.Context,
    exe string,
    publisherKey ed25519.PublicKey,
    certDERHash string,
    exeHash string,
    trustedInstalledRoot string,
    readers motorupdate.WindowsMotorRouteInspectors,
) (Review,error) {
    var rejected Review
    if ctx == nil { return rejected,errors.New("review context is required") }
    if err := ctx.Err(); err != nil { return rejected,err }
    if len(publisherKey) != ed25519.PublicKeySize {
        return rejected,errors.New("external Ed25519 publisher key required")
    }
    if exe == "" || !filepath.IsAbs(exe) ||
       trustedInstalledRoot == "" || !filepath.IsAbs(trustedInstalledRoot) {
        return rejected,errors.New("absolute executable and installed-root paths are mandatory")
    }
    rootInfo,err := os.Lstat(trustedInstalledRoot)
    if err != nil { return rejected,fmt.Errorf("installed-root inventory unavailable: %w",err) }
    if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
        return rejected,errors.New("installed-root inventory cannot traverse a link")
    }
    if err := singlefile.VerifyWindowsPublisherSignature(ctx,exe,certDERHash,exeHash); err != nil {
        return rejected,fmt.Errorf("publisher trust rejected: %w",err)
    }
    manifest,err := singlefile.InspectExecutable(exe,publisherKey)
    if err != nil { return rejected,fmt.Errorf("complete signed bundle rejected: %w",err) }
    if manifest.Release != wantedRelease || manifest.Platform != wantedPlatform ||
       len(manifest.Components) != 8 {
        return rejected,errors.New("signed bundle is not complete VOLVE 0.28.7 Windows package")
    }
    if err := ctx.Err(); err != nil { return rejected,err }
    // Never label a catalog task verified merely because the filename matches:
    // no expected publisher-pinned catalog action is supplied here.
    route,err := motorupdate.InspectWindowsMotorRouteReadOnly(
        ctx,trustedInstalledRoot,"","",readers,
    )
    if err != nil { return rejected,fmt.Errorf("six-inventory Windows inspection failed: %w",err) }
    if err := motorupdate.RequireMotorRouteReviewOnly(route); err != nil {
        return rejected,fmt.Errorf("Windows inventory unexpectedly authorized writes: %w",err)
    }
    if route.InventoriesChecked != 6 {
        return rejected,errors.New("Windows route has incomplete privileged inventory")
    }
    if err := ctx.Err(); err != nil { return rejected,err }
    // The host census is not atomic with package verification. Recheck the
    // exact Authenticode-pinned bytes and signed Ed25519 component inventory
    // after all six Windows observations. If the EXE changed while an
    // inventory command was running, discard the ENTIRE review.
    if err := singlefile.VerifyWindowsPublisherSignature(ctx,exe,certDERHash,exeHash); err != nil {
        return rejected,fmt.Errorf("publisher file changed during Windows inventory: %w",err)
    }
    confirmed,err := singlefile.InspectExecutable(exe,publisherKey)
    if err != nil { return rejected,fmt.Errorf("signed bundle changed during Windows inventory: %w",err) }
    if confirmed.Release != manifest.Release || confirmed.Platform != manifest.Platform ||
       len(confirmed.Components) != len(manifest.Components) {
        return rejected,errors.New("signed manifest changed during Windows inventory")
    }
    if err := ctx.Err(); err != nil { return rejected,err }
    return Review{
        Schema:bridgeSchema,
        Component:"installer-signed-bundle-windows-route-review",
        Release:manifest.Release,
        PackageParts:len(manifest.Components),
        WindowsPublisherAndPackageVerified:true,
        InventoriesChecked:route.InventoriesChecked,
        Route:route.Route,
        Reason:route.Reason,
        InstallAuthorized:false,
        UpgradeAuthorized:false,
        CanModifyDNS:false,
        Status:"REVIEW_ONLY_NEVER_INSTALL_OR_MIGRATE",
    },nil
}
