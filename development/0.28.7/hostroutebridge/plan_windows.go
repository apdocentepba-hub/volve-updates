//go:build windows

package hostroutebridge

// Plan describes which future, separately authorized transaction could apply
// after a signed package + complete Windows census. It NEVER performs or
// authorizes any installation, DNS change, task change, repair or removal.
import (
    "context"
    "crypto/ed25519"
    "errors"

    motorupdate "volve-browser-protection/motorupdate"
)

type PlanMode string

const (
    PlanStop PlanMode = "STOP_HOST_STATE_UNVERIFIED"
    PlanFresh PlanMode = "REVIEW_NEW_INSTALL"
    PlanCatalog PlanMode = "REVIEW_CATALOG_PRESERVING_INSTALL"
    PlanLegacy PlanMode = "REVIEW_LEGACY_SIGNED_MIGRATION"
    PlanManaged PlanMode = "REVIEW_MANAGED_SIGNED_UPDATE"
    PlanRecovery PlanMode = "STOP_RECOVERY_MUST_FINISH_FIRST"
    PlanConflict PlanMode = "STOP_CONFLICTING_PROTECTION"
)

// InstallerPlanReadOnly is suitable only for display and audit. It is NEVER
// evidence of authorisation: no production mutator is allowed to consume this
// as a signed permit or a protected lock/rollback receipt.
type InstallerPlanReadOnly struct {
    Schema int `json:"schema"`
    TargetRelease string `json:"target_release"`
    Mode PlanMode `json:"mode"`
    HostRoute motorupdate.MotorInstallRoute `json:"host_route"`
    Prerequisites []string `json:"prerequisites"`
    Notes string `json:"notes"`
    CompleteHostInventories int `json:"complete_host_inventories"`
    BrowserPolicyLocationsChecked int `json:"browser_policy_locations_checked"`
    BrowserPolicyReviewRequired bool `json:"browser_policy_review_required"`
    SignedPackageVerified bool `json:"signed_package_verified"`
    CanInstall bool `json:"can_install"`
    CanUpgrade bool `json:"can_upgrade"`
    CanChangeDNS bool `json:"can_change_dns"`
    CanChangeTasks bool `json:"can_change_tasks"`
    Disposition string `json:"disposition"`
}

var mandatoryBeforeAnyMutation = []string{
    "genuine-production-publisher-authorization",
    "protected-exclusive-SYSTEM-admin-lock",
    "signed-original-and-recovery-snapshot",
    "durable-independent-boot-watchdog",
    "compatibility-and-live-state-recheck-under-lock",
    "native-NTFS-ACL-and-rollback-restart-evidence",
}

// PlanFromVerifiedReview only accepts a complete NON-AUTHORIZING review.
// Every plan remains blocked, even for a clean host; an independently signed
// release permit and a new privileged Windows transaction are still required.
func PlanFromVerifiedReview(ctx context.Context, review Review) (InstallerPlanReadOnly,error) {
    var rejected InstallerPlanReadOnly
    if ctx==nil { return rejected,errors.New("non-nil plan context required") }
    if err:=ctx.Err();err!=nil{return rejected,err}
    if review.Schema!=bridgeSchema ||
        review.Component!="installer-signed-bundle-windows-route-review" ||
        review.Status!="REVIEW_ONLY_NEVER_INSTALL_OR_MIGRATE" ||
        review.Release!=wantedRelease ||review.PackageParts!=7||
        !review.WindowsPublisherAndPackageVerified||
        review.InventoriesChecked!=6||
        review.BrowserPolicyLocationsChecked!=browserPolicyProbes||
        review.BrowserPolicyExistingLocations<0||
        review.BrowserPolicyExistingLocations>browserPolicyProbes||
        review.BrowserPolicyReviewRequired!=(review.BrowserPolicyExistingLocations>0)||
        (review.Route==motorupdate.MotorRouteFreshCandidate&&review.BrowserPolicyReviewRequired)||
        review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS||
        review.Reason=="" {
        return rejected,errors.New("unsigned, incomplete or privileged route review rejected")
    }
    var mode PlanMode
    var steps []string
    var notes string
    switch review.Route {
    case motorupdate.MotorRouteFreshCandidate:
        mode=PlanFresh
        steps=[]string{"verify-full-browser-policy-inventory","validate-signed-fresh-install-permit","preserve-original-DNS-and-adapter-inventory"}
        notes="A clean DNS census does not prove no browser policies exist; never replace existing protection silently."
    case motorupdate.MotorRouteCatalogCandidate:
        mode=PlanCatalog
        steps=[]string{"verify-catalog-task-signer-and-exact-action","preserve-existing-catalog-and-browser-policies","validate-signed-fresh-install-permit"}
        notes="Catalog-only means preserve the independently verified scheduled catalog task."
    case motorupdate.MotorRouteLegacyReview:
        mode=PlanLegacy
        steps=[]string{"attest-exact-legacy-exe-task-SYSTEM-and-port53","require-one-time-signed-legacy-to-0287-migration-permit-with-exact-origin-SHA256","prove-original-task-XML-and-motor-SHA256"}
        notes="Existing legacy motor must remain running until a separate authorized protected transition is ready."
    case motorupdate.MotorRouteManagedReview:
        mode=PlanManaged
        steps=[]string{"verify-installed-signed-motor-receipt","validate-version-compatibility-and-upgrade-lease","preserve-original-version-for-watchdog-rollback"}
        notes="Managed motor cannot be overwritten or reinstalled merely because a new signed bundle is present."
    case motorupdate.MotorRouteRecoveryReview:
        mode=PlanRecovery
        steps=[]string{"verify-legacy-recovery-journal-and-ACL","finish-or-audit-pending-recovery-before-any-new-transaction"}
        notes="Recovery artifacts are a hard stop even if their last recorded state looks terminal."
    case motorupdate.MotorRouteConflictingResidue:
        mode=PlanConflict
        steps=[]string{"audit-unexpected-Windows-task-service-DNS53-ownership","identify-original-protection-without-removing-files-or-DNS"}
        notes="Conflicting DNS/host state must never be treated as a clean installation."
    case motorupdate.MotorRouteUnverified:
        mode=PlanStop
        steps=[]string{"complete-privileged-six-inventory-Windows-inspection","reconcile-inconsistent-task-counts-and-identities"}
        notes="The installer must not make any decision from unverified or contradictory evidence."
    default:
        return rejected,errors.New("unknown host route rejected")
    }
    requirements:=make([]string,0,len(steps)+len(mandatoryBeforeAnyMutation))
    requirements=append(requirements,steps...)
    if review.BrowserPolicyReviewRequired {
        requirements=append(requirements,"audit-existing-GPO-and-owner-before-any-registry-mutation")
    }
    requirements=append(requirements,mandatoryBeforeAnyMutation...)
    if err:=ctx.Err();err!=nil{return rejected,err}
    return InstallerPlanReadOnly{
        Schema:1,TargetRelease:wantedRelease,
        Mode:mode,HostRoute:review.Route,
        Prerequisites:requirements,Notes:notes,
        CompleteHostInventories:6,SignedPackageVerified:true,
        BrowserPolicyLocationsChecked:review.BrowserPolicyLocationsChecked,
        BrowserPolicyReviewRequired:review.BrowserPolicyReviewRequired,
        CanInstall:false,CanUpgrade:false,CanChangeDNS:false,CanChangeTasks:false,
        Disposition:"READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT",
    },nil
}

// ReviewAndPlanReadOnly obtains the verified signed-package and native Windows
// state BEFORE deriving the display-only plan. Never accept caller-selected
// Fresh/Legacy mode or version strings as a substitute for host inspection.
func ReviewAndPlanReadOnly(ctx context.Context, inspect func(context.Context)(Review,error)) (Review,InstallerPlanReadOnly,error) {
    var zeroReview Review
    var zeroPlan InstallerPlanReadOnly
    if ctx==nil||inspect==nil {return zeroReview,zeroPlan,errors.New("native signed review callback required")}
    if err:=ctx.Err();err!=nil{return zeroReview,zeroPlan,err}
    review,err:=inspect(ctx)
    if err!=nil{return zeroReview,zeroPlan,err}
    plan,err:=PlanFromVerifiedReview(ctx,review)
    if err!=nil{return zeroReview,zeroPlan,err}
    return review,plan,nil
}


// InspectAndPlanWindowsHostReadOnly is the non-injectable one-call preview
// entrypoint for a future Setup UI. There is no route, version or permission
// selector parameter: the complete route must come from actual OS inspection
// after validation of the release EXE with independent publisher pins.
// Supplying an alternative reader is useful for CI but does not grant any
// installer capability or override a failed trust check.
func InspectAndPlanWindowsHostReadOnly(
    ctx context.Context,
    signedEXE string,
    publisherPublicKey ed25519.PublicKey,
    windowsSignerCertSHA256 string,
    signedEXESHA256 string,
    installedRoot string,
    readers motorupdate.WindowsMotorRouteInspectors,
) (Review,InstallerPlanReadOnly,error) {
    var rejectedReview Review
    var rejectedPlan InstallerPlanReadOnly
    if ctx==nil { return rejectedReview,rejectedPlan,errors.New("non-nil preview context required") }
    if err:=ctx.Err();err!=nil{return rejectedReview,rejectedPlan,err}
    report,err:=ReviewReadOnly(ctx,signedEXE,publisherPublicKey,
        windowsSignerCertSHA256,signedEXESHA256,installedRoot,readers)
    if err!=nil{return rejectedReview,rejectedPlan,err}
    plan,err:=PlanFromVerifiedReview(ctx,report)
    if err!=nil{return rejectedReview,rejectedPlan,err}
    return report,plan,nil
}
