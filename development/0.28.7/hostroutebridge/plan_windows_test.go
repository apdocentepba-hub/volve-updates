//go:build windows

package hostroutebridge

import (
    "context"
    "strings"
    "testing"

    motorupdate "volve-browser-protection/motorupdate"
)

func safeReview(route motorupdate.MotorInstallRoute) Review {
    return Review{
        Schema:bridgeSchema,
        Component:"installer-signed-bundle-windows-route-review",
        Release:wantedRelease,PackageParts:7,
        WindowsPublisherAndPackageVerified:true,
        InventoriesChecked:6,
        BrowserPolicyLocationsChecked:browserPolicyProbes,
        BrowserPolicyExistingLocations:0,
        BrowserPolicyReviewRequired:false,
        Route:route,
        Reason:"independently read-only classified Windows host",
        InstallAuthorized:false,UpgradeAuthorized:false,CanModifyDNS:false,
        Status:"REVIEW_ONLY_NEVER_INSTALL_OR_MIGRATE",
    }
}

func TestAllWindowsInstallRoutesHaveNonAuthorizingPlans(t *testing.T) {
    cases:=[]struct{
        route motorupdate.MotorInstallRoute
        mode PlanMode
        mustInclude string
    }{
        {motorupdate.MotorRouteFreshCandidate,PlanFresh,"validate-signed-fresh-install-permit"},
        {motorupdate.MotorRouteCatalogCandidate,PlanCatalog,"preserve-existing-catalog-and-browser-policies"},
        {motorupdate.MotorRouteLegacyReview,PlanLegacy,"require-one-time-signed-legacy-to-0287-migration-permit-with-exact-origin-SHA256"},
        {motorupdate.MotorRouteManagedReview,PlanManaged,"verify-installed-signed-motor-receipt"},
        {motorupdate.MotorRouteRecoveryReview,PlanRecovery,"finish-or-audit-pending-recovery-before-any-new-transaction"},
        {motorupdate.MotorRouteConflictingResidue,PlanConflict,"audit-unexpected-Windows-task-service-DNS53-ownership"},
        {motorupdate.MotorRouteUnverified,PlanStop,"complete-privileged-six-inventory-Windows-inspection"},
    }
    for _,tc:=range cases {
        t.Run(string(tc.route),func(t *testing.T) {
            plan,err:=PlanFromVerifiedReview(context.Background(),safeReview(tc.route))
            if err!=nil{t.Fatal(err)}
            if plan.Mode!=tc.mode||plan.HostRoute!=tc.route||plan.TargetRelease!="0.28.7"||
                plan.CompleteHostInventories!=6||!plan.SignedPackageVerified||
                plan.CanInstall||plan.CanUpgrade||plan.CanChangeDNS||plan.CanChangeTasks||
                plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT" {
                t.Fatalf("route plan changed state or made an unauthorized decision: %+v",plan)
            }
            if len(plan.Prerequisites)<7{t.Fatalf("missing mandatory full-safety requirements: %+v",plan)}
            found:=false
            for _,v:=range plan.Prerequisites {
                if v==tc.mustInclude {found=true}
            }
            if !found{t.Fatalf("route-specific requirement %q absent in %v",tc.mustInclude,plan.Prerequisites)}
            if plan.Notes==""{t.Fatal("planning route must explain risk")}
        })
    }
}

func TestRoutePlanRejectsUnsignedIncompleteOrForgedReviews(t *testing.T) {
    cases:=[]struct{name string;change func(*Review)}{
        {"no-cert-or-bundle-proof",func(r *Review){r.WindowsPublisherAndPackageVerified=false}},
        {"missing-inventory",func(r *Review){r.InventoriesChecked=5}},
        {"wrong-release",func(r *Review){r.Release="0.28.6"}},
        {"missing-components",func(r *Review){r.PackageParts=6}},
        {"foreign-schema",func(r *Review){r.Schema=9}},
        {"wrong-review-type",func(r *Review){r.Component="untrusted"}},
        {"client-selected-action",func(r *Review){r.InstallAuthorized=true}},
        {"client-selected-upgrade",func(r *Review){r.UpgradeAuthorized=true}},
        {"client-selected-DNS",func(r *Review){r.CanModifyDNS=true}},
        {"status-not-read-only",func(r *Review){r.Status="ALLOW_INSTALL"}},
        {"reason-absent",func(r *Review){r.Reason=""}},
        {"unknown-route",func(r *Review){r.Route="fresh-confirmed-no-census"}},
        {"no-browser-census",func(r *Review){r.BrowserPolicyLocationsChecked=0}},
        {"unowned-browser-policy-fresh",func(r *Review){r.BrowserPolicyExistingLocations=1;r.BrowserPolicyReviewRequired=true}},
        {"inconsistent-browser-hits",func(r *Review){r.BrowserPolicyExistingLocations=1}},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            review:=safeReview(motorupdate.MotorRouteFreshCandidate)
            tc.change(&review)
            plan,err:=PlanFromVerifiedReview(context.Background(),review)
            if err==nil||plan.Mode!=""||plan.CanInstall||len(plan.Prerequisites)!=0{
                t.Fatalf("forged/incomplete review yielded plan: %+v, %v",plan,err)
            }
        })
    }
}

func TestRoutePlanRequiresContextAndVerifiedCallback(t *testing.T){
    review:=safeReview(motorupdate.MotorRouteLegacyReview)
    if p,err:=PlanFromVerifiedReview(nil,review);err==nil||p.Mode!=""{
        t.Fatalf("nil context accepted: %+v, %v",p,err)
    }
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if p,err:=PlanFromVerifiedReview(ctx,review);err==nil||p.Mode!=""{
        t.Fatalf("cancelled context accepted: %+v, %v",p,err)
    }
    _,plan,err:=ReviewAndPlanReadOnly(context.Background(),nil)
    if err==nil||plan.Mode!=""{t.Fatal("missing review callback accepted")}
    _,plan,err=ReviewAndPlanReadOnly(context.Background(),func(context.Context)(Review,error){
        return Review{Route:motorupdate.MotorRouteFreshCandidate},nil
    })
    if err==nil||plan.Mode!=""{t.Fatal("unverified upstream fresh route accepted")}
    _,plan,err=ReviewAndPlanReadOnly(context.Background(),func(context.Context)(Review,error){
        return safeReview(motorupdate.MotorRouteLegacyReview),nil
    })
    if err!=nil||plan.Mode!=PlanLegacy||plan.CanUpgrade{t.Fatalf("publisher review plan failed: %+v, %v",plan,err)}
}

func TestRoutePlanNeverConfusesLegacyWithFresh(t *testing.T) {
    plan,err:=PlanFromVerifiedReview(context.Background(),safeReview(motorupdate.MotorRouteLegacyReview))
    if err!=nil{t.Fatal(err)}
    if plan.Mode==PlanFresh||plan.Mode==PlanCatalog||plan.CanInstall{t.Fatal("legacy route treated as clean")}
    requirements:=strings.Join(plan.Prerequisites," ")
    if !strings.Contains(requirements,"exact-origin-SHA256")||!strings.Contains(requirements,"signed-original-and-recovery-snapshot"){
        t.Fatal("legacy migration missing strong original identity and rollback requirements")
    }
}
