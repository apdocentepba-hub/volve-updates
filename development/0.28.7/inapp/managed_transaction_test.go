package motorupdate

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"
)

type managedDriverTest struct {
    calls []string
    fail string
    cancel context.CancelFunc
    rollbackCancelled bool
}
func (d *managedDriverTest) tick(step string) error {
    d.calls = append(d.calls, step)
    if d.fail == step { return errors.New("simulated " + step + " failure") }
    return nil
}
func (d *managedDriverTest) Preflight(context.Context, Manifest) error { return d.tick("preflight") }
func (d *managedDriverTest) Snapshot(context.Context) error { return d.tick("snapshot") }
func (d *managedDriverTest) InstallVersionedCandidate(context.Context, string) error { return d.tick("install") }
func (d *managedDriverTest) Switch(context.Context) error {
    err := d.tick("switch")
    if d.cancel != nil {d.cancel()}
    return err
}
func (d *managedDriverTest) Probe(context.Context) error { return d.tick("probe") }
func (d *managedDriverTest) ProbeConnectivity(context.Context) error {return d.tick("connectivity")}
func (d *managedDriverTest) Commit(context.Context, Manifest) error {return d.tick("commit")}
func (d *managedDriverTest) Restore(ctx context.Context) error {
    if ctx.Err()!=nil {d.rollbackCancelled=true}
    return d.tick("restore")
}

func signedManagedFixture(t *testing.T) (string, ed25519.PublicKey) {
    t.Helper()
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    payload := []byte("MZ_test_signed_candidate_not_an_executable")
    digest := sha256.Sum256(payload)
    m := Manifest{
        Schema:1, Component:"dns-engine", Version:"0.28.7",
        MinPanelVersion:"0.28.7",
        URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
        SHA256:hex.EncodeToString(digest[:]), Size:int64(len(payload)),
        Notes:"managed contract fixture",
    }
    raw, err := json.Marshal(m)
    if err != nil { t.Fatal(err) }
    path := filepath.Join(t.TempDir(), "VOLVE_DNS_Motor_0_28_7.exe")
    if err := os.WriteFile(path,payload,0600);err != nil { t.Fatal(err) }
    if err := os.WriteFile(path+".json",raw,0600);err != nil { t.Fatal(err) }
    if err := os.WriteFile(path+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw))),0600);err != nil { t.Fatal(err) }
    return path,pub
}

func TestManagedUpgradeCommitOnlyAfterBothProbes(t *testing.T) {
    path,pub := signedManagedFixture(t)
    d:= &managedDriverTest{}
    if err:=ApplyManagedWithRollback(context.Background(),path,pub,"0.27.0","0.28.7",d);err!=nil {t.Fatal(err)}
    want:=[]string{"preflight","snapshot","install","switch","probe","connectivity","commit"}
    if !reflect.DeepEqual(d.calls,want) {t.Fatalf("unexpected order %#v",d.calls)}
}

func TestManagedUpgradeRollsBackAfterEveryPostSnapshotFailure(t *testing.T) {
    path,pub := signedManagedFixture(t)
    for _,step:=range []string{"install","switch","probe","connectivity","commit"}{
        t.Run(step,func(t *testing.T){
            d:=&managedDriverTest{fail:step}
            err:=ApplyManagedWithRollback(context.Background(),path,pub,"0.27.0","0.28.7",d)
            if err==nil || !strings.Contains(err.Error(),"simulated "+step+" failure"){t.Fatalf("failure not surfaced: %v",err)}
            found:=false
            for _,call:=range d.calls {if call=="restore" {found=true}}
            if !found {t.Fatalf("rollback not attempted for %s: %#v",step,d.calls)}
            if step!="commit" {
                for _,call:=range d.calls {if call=="commit" {t.Fatalf("committed after %s failed",step)}}
            }
        })
    }
}

func TestManagedUpgradeRejectsPreflightBeforeSwitch(t *testing.T) {
    path,pub:=signedManagedFixture(t)
    for _,step:=range []string{"preflight","snapshot"} {
        d:=&managedDriverTest{fail:step}
        if err:=ApplyManagedWithRollback(context.Background(),path,pub,"0.27.0","0.28.7",d);err==nil {t.Fatal("expected error")}
        if len(d.calls)>2 {t.Fatalf("mutation after %s failure: %#v",step,d.calls)}
    }
}

func TestManagedUpgradeRejectsTamperingBeforeDriverCall(t *testing.T) {
    path,pub:=signedManagedFixture(t)
    if err:=os.WriteFile(path,[]byte("altered"),0600);err!=nil {t.Fatal(err)}
    d:=&managedDriverTest{}
    if err:=ApplyManagedWithRollback(context.Background(),path,pub,"0.27.0","0.28.7",d);err==nil {t.Fatal("tampered candidate accepted")}
    if len(d.calls)>0 {t.Fatalf("driver called for unauthenticated input: %#v",d.calls)}
}

func TestManagedUpgradeRejectsUnknownLegacyVersion(t *testing.T) {
    path,pub:=signedManagedFixture(t)
    d:=&managedDriverTest{}
    if err:=ApplyManagedWithRollback(context.Background(),path,pub,"","0.28.7",d);err==nil {t.Fatal("unknown motor version was accepted")}
    if len(d.calls)!=0 {t.Fatalf("driver invoked without motor identity: %#v",d.calls)}
}

func TestManagedUpgradeRollbackUsesIndependentContextAfterCancellation(t *testing.T) {
    path,pub:=signedManagedFixture(t)
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    d:=&managedDriverTest{cancel:cancel}
    err:=ApplyManagedWithRollback(ctx,path,pub,"0.27.0","0.28.7",d)
    if err==nil {t.Fatal("cancelled upgrade reported success")}
    if d.rollbackCancelled {t.Fatal("rollback reused cancelled context")}
    found:=false
    for _,call:=range d.calls { if call=="restore" {found=true} }
    if !found {t.Fatalf("no rollback on cancellation: %#v",d.calls)}
}
