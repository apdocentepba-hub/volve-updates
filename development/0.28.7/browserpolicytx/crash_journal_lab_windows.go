//go:build windows

package browserpolicytx

// This is a CI-only, cross-PROCESS crash recovery experiment against the
// disposable HKCU VOLVE-CI Registry namespace. A durable JSON record is
// created AND flushed BEFORE a child process writes test values and exits.
// It is not a product journal, an installation permission or a SYSTEM driver.
import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
)

type LabIntent struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    RegistryRoot string `json:"registry_root"`
    PlanSHA256 string `json:"plan_sha256"`
    Policy Plan `json:"policy"`
}
type LabRecoveryResult struct {
    Checked int `json:"checked"`
    Reverted int `json:"reverted"`
    Status string `json:"status"`
    InstallAuthorized bool `json:"install_authorized"`
}

func labRootFromEnvironment()(string,error){
    run,attempt:=os.Getenv("GITHUB_RUN_ID"),os.Getenv("GITHUB_RUN_ATTEMPT")
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
        !numberOnly.MatchString(run)||!numberOnly.MatchString(attempt) {
        return "",errors.New("cross-process recovery only allowed in disposable hosted Windows CI")
    }
    return `SOFTWARE\VOLVE-CI-BrowserPolicies-`+run+"-"+attempt,nil
}
func checkLabJournalLocation(path string)error {
    if !filepath.IsAbs(path)||filepath.Ext(path)!=".json"{
        return errors.New("absolute test journal .json path required")
    }
    base:=os.TempDir()
    rel,err:=filepath.Rel(base,filepath.Clean(path))
    if err!=nil||rel=="."||rel==".."||strings.HasPrefix(rel,".."+string(filepath.Separator)){
        return errors.New("CI journal must stay within disposable OS temp directory")
    }
    st,err:=os.Lstat(filepath.Dir(path))
    if err!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0 {
        return errors.New("journal parent unavailable or redirected")
    }
    return nil
}
func createLabIntentDurable(path string,store *WindowsRegistryLab,plan Plan)error {
    expected,err:=labRootFromEnvironment();if err!=nil{return err}
    if store==nil||store.closed||store.root!=expected{return errors.New("unexpected test registry root")}
    if err:=checkLabJournalLocation(path);err!=nil{return err}
    if err:=Validate(plan);err!=nil{return err}
    raw,err:=json.Marshal(plan);if err!=nil{return err}
    sum:=sha256.Sum256(raw)
    intent:=LabIntent{Schema:1,Component:"VOLVE-CI-browser-policy-crash-recovery",
        RegistryRoot:expected,PlanSHA256:hex.EncodeToString(sum[:]),Policy:plan}
    content,err:=json.Marshal(intent);if err!=nil{return err}
    if len(content)>1<<20{return errors.New("test recovery intent too large")}
    file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
    if err!=nil{return err}
    // On sync failure never proceed to any test writes.
    if _,err=file.Write(content);err!=nil{file.Close();return err}
    if err=file.Sync();err!=nil{file.Close();return err}
    return file.Close()
}
func readLabIntent(path string,store *WindowsRegistryLab)(LabIntent,error){
    var zero LabIntent
    expected,err:=labRootFromEnvironment();if err!=nil{return zero,err}
    if store==nil||store.closed||store.root!=expected{return zero,errors.New("invalid lab registry root")}
    if err:=checkLabJournalLocation(path);err!=nil{return zero,err}
    st,err:=os.Lstat(path);if err!=nil{return zero,err}
    if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>1<<20{
        return zero,errors.New("invalid or redirected lab recovery record")
    }
    raw,err:=os.ReadFile(path);if err!=nil{return zero,err}
    dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
    var intent LabIntent
    if err:=dec.Decode(&intent);err!=nil{return zero,err}
    var trailing any
    if err:=dec.Decode(&trailing);err!=io.EOF{return zero,errors.New("unexpected trailing recovery data")}
    if intent.Schema!=1||intent.Component!="VOLVE-CI-browser-policy-crash-recovery"||
        intent.RegistryRoot!=expected||len(intent.PlanSHA256)!=64{
        return zero,errors.New("foreign recovery identity")
    }
    if err:=Validate(intent.Policy);err!=nil{return zero,err}
    canonical,err:=json.Marshal(intent.Policy);if err!=nil{return zero,err}
    digest:=sha256.Sum256(canonical)
    if hex.EncodeToString(digest[:])!=intent.PlanSHA256{
        return zero,errors.New("recovery record is corrupt")
    }
    return intent,nil
}
// ReplayLabIntent reverses only exact matching CI values and preserves any
// changed value. Missing values are safe to skip after an interrupted writer.
// A second replay is idempotent; no product/browser registry key is affected.
func ReplayLabIntent(ctx context.Context,path string,store *WindowsRegistryLab)(LabRecoveryResult,error){
    var zero LabRecoveryResult
    if ctx==nil{return zero,errors.New("context required")}
    if err:=ctx.Err();err!=nil{return zero,err}
    intent,err:=readLabIntent(path,store);if err!=nil{return zero,err}
    result:=LabRecoveryResult{Checked:len(intent.Policy.RegistryValues),Status:"LAB_RECOVERY_INCOMPLETE"}
    for i:=len(intent.Policy.RegistryValues)-1;i>=0;i-- {
        if err:=ctx.Err();err!=nil{return result,err}
        value:=intent.Policy.RegistryValues[i]
        found,err:=store.Exists(ctx,value)
        if err!=nil{return result,err}
        if !found{continue}
        if err:=store.DeleteOnlyIfEqual(ctx,value);err!=nil{
            return result,fmt.Errorf("refusing to delete nonmatching Registry value: %w",err)
        }
        result.Reverted++
    }
    for _,value:=range intent.Policy.RegistryValues {
        found,err:=store.Exists(ctx,value)
        if err!=nil||found{return result,errors.New("incomplete CI policy recovery")}
    }
    result.Status="LAB_RECOVERED_NO_INSTALL"
    return result,nil
}
