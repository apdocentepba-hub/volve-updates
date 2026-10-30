package motorupdate

import (
    "bytes"
    "crypto/ed25519"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "strings"
)

var ErrUnregisteredEngine = errors.New("motor instalado sin versión verificada")

// InstalledReceipt is an administrative pointer to an independently signed,
// versioned executable. A receipt alone is NEVER proof of an installed engine.
// InspectInstalledEngine validates the executable and the original Ed25519
// manifest + detached signature every time it reads the version.
type InstalledReceipt struct {
    Schema int    `json:"schema"`
    Version string `json:"version"`
    SHA256 string `json:"sha256"`
}

const installedReceiptName = "VOLVE_Motor_Current.json"
const installedReceiptMaxBytes int64 = 4096

func safeInventoryDirectory(path string) error {
    if path == "" || !filepath.IsAbs(path) {
        return errors.New("ruta de inventario no absoluta")
    }
    // Examine every actual path component using Lstat, not EvalSymlinks
    // string equality. On Windows, EvalSymlinks can expand DOS 8.3 paths
    // (RUNNER~1 -> runneradmin) without a symlink; rejecting this is a
    // false positive. A junction/symlink is detected by Lstat at its
    // original path component rather than by the spelling of its target.
    clean:=filepath.Clean(path)
    volume:=filepath.VolumeName(clean)
    root:=string(os.PathSeparator)
    if volume!="" {root=volume+root}
    current:=root
    rest:=strings.TrimPrefix(clean,root)
    for _,component:=range strings.Split(rest,string(os.PathSeparator)) {
        if component=="" {continue}
        current=filepath.Join(current,component)
        info,err:=os.Lstat(current)
        if err!=nil{return err}
        if info.Mode() & os.ModeSymlink != 0 {
            return fmt.Errorf("componente del inventario redirigido: %s",component)
        }
        if !info.IsDir() {
            return fmt.Errorf("componente del inventario no es directorio: %s",component)
        }
    }
    return nil
}

func installedEnginePath(root string, version string) string {
    return filepath.Join(root, "motor-"+version, stagedFilename(Manifest{Version:version}))
}

func sameInventoryPath(a,b string) bool {
    x,y:=filepath.Clean(a),filepath.Clean(b)
    if runtime.GOOS=="windows" { return strings.EqualFold(x,y) }
    return x==y
}

func inspectInstalledRecord(root string, key ed25519.PublicKey) (InstalledReceipt,error) {
    var receipt InstalledReceipt
    if len(key)!=ed25519.PublicKeySize { return receipt,errors.New("clave pública de motor inválida") }
    if err:=safeInventoryDirectory(root);err!=nil{return receipt,err}
    state:=filepath.Join(root,installedReceiptName)
    stat,err:=os.Lstat(state)
    if errors.Is(err,os.ErrNotExist){return receipt,ErrUnregisteredEngine}
    if err!=nil{return receipt,err}
    if !stat.Mode().IsRegular() || stat.Size()<2 || stat.Size()>installedReceiptMaxBytes {
        return receipt,errors.New("registro de versión no regular o fuera de límite")
    }
    raw,err:=os.ReadFile(state);if err!=nil{return receipt,err}
    dec:=json.NewDecoder(bytes.NewReader(raw))
    dec.DisallowUnknownFields()
    if err:=dec.Decode(&receipt);err!=nil{return InstalledReceipt{},fmt.Errorf("registro de motor inválido: %w",err)}
    var extra any
    if dec.Decode(&extra)!=io.EOF {return InstalledReceipt{},errors.New("registro de motor contiene datos extra")}
    if receipt.Schema!=1 || !versionRe.MatchString(receipt.Version) || !hexRe.MatchString(receipt.SHA256) {
        return InstalledReceipt{},errors.New("registro de motor no reconocido")
    }
    versionDir:=filepath.Join(root,"motor-"+receipt.Version)
    if err:=safeInventoryDirectory(versionDir);err!=nil { return InstalledReceipt{},fmt.Errorf("motor versionado no seguro: %w",err) }
    candidate:=installedEnginePath(root,receipt.Version)
    // VerifyStaged checks signed manifest version/name, exact binary size and
    // SHA256. No installed-version assertion may bypass this verification.
    for _,p:=range []string{candidate,candidate+".json",candidate+".sig"} {
        info,err:=os.Lstat(p)
        if err!=nil{return InstalledReceipt{},err}
        if !info.Mode().IsRegular() || info.Size()<=0 {
            return InstalledReceipt{},fmt.Errorf("archivo no regular en motor instalado: %s",filepath.Base(p))
        }
    }
    m,err:=VerifyStaged(candidate,key)
    if err!=nil{return InstalledReceipt{},fmt.Errorf("motor instalado sin firma o huella válidas: %w",err)}
    if m.Version!=receipt.Version || m.SHA256!=receipt.SHA256 {
        return InstalledReceipt{},errors.New("registro de versión no coincide con el motor firmado")
    }
    return receipt,nil
}

// InspectInstalledEngine returns a version ONLY when the administrative record,
// signed manifest, detached signature and exact motor EXE all agree. Legacy
// installs without a recorded version are explicitly unknown, never guessed.
func InspectInstalledEngine(root string, key ed25519.PublicKey) (string,error) {
    r,err:=inspectInstalledRecord(root,key)
    if err!=nil {return "",err}
    return r.Version,nil
}

// RecordVerifiedEngine records an ALREADY-installed versioned candidate.
// It cannot move/launch a motor or modify DNS. Never invoke before the Windows
// driver verifies the new DNS engine AND external connectivity. The driver
// must preserve the old record for rollback in its durable transaction journal.
func RecordVerifiedEngine(root, candidate string, key ed25519.PublicKey) error {
    if err:=safeInventoryDirectory(root);err!=nil{return err}
    if !filepath.IsAbs(candidate) {return errors.New("ruta del candidato no absoluta")}
    m,err:=VerifyStaged(candidate,key)
    if err!=nil{return fmt.Errorf("motor candidato no verificable: %w",err)}
    if !sameInventoryPath(candidate,installedEnginePath(root,m.Version)) {
        return errors.New("candidato fuera del directorio versionado registrado")
    }
    versionDir:=filepath.Dir(candidate)
    if err:=safeInventoryDirectory(versionDir);err!=nil{return err}
    if stat,err:=os.Lstat(candidate);err!=nil || !stat.Mode().IsRegular() {
        return errors.New("candidato no regular o inaccesible")
    }
    for _,p:=range []string{candidate+".json",candidate+".sig"} {
        info,e:=os.Lstat(p)
        if e!=nil || !info.Mode().IsRegular() {return errors.New("firma o manifiesto en ruta no segura")}
    }
    previous,err:=inspectInstalledRecord(root,key)
    if err==nil {
        cmp,cmpErr:=compareVersions(previous.Version,m.Version)
        if cmpErr!=nil{return cmpErr}
        if cmp>0 {return errors.New("retroceso del motor instalado rechazado")}
        if cmp==0 {
            if previous.SHA256==m.SHA256{return nil}
            return errors.New("versión del motor igual pero huella diferente")
        }
    } else if !errors.Is(err,ErrUnregisteredEngine) {
        return fmt.Errorf("inventario anterior alterado o inválido: %w",err)
    }
    data,err:=json.Marshal(InstalledReceipt{Schema:1,Version:m.Version,SHA256:m.SHA256})
    if err!=nil{return err}
    tmp,err:=os.CreateTemp(root,".motor-current-*.tmp")
    if err!=nil{return err}
    defer os.Remove(tmp.Name())
    if err:=tmp.Chmod(0600);err!=nil{tmp.Close();return err}
    if _,err=tmp.Write(append(data,'\n'));err!=nil{tmp.Close();return err}
    if err=tmp.Sync();err!=nil{tmp.Close();return err}
    if err=tmp.Close();err!=nil{return err}
    if err=os.Rename(tmp.Name(),filepath.Join(root,installedReceiptName));err!=nil{return fmt.Errorf("no se pudo publicar el inventario: %w",err)}
    return nil
}
