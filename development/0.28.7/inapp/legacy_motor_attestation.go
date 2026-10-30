package motorupdate

import (
    "bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
)

const maxLegacyStatementBytes = 4096
const legacySystemTask = "VOLVE-DNS-SERVER-0270"
const legacyServiceName = "VOLVE_DNS_Server_0270.exe"
const legacyServiceArg = "--dns-service"

// LegacyMotorStatement is a detached, publisher-signed provenance statement
// mapping a SPECIFIC installed DNS binary hash to its engine version. A
// Windows task's executable name or the panel version is not provenance.
// It cannot be produced safely by the unprivileged updater or guessed.
type LegacyMotorStatement struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    Version string `json:"version"`
    TaskName string `json:"task_name"`
    ExecutableName string `json:"executable_name"`
    Args string `json:"args"`
    SHA256 string `json:"sha256"`
    Size int64 `json:"size"`
}

// VerifyLegacyMotorAttestation checks publisher-signed bytes AND the real
// installed legacy binary. Caller must separately verify live Task Scheduler
// SYSTEM ownership, rescue task, DNS journal and network readiness.
// No system setting or file is changed by this function.
func VerifyLegacyMotorAttestation(
    installedExe, actualTaskName, actualTaskArgs string,
    rawStatement, detachedSignature []byte, key ed25519.PublicKey,
) (string,error) {
    if len(key)!=ed25519.PublicKeySize {return "",errors.New("clave pública de atestación inválida")}
    if len(rawStatement)==0 || len(rawStatement)>maxLegacyStatementBytes {
        return "",errors.New("atestación heredada ausente o demasiado grande")
    }
    signature,err:=base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(detachedSignature)))
    if err!=nil || len(signature)!=ed25519.SignatureSize || !ed25519.Verify(key,rawStatement,signature) {
        return "",errors.New("firma Ed25519 de procedencia del motor inválida")
    }
    dec:=json.NewDecoder(bytes.NewReader(rawStatement));dec.DisallowUnknownFields()
    var m LegacyMotorStatement
    if err:=dec.Decode(&m);err!=nil {return "",fmt.Errorf("atestación no reconocida: %w",err)}
    var extra any
    if err:=dec.Decode(&extra);err!=io.EOF {return "",errors.New("atestación con contenido extra")}
    if m.Schema!=1 || m.Component!="dns-engine-legacy" || !versionRe.MatchString(m.Version) {
        return "",errors.New("atestación con versión/componente no reconocidos")
    }
    if m.TaskName!=legacySystemTask || m.ExecutableName!=legacyServiceName || m.Args!=legacyServiceArg ||
       actualTaskName!=legacySystemTask || actualTaskArgs!=legacyServiceArg {
        return "",errors.New("identidad/argumentos de la tarea legacy no coincide")
    }
    if !filepath.IsAbs(installedExe) || filepath.Base(installedExe)!=legacyServiceName {
        return "",errors.New("ruta del motor heredado inesperada")
    }
    if err:=safeInventoryDirectory(filepath.Dir(installedExe));err!=nil {return "",fmt.Errorf("directorio del motor no confiable: %w",err)}
    stat,err:=os.Lstat(installedExe)
    if err!=nil{return "",err}
    if !stat.Mode().IsRegular() || stat.Size()!=m.Size || m.Size<=0 || m.Size>80<<20 || !hexRe.MatchString(m.SHA256) {
        return "",errors.New("huella o tamaño del motor heredado no reconocidos")
    }
    f,err:=os.Open(installedExe);if err!=nil{return "",err}
    defer f.Close()
    h:=sha256.New()
    n,err:=io.Copy(h,io.LimitReader(f,m.Size+1))
    if err!=nil{return "",err}
    if n!=m.Size || hex.EncodeToString(h.Sum(nil))!=m.SHA256 {
        return "",errors.New("motor instalado distinto al autorizado por firma")
    }
    return m.Version,nil
}
