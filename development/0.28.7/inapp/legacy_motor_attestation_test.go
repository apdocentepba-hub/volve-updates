package motorupdate

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func signedLegacyFixture(t *testing.T) (string,[]byte,[]byte,ed25519.PublicKey,ed25519.PrivateKey) {
    t.Helper()
    root:=t.TempDir()
    path:=filepath.Join(root,legacyServiceName)
    binary:=[]byte("MZ_legacy_laboratory_motor_0.27.0")
    if err:=os.WriteFile(path,binary,0600);err!=nil{t.Fatal(err)}
    sum:=sha256.Sum256(binary)
    m:=LegacyMotorStatement{Schema:1,Component:"dns-engine-legacy",Version:"0.27.0",
        TaskName:legacySystemTask,ExecutableName:legacyServiceName,Args:legacyServiceArg,
        SHA256:hex.EncodeToString(sum[:]),Size:int64(len(binary))}
    raw,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
    pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
    return path,raw,sig,pub,priv
}
func TestSignedLegacyMotorAttestationIdentifiesExactBinary(t *testing.T){
    path,raw,sig,pub,_:=signedLegacyFixture(t)
    version,err:=VerifyLegacyMotorAttestation(path,legacySystemTask,legacyServiceArg,raw,sig,pub)
    if err!=nil || version!="0.27.0"{t.Fatalf("known signed motor not recognized: %q %v",version,err)}
}
func TestSignedLegacyMotorAttestationRejectsChangedBinary(t *testing.T){
    path,raw,sig,pub,_:=signedLegacyFixture(t)
    if err:=os.WriteFile(path,[]byte("MZ_tampered"),0600);err!=nil{t.Fatal(err)}
    if _,err:=VerifyLegacyMotorAttestation(path,legacySystemTask,legacyServiceArg,raw,sig,pub);err==nil{t.Fatal("changed legacy EXE trusted")}
}
func TestSignedLegacyMotorAttestationRejectsForgedPublisher(t *testing.T){
    path,raw,sig,_,_:=signedLegacyFixture(t)
    forgedPub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    if _,err:=VerifyLegacyMotorAttestation(path,legacySystemTask,legacyServiceArg,raw,sig,forgedPub);err==nil{t.Fatal("forged publisher accepted")}
}
func TestSignedLegacyMotorAttestationRejectsTaskImpersonation(t *testing.T){
    path,raw,sig,pub,_:=signedLegacyFixture(t)
    cases:=[][2]string{
        {"VOLVE-CI-OTHER",legacyServiceArg},
        {legacySystemTask,"--refresh"},
        {"VOLVE-DNS-RESCUE-0270",legacyServiceArg},
    }
    for _,pair:=range cases{
        if _,err:=VerifyLegacyMotorAttestation(path,pair[0],pair[1],raw,sig,pub);err==nil{t.Fatalf("task identity accepted: %v",pair)}
    }
}
func TestSignedLegacyMotorAttestationRejectsModifiedSignedRecord(t *testing.T){
    path,raw,sig,pub,_:=signedLegacyFixture(t)
    changed:=[]byte(strings.Replace(string(raw),"0.27.0","0.28.6",1))
    if _,err:=VerifyLegacyMotorAttestation(path,legacySystemTask,legacyServiceArg,changed,sig,pub);err==nil{t.Fatal("modified signed version accepted")}
}
func TestSignedLegacyMotorAttestationRejectsTrailingJSONEvenWhenSigned(t *testing.T){
    path,raw,_,pub,priv:=signedLegacyFixture(t)
    changed:=append(append([]byte{},raw...),[]byte(" {}")...)
    sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,changed)))
    if _,err:=VerifyLegacyMotorAttestation(path,legacySystemTask,legacyServiceArg,changed,sig,pub);err==nil{t.Fatal("trailing JSON accepted")}
}
func TestSignedLegacyMotorAttestationRejectsUnsignedStatement(t *testing.T){
    path,raw,_,pub,_:=signedLegacyFixture(t)
    if _,err:=VerifyLegacyMotorAttestation(path,legacySystemTask,legacyServiceArg,raw,[]byte("not-a-signature"),pub);err==nil{t.Fatal("unsigned motor accepted")}
}
func TestSignedLegacyMotorAttestationRejectsUnrecognizedDirAndName(t *testing.T){
    path,raw,sig,pub,_:=signedLegacyFixture(t)
    other:=filepath.Join(filepath.Dir(path),"UnknownDNS.exe")
    bytes,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(other,bytes,0600);err!=nil{t.Fatal(err)}
    if _,err:=VerifyLegacyMotorAttestation(other,legacySystemTask,legacyServiceArg,raw,sig,pub);err==nil{t.Fatal("unexpected legacy file name accepted")}
}
