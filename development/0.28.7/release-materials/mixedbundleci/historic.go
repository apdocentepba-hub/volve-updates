package mixedbundleci

// Independent publisher authentication of the exact historical DNS motor
// sidecars. This proves the old candidate's identity, NOT install permission.
import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "strings"
)

const historicPublisherPublicKeyB64="6pa2qoWNv+J7u0ulDXvqlBd7qEeDzPBdxmU6NpqTGHk="
const historicMotorSignedURL="https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe"

type historicMotorManifest struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Version string `json:"version"`
 MinimumPanel string `json:"min_panel_version"`
 URL string `json:"url"`
 SHA256 string `json:"sha256"`
 Size int64 `json:"size"`
 Notes string `json:"notes"`
}

// VerifyHistoricMotorSidecars ensures a signed manifest was authored by the
// pinned historical editor and matches exactly the old, known engine bytes.
// It does not trust a new key from the bundle or generate signatures.
func VerifyHistoricMotorSidecars(manifestJSON,signatureFile []byte,motorHash string,motorSize int64)error{
 pub,err:=base64.StdEncoding.Strict().DecodeString(historicPublisherPublicKeyB64)
 if err!=nil||len(pub)!=ed25519.PublicKeySize{return errors.New("pinned historical publisher key invalid")}
 sig,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(signatureFile)))
 if err!=nil||len(sig)!=ed25519.SignatureSize{
  return errors.New("missing or malformed historical Ed25519 signature")
 }
 if !ed25519.Verify(ed25519.PublicKey(pub),manifestJSON,sig){
  return errors.New("historic DNS manifest signature did not verify against pinned publisher")
 }
 var m historicMotorManifest
 if err:=json.Unmarshal(manifestJSON,&m);err!=nil{return fmt.Errorf("invalid signed historic motor manifest: %w",err)}
 if m.Schema!=1||m.Component!="dns-engine"||m.Version!="0.28.7"||m.MinimumPanel!="0.28.7"||
  m.URL!=historicMotorSignedURL||m.SHA256!=ExpectedHistoricMotorSHA256||
  m.Size!=ExpectedHistoricMotorBytes||motorHash!=ExpectedHistoricMotorSHA256||
  motorSize!=ExpectedHistoricMotorBytes{
  return errors.New("historically signed manifest is incompatible with the exact old motor")
 }
 return nil
}
