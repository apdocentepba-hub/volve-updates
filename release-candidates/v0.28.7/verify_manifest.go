package main
import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "strings"
)
const publisherPublicKey = "6pa2qoWNv+J7u0ulDXvqlBd7qEeDzPBdxmU6NpqTGHk="
const expectedSHA = "e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414"
type Manifest struct{
 Schema int `json:"schema"`
 Version string `json:"version"`
 Published string `json:"published"`
 Notes string `json:"notes"`
 URL string `json:"url"`
 SHA256 string `json:"sha256"`
 Size int64 `json:"size"`
}
func check()error{
 if len(os.Args)!=2{return errors.New("usage: verifier <exact candidate PE path>")}
 raw,err:=os.ReadFile("release-candidates/v0.28.7/stable.json");if err!=nil{return err}
 encoded,err:=os.ReadFile("release-candidates/v0.28.7/stable.json.sig");if err!=nil{return err}
 sig,err:=base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)));if err!=nil{return err}
 key,err:=base64.StdEncoding.DecodeString(publisherPublicKey);if err!=nil{return err}
 if len(key)!=ed25519.PublicKeySize||len(sig)!=ed25519.SignatureSize||!ed25519.Verify(ed25519.PublicKey(key),raw,sig){
  return errors.New("offline original publisher signature invalid")
 }
 var m Manifest
 if err:=json.Unmarshal(raw,&m);err!=nil{return err}
 if m.Schema!=1||m.Version!="0.28.7"||m.SHA256!=expectedSHA||m.Size!=18168832||
  m.URL!="https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_0_28_7_CENTRO.exe"{
  return errors.New("signed publisher manifest wrong identity")
 }
 b,err:=os.ReadFile(os.Args[1]);if err!=nil{return err}
 digest:=sha256.Sum256(b)
 if len(b)!=int(m.Size)||hex.EncodeToString(digest[:])!=m.SHA256||len(b)<2||string(b[:2])!="MZ"{
  return errors.New("Windows release executable differs from offline signed manifest")
 }
 fmt.Println("PASS: exact original editor signature and candidate binary SHA/size")
 return nil
}
func main(){if err:=check();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
