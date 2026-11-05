package mixedbundleci
import (
 "strings"
 "testing"
)

// Exact public historical sidecar fixtures, no secret key or install permit.
// The manifest's terminal newline is part of the Ed25519-signed bytes.
const signedHistoricManifest="{\"schema\":1,\"component\":\"dns-engine\",\"version\":\"0.28.7\",\"min_panel_version\":\"0.28.7\",\"url\":\"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe\",\"sha256\":\"e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414\",\"size\":18168832,\"notes\":\"Candidate DNS-engine package for controlled signed migration; NOT released or enabled in motor-stable.json.\"}\n"
const historicSignature="ZzyxZ4DMzsuXAy54sujDspYcnkc+6N9TGSEgBWuOW3ZYAQ7o1y5aEgUfkKUDhrHL14oNajNj066LbI525fX1Ag==\n"
func TestPinnedHistoricalMotorSidecarAuthenticates(t *testing.T){
 if err:=VerifyHistoricMotorSidecars([]byte(signedHistoricManifest),[]byte(historicSignature),ExpectedHistoricMotorSHA256,ExpectedHistoricMotorBytes);err!=nil{
  t.Fatal("real historic publisher signature incorrectly refused:",err)
 }
}
func TestTamperedHistoricSidecarOrIdentityIsRejected(t *testing.T){
 cases:=[]struct{name,manifest,signature,sha string;size int64}{
  {"changed-body",strings.Replace(signedHistoricManifest,"0.28.7","0.28.6",1),historicSignature,ExpectedHistoricMotorSHA256,ExpectedHistoricMotorBytes},
  {"missing-newline",strings.TrimSuffix(signedHistoricManifest,"\n"),historicSignature,ExpectedHistoricMotorSHA256,ExpectedHistoricMotorBytes},
  {"unknown-signature",signedHistoricManifest,strings.Repeat("A",88),ExpectedHistoricMotorSHA256,ExpectedHistoricMotorBytes},
  {"altered-signature",signedHistoricManifest,historicSignature[:8]+"Z"+historicSignature[9:],ExpectedHistoricMotorSHA256,ExpectedHistoricMotorBytes},
  {"wrong-motor-digest",signedHistoricManifest,historicSignature,strings.Repeat("0",64),ExpectedHistoricMotorBytes},
  {"wrong-motor-length",signedHistoricManifest,historicSignature,ExpectedHistoricMotorSHA256,ExpectedHistoricMotorBytes-1},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   if err:=VerifyHistoricMotorSidecars([]byte(tc.manifest),[]byte(tc.signature),tc.sha,tc.size);err==nil{
    t.Fatal("tampered historic source accepted")
   }
  })
 }
}
