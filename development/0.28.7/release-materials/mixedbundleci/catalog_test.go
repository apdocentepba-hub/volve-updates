package mixedbundleci
import(
 "encoding/json"
 "strings"
 "testing"
)
func TestFullCatalogRefusesSyntheticOrPartialSource(t *testing.T){
 bogus:=[]byte("*.casino.example\n")
 if err:=VerifyPinnedFullCatalog(bogus,[]byte("{}"));err==nil{
  t.Fatal("unverified tiny or fabricated full catalog accepted")
 }
}
func TestFullCatalogRequiresSourceWithoutInstallationPermission(t *testing.T){
 proof:=CatalogReceipt{
  Schema:1,Component:"full-catalog-upstream-source-only",
  Source:"hagezi/dns-blocklists",Commit:PinnedFullCatalogCommit,
  GitBlobSHA1:PinnedFullCatalogBlobSHA1,SourceURL:PinnedFullCatalogURL,
  License:"GPL-3.0",Size:PinnedFullCatalogBytes,
  SHA256:strings.Repeat("0",64),DomainCount:626316,
  SourceVerified:true,
 }
 serialized,err:=json.Marshal(proof);if err!=nil{t.Fatal(err)}
 if err:=VerifyPinnedFullCatalog(make([]byte,PinnedFullCatalogBytes),serialized);err==nil{
  t.Fatal("forged full catalog with truthful-looking receipt accepted")
 }
 proof.ProductionInstallAuthorized=true
 if !proof.ProductionInstallAuthorized{t.Fatal("negative fixture malformed")}
}
