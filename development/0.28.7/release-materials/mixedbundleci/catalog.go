package mixedbundleci

// Independent second check of the official HaGeZi full gambling list.
// This establishes source provenance, NOT compatibility, enforcement, license
// compliance or permission to install it on any Windows computer.
import (
 "crypto/sha1"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "strconv"
 "strings"
)

const (
 PinnedFullCatalogCommit="81bbd1b9009893d65358146b23282647634c26be"
 PinnedFullCatalogBlobSHA1="096ce47515721f7aac2ce8138fb5b421aa6fb1e1"
 PinnedFullCatalogSHA256="ec700a88cdaedcc90cd482105ecbdeb7177289029303d61e35365ed1ea9c2347"
 PinnedFullCatalogBytes=11040215
 PinnedFullCatalogURL="https://raw.githubusercontent.com/hagezi/dns-blocklists/"+PinnedFullCatalogCommit+"/wildcard/gambling-onlydomains.txt"
)
type CatalogReceipt struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Source string `json:"source"`
 Commit string `json:"commit"`
 GitBlobSHA1 string `json:"git_blob_sha1"`
 SourceURL string `json:"source_url"`
 License string `json:"license"`
 Size int64 `json:"size"`
 SHA256 string `json:"sha256"`
 DomainCount int `json:"domain_count"`
 CommentLines int `json:"comment_lines"`
 SourceVerified bool `json:"source_verified"`
 CompatibleWithDNSMotorVerified bool `json:"compatible_with_dns_motor_verified"`
 ProductionInstallAuthorized bool `json:"production_install_authorized"`
 PublishReleaseAuthorized bool `json:"publish_release_authorized"`
}

func VerifyPinnedFullCatalog(content,receipt []byte)error{
 if len(content)!=PinnedFullCatalogBytes{return errors.New("full catalog does not match fixed upstream byte count")}
 sum:=sha1.New()
 _,_ = sum.Write([]byte("blob "+strconv.Itoa(len(content))))
 _,_ = sum.Write([]byte{0})
 _,_ = sum.Write(content)
 if SHA256(content)!=PinnedFullCatalogSHA256{return errors.New("HaGeZi source mismatches fixed SHA-256, independent of Git SHA-1")}
 if hex.EncodeToString(sum.Sum(nil))!=PinnedFullCatalogBlobSHA1{
  return errors.New("HaGeZi source mismatches fixed upstream Git blob")
 }
 var proof CatalogReceipt
 dec:=json.NewDecoder(strings.NewReader(string(receipt)));dec.DisallowUnknownFields()
 if err:=dec.Decode(&proof);err!=nil{return fmt.Errorf("unreadable upstream provenance receipt: %w",err)}
 if proof.Schema!=1||proof.Component!="full-catalog-upstream-source-only"||
  proof.Source!="hagezi/dns-blocklists"||proof.Commit!=PinnedFullCatalogCommit||
  proof.GitBlobSHA1!=PinnedFullCatalogBlobSHA1||proof.SourceURL!=PinnedFullCatalogURL||
  proof.License!="GPL-3.0"||proof.Size!=PinnedFullCatalogBytes||
  proof.SHA256!=SHA256(content)||proof.DomainCount<400000||proof.DomainCount>1500000||
  proof.CommentLines<0||!proof.SourceVerified||proof.CompatibleWithDNSMotorVerified||
  proof.ProductionInstallAuthorized||proof.PublishReleaseAuthorized {
  return errors.New("source receipt missing, forged or falsely claiming product release")
 }
 return nil
}
