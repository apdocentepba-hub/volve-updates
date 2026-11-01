package motorupdate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func (f *signedBridgeFixture) review(ctx context.Context, protect func(string)error, preflight func()error)(LegacyPublisherReviewPacket,error){
 return BuildLegacyPublisherReviewPacketReadOnly(ctx,f.live,f.backup,f.candidate,"0.28.7",
  f.pub,protect,preflight)
}

func TestLegacyPublisherReviewPacketMatchesVerifiedExactBytesButIsNotPermit(t *testing.T){
 f:=newSignedBridge(t)
 calls:=0
 packet,err:=f.review(context.Background(),testSecureLabFolderBridge,func()error{calls++;return nil})
 if err!=nil{t.Fatal(err)}
 if packet.Schema!=1||packet.Component!=LegacyPublisherReviewComponent||
  packet.Disposition!="REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT"||packet.FromTask!=legacySystemTask||
  packet.FromArgs!=legacyServiceArg||packet.FromExecutable!=legacyServiceName||
  packet.FromSHA256!=f.permit.FromSHA256||packet.FromTaskXMLSHA256!=f.permit.FromTaskXMLSHA256||
  packet.ToSHA256!=f.permit.ToSHA256||packet.ToVersion!=f.permit.ToVersion||
  packet.FromSize!=f.permit.FromSize||packet.ToSize!=f.permit.ToSize||calls!=2{
  t.Fatalf("unsigned review evidence mismatched actual original/candidate: %+v, probes=%d",packet,calls)
 }
 if strings.Contains(packet.Disposition,"SIGNED_PERMIT")||strings.Contains(packet.Disposition,"AUTHORIZED"){
  t.Fatal("unsigned packet misleadingly claims publisher authorization")
 }
 // The unsigned review packet MUST NOT be accepted as a publisher permit,
 // even though all hashes, paths and preflight checks are authentic to CI.
 _,err=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,f.candidate,"0.28.7",
  []byte("{}"),nil,f.pub,testSecureLabFolderBridge,func()error{return nil})
 if err==nil{t.Fatal("unsigned review packet bypassed permit verification")}
}

func TestLegacyPublisherReviewPacketRejectsTamperingAndWeakEvidence(t *testing.T){
 for _,kind:=range []string{
  "changed-legacy","changed-backup","missing-rollback","changed-signed-candidate",
  "missing-candidate-signature","wrong-publisher","weak-parent-ACL","weak-receipt-ACL",
  "failed-first-preflight","failed-second-preflight","already-managed","panel-too-old",
  "missing-key","missing-preflight","missing-acl","cancelled",
 }{
  t.Run(kind,func(t *testing.T){
   f:=newSignedBridge(t)
   secure:=testSecureLabFolderBridge
   var protect func(string)error=secure
   calls:=0
   var preflight func()error=func()error{calls++;return nil}
   ctx:=context.Background()
   panel:="0.28.7"
   switch kind{
    case "changed-legacy":_ = os.WriteFile(f.live,[]byte("MZ_DIFFERENT"),0600)
    case "changed-backup":_ = os.WriteFile(filepath.Join(f.backup,legacyBackupExe),[]byte("MZ_CORRUPT"),0600)
    case "missing-rollback":_ = os.Remove(filepath.Join(f.backup,legacyBackupReceipt))
    case "changed-signed-candidate":_ = os.WriteFile(f.candidate,[]byte("MZ_BAD"),0600)
    case "missing-candidate-signature":_ = os.Remove(f.candidate+".sig")
    case "wrong-publisher":f.pub,_,_=ed25519.GenerateKey(rand.Reader)
    case "weak-parent-ACL":
     protect=func(path string)error{
      if path==filepath.Dir(f.backup){return os.ErrPermission};return nil
     }
    case "weak-receipt-ACL":
     protect=func(path string)error{
      if path==filepath.Join(f.backup,legacyBackupReceipt){return os.ErrPermission};return nil
     }
    case "failed-first-preflight":preflight=func()error{return os.ErrPermission}
    case "failed-second-preflight":preflight=func()error{calls++;if calls==2{return os.ErrPermission};return nil}
    case "already-managed":
     dir:=filepath.Join(f.root,"installed-engines")
     if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
     if err:=os.WriteFile(filepath.Join(dir,installedReceiptName),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
    case "panel-too-old":panel="0.28.6"
    case "missing-key":f.pub=nil
    case "missing-preflight":preflight=nil
    case "missing-acl":protect=nil
    case "cancelled":
     c,cancel:=context.WithCancel(ctx);cancel();ctx=c
   }
   pkt,err:=BuildLegacyPublisherReviewPacketReadOnly(ctx,f.live,f.backup,f.candidate,panel,
    f.pub,protect,preflight)
   if err==nil||pkt.Component!=""{
    t.Fatalf("unsafe review case %q produced an apparently valid packet: %+v err=%v",kind,pkt,err)
   }
  })
 }
}

func TestLegacyPublisherReviewPacketCannotFalsifyOldVersionOrMutateInstalledFiles(t *testing.T){
 f:=newSignedBridge(t)
 original,err:=os.ReadFile(f.live);if err!=nil{t.Fatal(err)}
 before,err:=os.ReadFile(filepath.Join(f.backup,legacyBackupReceipt));if err!=nil{t.Fatal(err)}
 packet,err:=f.review(context.Background(),testSecureLabFolderBridge,func()error{return nil})
 if err!=nil{t.Fatal(err)}
 after,err:=os.ReadFile(filepath.Join(f.backup,legacyBackupReceipt));if err!=nil{t.Fatal(err)}
 motor,err:=os.ReadFile(f.live);if err!=nil{t.Fatal(err)}
 if string(motor)!=string(original)||string(before)!=string(after){
  t.Fatal("read-only publisher review modified installed motor or backup")
 }
 if strings.Contains(packet.Disposition,"0.28.6")||packet.Component=="dns-engine-legacy-migration"{
  t.Fatal("publisher review claims a historical version or resembles an authorized permit")
 }
}
