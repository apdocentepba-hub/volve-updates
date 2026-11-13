package singlefile

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "strings"
 "crypto/rand"
 "os"
 "path/filepath"
 "testing"
 "volve.local/installer/unifiedbundle"
)

func TestStageInLabVerifiesFilesAndRejectsOverwrite(t *testing.T) {
 root,pub,_:=fixture(t)
 exe:=filepath.Join(t.TempDir(),"packed.exe")
 if err:=Assemble(fakePE(t),root,exe,pub);err!=nil{t.Fatal(err)}
 dest:=filepath.Join(t.TempDir(),"VOLVE-CI-staged")
 m,err:=StageInLab(exe,pub,dest)
 if err!=nil{t.Fatal(err)}
 if len(m.Components)!=8{t.Fatal("expected all 8 embedded components")}
 if _,err:=unifiedbundle.Verify(dest,pub);err!=nil{t.Fatal(err)}
 if _,err:=StageInLab(exe,pub,dest);err==nil{t.Fatal("reused staging destination accepted")}
}

func TestStageInLabRejectsInvalidKeysAndUnsafePathsWithoutWriting(t *testing.T){
 root,pub,_:=fixture(t)
 exe:=filepath.Join(t.TempDir(),"packed.exe")
 if err:=Assemble(fakePE(t),root,exe,pub);err!=nil{t.Fatal(err)}
 parent:=t.TempDir()
 if _,err:=StageInLab(exe,pub,filepath.Join(parent,"installed-engines"));err==nil{t.Fatal("production-like target accepted")}
 if _,err:=StageInLab(exe,pub,"VOLVE-CI-relative");err==nil{t.Fatal("relative target accepted")}
 wrong,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 dest:=filepath.Join(parent,"VOLVE-CI-wrongkey")
 if _,err:=StageInLab(exe,wrong,dest);err==nil{t.Fatal("wrong key accepted")}
 if _,err:=os.Stat(dest);!os.IsNotExist(err){t.Fatal("wrong key wrote staging files")}
}

func TestStageInLabRejectsSymlinkedParent(t *testing.T){
 root,pub,_:=fixture(t)
 exe:=filepath.Join(t.TempDir(),"packed.exe")
 if err:=Assemble(fakePE(t),root,exe,pub);err!=nil{t.Fatal(err)}
 linked:=filepath.Join(t.TempDir(),"link")
 if err:=os.Symlink(t.TempDir(),linked);err!=nil{t.Skip("symlink unavailable: "+err.Error())}
 if _,err:=StageInLab(exe,pub,filepath.Join(linked,"VOLVE-CI-test"));err==nil{t.Fatal("symlink parent accepted")}
}

func TestStageInLabPinnedRequiresSameEXEBytesAsPublisherGate(t *testing.T) {
 root,pub,_:=fixture(t)
 exe:=filepath.Join(t.TempDir(),"signed-bundle-lab.exe")
 if err:=Assemble(fakePE(t),root,exe,pub);err!=nil{t.Fatal(err)}
 raw,err:=os.ReadFile(exe);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(raw)
 correct:=hex.EncodeToString(sum[:])
 bad:=strings.Repeat("0",64)
 if bad==correct {bad=strings.Repeat("1",64)}
 parent:=t.TempDir()
 wrong:=filepath.Join(parent,"VOLVE-CI-untrusted-path-replacement")
 if _,err:=StageInLabPinned(exe,pub,wrong,bad);err==nil||!strings.Contains(err.Error(),"opened EXE SHA256"){
  t.Fatalf("mismatched Authenticode-verified EXE hash was not rejected: %v",err)
 }
 if _,err:=os.Lstat(wrong);!os.IsNotExist(err){t.Fatal("invalid EXE pin wrote any staging directory")}
 missing:=filepath.Join(parent,"VOLVE-CI-pin-missing")
 if _,err:=StageInLabPinned(exe,pub,missing,"");err==nil{t.Fatal("missing external EXE pin accepted")}
 if _,err:=os.Lstat(missing);!os.IsNotExist(err){t.Fatal("empty EXE pin wrote a staging directory")}
 malformed:=filepath.Join(parent,"VOLVE-CI-pin-uppercase")
 if _,err:=StageInLabPinned(exe,pub,malformed,strings.ToUpper(correct));err==nil{t.Fatal("noncanonical external EXE pin accepted")}
 if _,err:=os.Lstat(malformed);!os.IsNotExist(err){t.Fatal("noncanonical EXE pin wrote a staging directory")}
 good:=filepath.Join(parent,"VOLVE-CI-valid-exact-exe")
 m,err:=StageInLabPinned(exe,pub,good,correct)
 if err!=nil{t.Fatalf("exact opened EXE failed signed staging: %v",err)}
 if len(m.Components)!=7{t.Fatalf("expected exactly seven public parts, got %d",len(m.Components))}
 if _,err:=unifiedbundle.Verify(good,pub);err!=nil{t.Fatal(err)}
}

func TestStageInLabPinnedRejectsInPlaceSourceMutationAfterExtraction(t *testing.T) {
 root,pub,_:=fixture(t)
 exe:=filepath.Join(t.TempDir(),"source-pinned.exe")
 if err:=Assemble(fakePE(t),root,exe,pub);err!=nil{t.Fatal(err)}
 raw,err:=os.ReadFile(exe);if err!=nil{t.Fatal(err)}
 if len(raw)<4{t.Fatal("test EXE too short")}
 sum:=sha256.Sum256(raw)
 expected:=hex.EncodeToString(sum[:])
 destination:=filepath.Join(t.TempDir(),"VOLVE-CI-source-changed-before-commit")
 mutated:=false
 var mutationErr error
 _,err=stageInLabWithFinalHook(exe,pub,destination,expected,func(){
  // Deliberate equal-length write AFTER the embedded archive has already
  // been extracted: file size alone cannot catch the mutation.
  file,openErr:=os.OpenFile(exe,os.O_WRONLY,0)
  if openErr!=nil{mutationErr=openErr;return}
  _,writeErr:=file.WriteAt([]byte{raw[3]^1},3)
  closeErr:=file.Close()
  if writeErr!=nil{mutationErr=writeErr;return}
  if closeErr!=nil{mutationErr=closeErr;return}
  mutated=true
 })
 if mutationErr!=nil{t.Fatalf("could not mutate synthetic CI-only source: %v",mutationErr)}
 if !mutated || err==nil || !strings.Contains(err.Error(),"opened EXE changed during staging (SHA256 mismatch)") {
  t.Fatalf("source in-place mutation not rejected by final fingerprint: mutated=%t err=%v",mutated,err)
 }
 if _,statErr:=os.Lstat(destination);!os.IsNotExist(statErr) {
  t.Fatalf("source mutation left staged payload available: %v",statErr)
 }
}
