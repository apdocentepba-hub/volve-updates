package singlefile

import (
 "crypto/ed25519"
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
