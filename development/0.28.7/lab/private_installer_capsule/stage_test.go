package main

import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "testing/fstest"
)

func capsuleFixture() (fstest.MapFS,[]string){
 payload:=fstest.MapFS{}
 pins:=[]string{}
 for _,name:=range capsuleNames{
  raw:=[]byte("exact fixture "+name)
  payload[name]=&fstest.MapFile{Data:raw,Mode:0600}
  digest:=sha256.Sum256(raw)
  pins=append(pins,strings.ToUpper(hex.EncodeToString(digest[:])))
 }
 return payload,pins
}
func TestCapsuleStagesExactComponentsOnlyOnce(t *testing.T){
 root:=t.TempDir()
 data,pins:=capsuleFixture()
 if err:=stageCapsule(root,data,pins);err!=nil{t.Fatal(err)}
 for _,name:=range capsuleNames{
  raw,err:=os.ReadFile(filepath.Join(root,name))
  if err!=nil||string(raw)!=string(data[name].Data){t.Fatalf("bad staged component %s: %v",name,err)}
 }
 if err:=stageCapsule(root,data,pins);err==nil{t.Fatal("repeat staging accepted")}
}
func TestCapsuleRejectsUnsafeInputsBeforeWriting(t *testing.T){
 for _,mode:=range []string{"wrong-hash","missing","extra","bad-pin","existing","symlink-component","relative-root"}{
  t.Run(mode,func(t *testing.T){
   root:=t.TempDir()
   data,pins:=capsuleFixture()
   target:=root
   existing:=false
   switch mode{
   case "wrong-hash":data[capsuleNames[2]].Data=[]byte("changed")
   case "missing":delete(data,capsuleNames[1])
   case "extra":data["unexpected"]=&fstest.MapFile{Data:[]byte("extra")}
   case "bad-pin":pins[0]="invalid"
   case "existing":
    existing=true
    if err:=os.WriteFile(filepath.Join(root,capsuleNames[2]),[]byte("preserve"),0600);err!=nil{t.Fatal(err)}
   case "symlink-component":data[capsuleNames[0]].Mode=os.ModeSymlink|0600
   case "relative-root":target="unsafe-relative"
   }
   if err:=stageCapsule(target,data,pins);err==nil{t.Fatal("unsafe stage accepted")}
   entries,err:=os.ReadDir(root)
   if err!=nil{t.Fatal(err)}
   if existing{
    raw,err:=os.ReadFile(filepath.Join(root,capsuleNames[2]))
    if len(entries)!=1||err!=nil||string(raw)!="preserve"{t.Fatal("existing component changed")}
   }else if len(entries)!=0{t.Fatal("invalid input partially staged")}
  })
 }
}
