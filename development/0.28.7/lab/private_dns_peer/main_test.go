package main

import (
 "bytes"
 "encoding/binary"
 "testing"
)

func challengeQuery() []byte {
 q:=[]byte{0xab,0xcd,1,0,0,1,0,0,0,0,0,0}
 for _,s:=range []string{"0123456789abcdef0123456789abcdef","volve-ci","invalid"}{q=append(q,byte(len(s)));q=append(q,[]byte(s)...)}
 return append(q,0,0,1,0,1)
}
func TestPrivateDNSChallengeReply(t *testing.T){
 q:=challengeQuery()
 r,nonce,err:=challengeReply(q)
 if err!=nil||nonce!="0123456789abcdef0123456789abcdef"{t.Fatalf("valid challenge refused: %v",err)}
 if !bytes.Equal(r[:2],q[:2])||r[2]!=0x85||binary.BigEndian.Uint16(r[6:8])!=1||!bytes.Equal(r[12:len(q)],q[12:])||!bytes.Equal(r[len(q):],[]byte{0xc0,0x0c,0,1,0,1,0,0,0,0,0,4,192,0,2,53}){t.Fatal("incorrect transaction-bound DNS answer")}
 edns:=append(append([]byte(nil),q...),0,0,41,4,208,0,0,0,0,0,0)
 edns[11]=1
 if got,_,err:=challengeReply(edns);err!=nil||!bytes.Equal(got,r){t.Fatalf("valid EDNS not accepted: %v",err)}
}
func TestPrivateDNSChallengeRejectsUnrelatedOrMalformedQuestions(t *testing.T){
 for _,name:=range []string{"truncated","foreign","nonhex","compression","AAAA","extra","response","other-opcode","bad-edns","many-questions"}{
  t.Run(name,func(t *testing.T){
   q:=challengeQuery()
   switch name {
   case "truncated":q=q[:len(q)-1]
   case "foreign":q[46]='x'
   case "nonhex":q[13]='z'
   case "compression":q[12]=0xc0
   case "AAAA":q[len(q)-3]=28
   case "extra":q=append(q,0)
   case "response":q[2]=0x81
   case "other-opcode":q[2]=9
   case "bad-edns":q[11]=1
   case "many-questions":q[5]=2
   }
   if _,_,err:=challengeReply(q);err==nil{t.Fatal("unexpected DNS request admitted")}
  })
 }
}
