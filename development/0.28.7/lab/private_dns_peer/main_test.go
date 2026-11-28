package main

import (
 "bytes"
 "encoding/binary"
 "os"
 "os/exec"
 "path/filepath"
 "runtime"
 "testing"
)

func challengeQuery() []byte {
 q:=[]byte{0xab,0xcd,1,0,0,1,0,0,0,0,0,0}
 for _,s:=range []string{"0123456789abcdef0123456789abcdef","volve-ci","test"}{q=append(q,byte(len(s)));q=append(q,[]byte(s)...)}
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

func TestPrivateDNSPeerEvidenceReadableWhileWriterOpen(t *testing.T){
 path:=filepath.Join(t.TempDir(),"peer.log")
 w,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{t.Fatal(err)}
 defer w.Close()
 const marker="VOLVE_PRIVATE_PEER_READY two_ipv4_addresses udp_tcp53 NO_FORWARDING"
 peerEvidence(w,"%s\n",marker)
 got,err:=os.ReadFile(path)
 if err!=nil||string(got)!=marker+"\n"{t.Fatalf("Go shared reader failed: %q %v",got,err)}
 if runtime.GOOS!="windows"{return}
 // Native PowerShell must be able to read the same evidence before the
 // Go writer exits. This reproduces the prior actual guest sharing failure.
 cmd:=exec.Command("powershell.exe","-NoProfile","-NonInteractive","-Command",
  "$ErrorActionPreference='Stop';$s=[IO.File]::Open($env:VOLVE_TEST_PEER_LOG,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$r=[IO.StreamReader]::new($s);try{[Console]::Write($r.ReadToEnd())}finally{$r.Dispose()}}finally{$s.Dispose()}")
 cmd.Env=append(os.Environ(),"VOLVE_TEST_PEER_LOG="+path)
 out,err:=cmd.CombinedOutput()
 if err!=nil||string(out)!=marker+"\n"{t.Fatalf("native PowerShell shared reader failed: %q %v",out,err)}
}
