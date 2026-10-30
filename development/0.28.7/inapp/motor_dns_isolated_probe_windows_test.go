//go:build windows

package main

import (
    "strings"
    "testing"
)

func TestMotorDNSIsolatedLoopbackProof(t *testing.T){
    report,err:=runMotorDNSIsolatedLoopbackProof()
    if err!=nil{t.Fatalf("real VOLVE DNS engine core failed on loopback: %v",err)}
    for _,expected:=range []string{
        "VOLVE_DNS_ISOLATED_LOOPBACK_OK",
        "5 consultas DNS respondidas correctamente",
        "3 bloqueadas, 2 permitidas",
        "Windows NO modificado",
    }{
        if !strings.Contains(report,expected){t.Fatalf("missing runtime DNS evidence %q from %q",expected,report)}
    }
    t.Log(report)
}
