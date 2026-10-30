//go:build windows

package main

import (
    "errors"
    "fmt"
    "strings"

    "volve-browser-protection/dnsproxy"
)

// runMotorDNSIsolatedLoopbackProof exercises the REAL DNS proxy code used by
// VOLVE's resident motor. It starts a temporary local UDP listener on a
// dynamically allocated port and a fake local upstream. It NEVER invokes
// runDNSService, port 53, Windows adapter settings, Task Scheduler, hosts,
// browser policies or the production blocklist.
func runMotorDNSIsolatedLoopbackProof() (string,error) {
    report,err:=dnsproxy.SelfTest()
    if err!=nil{return "",fmt.Errorf("motor DNS aislado no supera consultas: %w",err)}
    // Keep this a verified, fixed-contract probe; a future SelfTest that
    // silently skips queries must not pass the release gate.
    if !strings.Contains(report,"5 consultas DNS respondidas correctamente") ||
        !strings.Contains(report,"3 bloqueadas, 2 permitidas") ||
        !strings.Contains(report,"Puerto local temporal") {
        return "",errors.New("motor DNS aislado devolvió evidencia incompleta")
    }
    return "VOLVE_DNS_ISOLATED_LOOPBACK_OK: "+report,nil
}
