// Command stageci is a CI-only, read-only publication gate for a VOLVE EXE.
// It requires BOTH an externally supplied trusted publisher Authenticode
// certificate/file pin AND an independently trusted Ed25519 bundle manifest.
// It extracts synthetic assets solely to a fresh disposable CI lab directory.
// NEVER install, execute components, change DNS, register tasks or ship this
// command as a user installer.
package main

import (
    "context"
    "crypto/ed25519"
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "time"

    "volve.local/installer/singlefile"
)

func main() {
    exe := flag.String("exe", "", "signed Windows PE lab file")
    out := flag.String("out", "", "fresh absolute VOLVE-CI- staging directory")
    keyHex := flag.String("pubkey", "", "trusted synthetic Ed25519 bundle key")
    certSHA := flag.String("certsha", "", "externally pinned Windows signer certificate SHA256")
    exeSHA := flag.String("exesha", "", "externally pinned exact Windows executable SHA256")
    flag.Parse()

    // Safety boundary: a CI lab harness, NOT a product installation CLI.
    if os.Getenv("GITHUB_ACTIONS") != "true" ||
        os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
        fmt.Fprintln(os.Stderr, "REFUSED: disposable hosted CI required")
        os.Exit(2)
    }
    if *exe == "" || *out == "" || *certSHA == "" || *exeSHA == "" {
        fmt.Fprintln(os.Stderr, "REFUSED: signed EXE, destination and independent publisher pins required")
        os.Exit(2)
    }
    key, err := hex.DecodeString(*keyHex)
    if err != nil || len(key) != ed25519.PublicKeySize {
        fmt.Fprintln(os.Stderr, "REFUSED: externally trusted Ed25519 publisher key missing")
        os.Exit(2)
    }
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    // Gate 1: Authenticode must be Windows-valid and match BOTH external pins.
    // On non-Windows builds this gate fails closed.
    if err := verifyWindowsPublisher(ctx, *exe, *certSHA, *exeSHA); err != nil {
        fmt.Fprintln(os.Stderr, "REFUSED: Windows publisher attestation:", err)
        os.Exit(1)
    }

    // Gate 2: signed ZIP payload, exact 8 components, hash, and second
    // verification after staging. StageInLab creates NO destination until
    // it has inspected the complete signed embedded bundle.
    manifest, err := singlefile.StageInLab(*exe, ed25519.PublicKey(key), *out)
    if err != nil {
        fmt.Fprintln(os.Stderr, "REFUSED: embedded bundle or lab staging:", err)
        os.Exit(1)
    }
    fmt.Printf("PASS VOLVE_DUAL_SIGNED_STAGE_LAB release=%s items=%d NO_INSTALL NO_DNS_CHANGE\n", manifest.Release, len(manifest.Components))
}
