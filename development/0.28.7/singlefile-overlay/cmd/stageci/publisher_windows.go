//go:build windows

package main

import (
    "context"

    "volve.local/installer/singlefile"
)

// Windows trust is evaluated by OS Authenticode with external certificate
// and exact file pins. No user-controlled bypass or unsigned fallback.
func verifyWindowsPublisher(ctx context.Context, exe, certPin, exePin string) error {
    return singlefile.VerifyWindowsPublisherSignature(ctx, exe, certPin, exePin)
}
