//go:build !windows

package main

import (
    "context"
    "errors"
)

// Never allow a POSIX runner to claim that it verified Windows Authenticode.
func verifyWindowsPublisher(_ context.Context, _, _, _ string) error {
    return errors.New("native Windows Authenticode verification required")
}
