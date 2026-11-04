//go:build !windows

package uninstallguard

import (
    "context"
    "errors"
)

func InspectWindowsReadOnly(context.Context)(Evidence,error){
    return Evidence{},errors.New("native Windows read-only uninstall census required")
}
