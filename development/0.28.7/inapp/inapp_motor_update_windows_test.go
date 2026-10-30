//go:build windows

package main

import (
    "strings"
    "testing"
)

func TestMergeUpdateReportsPreservesPanelInstallMarker(t *testing.T) {
    panel := "CENTRO: actualización descargada.\nVOLVE_STAGE_READY=C:\\Users\\Prueba\\VOLVE_0_28_8.exe"
    merged := mergeUpdateReports(panel, "MOTOR: versión firmada preparada.")
    if !strings.Contains(merged, "CENTRO: actualización") || !strings.Contains(merged, "MOTOR: versión firmada preparada.") {
        t.Fatal("either component report was lost")
    }
    if strings.Count(merged, "VOLVE_STAGE_READY=") != 1 {
        t.Fatal("the panel install marker must occur exactly once")
    }
    if !strings.HasSuffix(merged, "\nVOLVE_STAGE_READY=C:\\Users\\Prueba\\VOLVE_0_28_8.exe") {
        t.Fatal("the existing UI must receive the complete staged Centre path on the last line")
    }
}

func TestMergeUpdateReportsNoPanelCandidate(t *testing.T) {
    got := mergeUpdateReports("CENTRO: ya está actualizado.", "MOTOR: no publicado.")
    if got != "CENTRO: ya está actualizado.\n\nMOTOR: no publicado." {
        t.Fatalf("unexpected report %q", got)
    }
    if strings.Contains(got, "VOLVE_STAGE_READY=") {
        t.Fatal("must never fabricate an install candidate")
    }
}
