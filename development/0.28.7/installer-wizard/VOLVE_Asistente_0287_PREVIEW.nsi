; VOLVE 0.28.7 — wizard visual de consentimiento, prototipo NO OPERATIVO.
; Nunca cambiar a un nombre de instalador productivo sin un backend firmado,
; restauracion certificada y pruebas de Windows despues de reiniciar.
Unicode true
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"

Name "VOLVÉ - Asistente (DEMO SIN PROTECCIÓN)"
OutFile "VOLVE_Asistente_VistaPrevia_0287.exe"
RequestExecutionLevel user
SetBrandingText "VOLVÉ 0.28.7 | Vista previa sin protección"
InstallDir "$LOCALAPPDATA\VOLVE-Preview"
ShowInstDetails show
SetCompressor /SOLID lzma
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Bienvenido a VOLVÉ"
!define MUI_WELCOMEPAGE_TEXT "Este asistente muestra las pantallas previstas para instalar VOLVÉ.\r\n\r\nVISTA PREVIA: NO instala el motor, NO bloquea apuestas ni modifica Windows.\r\n\r\nLa versión final deberá pedir permisos de administrador, crear un respaldo verificable y probar que puede recuperar la conectividad."
!define MUI_LICENSEPAGE_CHECKBOX
!define MUI_FINISHPAGE_TITLE "Vista previa completada"
!define MUI_FINISHPAGE_TEXT "Revisaste el flujo de instalación de VOLVÉ.\r\n\r\nNO hay protección instalada o activada por esta demostración. No se guardaron preferencias, no se configuró DNS y no se registraron tareas ni servicios."

Var ConsentDlg
Var ConsentDNS
Var ConsentSYSTEM
Var ConsentBrowser
Var ConsentUpdates
Var ConsentRestrictions
Var PeriodDlg
Var Period7
Var Period30
Var Period90
Var PeriodValue
Var SummaryDlg
Var SummaryAgree

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "TERMINOS_PREVIEW_0287.txt"
Page custom PermissionsPage PermissionsLeave
Page custom CommitmentPage CommitmentLeave
Page custom SummaryPage SummaryLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "Spanish"

Function PermissionsPage
 !insertmacro MUI_HEADER_TEXT "Permisos de VOLVÉ" "Revisá cada autorización antes de continuar."
 nsDialogs::Create 1018
 Pop $ConsentDlg
 ${If} $ConsentDlg == error
  Abort
 ${EndIf}
 ${NSD_CreateLabel} 0 0u 100% 22u "Marcá las cinco casillas. En esta demostración no se aplica ningún cambio."
 Pop $0
 ${NSD_CreateCheckbox} 0 24u 100% 17u "Configurar DNS IPv4 e IPv6 (con respaldo y recuperación)."
 Pop $ConsentDNS
 ${NSD_CreateCheckbox} 0 42u 100% 17u "Crear tareas de arranque y recuperación SYSTEM."
 Pop $ConsentSYSTEM
 ${NSD_CreateCheckbox} 0 60u 100% 17u "Aplicar políticas de bloqueo en navegadores compatibles."
 Pop $ConsentBrowser
 ${NSD_CreateCheckbox} 0 78u 100% 17u "Actualizar automáticamente catálogos y paquetes firmados."
 Pop $ConsentUpdates
 ${NSD_CreateCheckbox} 0 98u 100% 32u "Entiendo el plazo del compromiso, las restricciones habituales de desactivación y el retiro o reparación autorizado."
 Pop $ConsentRestrictions
 nsDialogs::Show
FunctionEnd

Function PermissionsLeave
 ${NSD_GetState} $ConsentDNS $0
 ${If} $0 != ${BST_CHECKED}
  MessageBox MB_OK|MB_ICONEXCLAMATION "Para seguir, revisá y aceptá expresamente la configuración DNS o cancelá la instalación."
  Abort
 ${EndIf}
 ${NSD_GetState} $ConsentSYSTEM $0
 ${If} $0 != ${BST_CHECKED}
  MessageBox MB_OK|MB_ICONEXCLAMATION "La recuperación SYSTEM requiere consentimiento explícito."
  Abort
 ${EndIf}
 ${NSD_GetState} $ConsentBrowser $0
 ${If} $0 != ${BST_CHECKED}
  MessageBox MB_OK|MB_ICONEXCLAMATION "Revisá la configuración de bloqueo de navegadores."
  Abort
 ${EndIf}
 ${NSD_GetState} $ConsentUpdates $0
 ${If} $0 != ${BST_CHECKED}
  MessageBox MB_OK|MB_ICONEXCLAMATION "Las actualizaciones firmadas de reglas son necesarias para esta modalidad."
  Abort
 ${EndIf}
 ${NSD_GetState} $ConsentRestrictions $0
 ${If} $0 != ${BST_CHECKED}
  MessageBox MB_OK|MB_ICONEXCLAMATION "Debés entender cómo funciona el compromiso y la recuperación autorizada."
  Abort
 ${EndIf}
FunctionEnd

Function CommitmentPage
 !insertmacro MUI_HEADER_TEXT "Duración del compromiso" "Elegí cuánto tiempo querés mantener las restricciones."
 nsDialogs::Create 1018
 Pop $PeriodDlg
 ${If} $PeriodDlg == error
  Abort
 ${EndIf}
 ${NSD_CreateLabel} 0 0u 100% 28u "Esta elección no se guarda en la demo. La versión final exigirá una política firmada."
 Pop $0
 ${NSD_CreateRadioButton} 0 30u 100% 17u "7 días de protección"
 Pop $Period7
 ${NSD_CreateRadioButton} 0 49u 100% 17u "30 días de protección"
 Pop $Period30
 ${NSD_CreateRadioButton} 0 68u 100% 17u "90 días de protección"
 Pop $Period90
 ${If} $PeriodValue == "30"
  ${NSD_Check} $Period30
 ${ElseIf} $PeriodValue == "90"
  ${NSD_Check} $Period90
 ${Else}
  ${NSD_Check} $Period7
 ${EndIf}
 ${NSD_CreateLabel} 0 96u 100% 38u "El retiro ordinario puede requerir autorización de soporte; siempre debe existir recuperación de emergencia por fallas de conectividad."
 Pop $0
 nsDialogs::Show
FunctionEnd

Function CommitmentLeave
 ${NSD_GetState} $Period7 $0
 ${If} $0 == ${BST_CHECKED}
  StrCpy $PeriodValue "7"
  Return
 ${EndIf}
 ${NSD_GetState} $Period30 $0
 ${If} $0 == ${BST_CHECKED}
  StrCpy $PeriodValue "30"
  Return
 ${EndIf}
 ${NSD_GetState} $Period90 $0
 ${If} $0 == ${BST_CHECKED}
  StrCpy $PeriodValue "90"
  Return
 ${EndIf}
 MessageBox MB_OK|MB_ICONEXCLAMATION "Elegí una duración válida para continuar."
 Abort
FunctionEnd

Function SummaryPage
 !insertmacro MUI_HEADER_TEXT "Confirmación final" "Revisá la duración y los límites de la demostración."
 nsDialogs::Create 1018
 Pop $SummaryDlg
 ${If} $SummaryDlg == error
  Abort
 ${EndIf}
 ${NSD_CreateLabel} 0 0u 100% 30u "Se simularon permisos de DNS, SYSTEM, navegadores y actualizaciones. Duración: $PeriodValue días."
 Pop $0
 ${NSD_CreateLabel} 0 36u 100% 41u "La versión final exigirá respaldo, prueba de recuperación y revisión de instalaciones anteriores antes de aplicar cambios."
 Pop $0
 ${NSD_CreateCheckbox} 0 83u 100% 42u "Confirmo que esto es una VISTA PREVIA: no instala nada, no activa el bloqueo y no crea un compromiso real."
 Pop $SummaryAgree
 nsDialogs::Show
FunctionEnd

Function SummaryLeave
 ${NSD_GetState} $SummaryAgree $0
 ${If} $0 != ${BST_CHECKED}
  MessageBox MB_OK|MB_ICONEXCLAMATION "Confirmá que comprendés que esta versión es sólo una vista previa."
  Abort
 ${EndIf}
FunctionEnd

Section "Vista previa sin instalación" SecPreview
 DetailPrint "VOLVÉ 0.28.7 - flujo visual de instalación."
 DetailPrint "Compromiso elegido en memoria: $PeriodValue días (NO GUARDADO)."
 DetailPrint "No se copian archivos ni se registra instalación."
 DetailPrint "No se modifican DNS, tareas SYSTEM, políticas ni servicios."
 DetailPrint "No se abre la red ni se envía telemetría."
 DetailPrint "Resultado: NO INSTALADO / PROTECCIÓN NO ACTIVADA."
SectionEnd
