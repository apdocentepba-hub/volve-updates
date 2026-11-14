; VOLVE 0.28.7 — wizard visual de consentimiento, prototipo NO OPERATIVO.
; Nunca cambiar a un nombre de instalador productivo sin un backend firmado,
; restauracion certificada y pruebas de Windows despues de reiniciar.
Unicode true
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"

Name "VOLVÉ — Asistente (VISTA PREVIA SIN PROTECCIÓN)"
OutFile "VOLVE_Asistente_VistaPrevia_0287.exe"
RequestExecutionLevel user
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
 nsDialogs::Create 1018
 Pop $ConsentDlg
 ${If} $ConsentDlg == error
  Abort
 ${EndIf}
 ${NSD_CreateLabel} 0 0u 100% 35u "Permisos requeridos por la futura versión (ningún permiso se concede en esta vista previa)."
 Pop $0
 ${NSD_CreateCheckbox} 0 40u 100% 20u "Permitir configurar el DNS de IPv4 e IPv6 (con respaldo y reversión)."
 Pop $ConsentDNS
 ${NSD_CreateCheckbox} 0 63u 100% 20u "Permitir tareas de arranque y recuperación bajo SYSTEM."
 Pop $ConsentSYSTEM
 ${NSD_CreateCheckbox} 0 86u 100% 20u "Permitir políticas de bloqueo en navegadores compatibles."
 Pop $ConsentBrowser
 ${NSD_CreateCheckbox} 0 109u 100% 20u "Permitir descargas automáticas de reglas y paquetes firmados."
 Pop $ConsentUpdates
 ${NSD_CreateCheckbox} 0 132u 100% 35u "Comprendo que el compromiso elegido limita la desactivación habitual; habrá una vía de recuperación y retiro autorizado."
 Pop $ConsentRestrictions
 ${NSD_CreateLabel} 0 183u 100% 35u "La aprobación puede cancelarse antes de activar la instalación. Ninguna autorización equivale a perder el control administrativo del equipo para siempre."
 Pop $0
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
 nsDialogs::Create 1018
 Pop $PeriodDlg
 ${If} $PeriodDlg == error
  Abort
 ${EndIf}
 ${NSD_CreateLabel} 0 0u 100% 35u "Elegí la duración del compromiso de protección. En el futuro este valor será una política firmada, no un bloqueo imposible de revertir."
 Pop $0
 ${NSD_CreateRadioButton} 0 50u 100% 19u "7 días de protección"
 Pop $Period7
 ${NSD_CreateRadioButton} 0 77u 100% 19u "30 días de protección"
 Pop $Period30
 ${NSD_CreateRadioButton} 0 104u 100% 19u "90 días de protección"
 Pop $Period90
 ${If} $PeriodValue == "30"
  ${NSD_Check} $Period30
 ${ElseIf} $PeriodValue == "90"
  ${NSD_Check} $Period90
 ${Else}
  ${NSD_Check} $Period7
 ${EndIf}
 ${NSD_CreateLabel} 0 151u 100% 65u "Durante el compromiso, la desactivación ordinaria estará restringida. El soporte podrá emitir una autorización de retiro limitada y verificable. También existirá recuperación de emergencia en caso de fallas de conectividad o seguridad."
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
 nsDialogs::Create 1018
 Pop $SummaryDlg
 ${If} $SummaryDlg == error
  Abort
 ${EndIf}
 ${NSD_CreateLabel} 0 0u 100% 50u "Resumen: permisos de DNS, tareas SYSTEM, navegadores y reglas firmadas, todos aceptados en esta simulación. Duración elegida: $PeriodValue días."
 Pop $0
 ${NSD_CreateLabel} 0 60u 100% 56u "En la versión final, antes de activar cualquier bloqueo se verificará el respaldo, la conectividad y la recuperación. El instalador rechazará instalaciones previas no migrables."
 Pop $0
 ${NSD_CreateCheckbox} 0 135u 100% 55u "Confirmo que esta es una VISTA PREVIA: no instalará ni activará protección, no creará una exclusión y no habrá cambios en mi equipo."
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
