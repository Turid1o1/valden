!include "LogicLib.nsh"

!macro StopValdenProcesses
  DetailPrint "Stopping running VALDEN processes..."
  StrCpy $R0 0
  ${Do}
    nsExec::ExecToLog 'taskkill /F /T /IM "VALDEN.exe"'
    Pop $0
    nsExec::ExecToLog 'taskkill /F /T /IM "Uninstall VALDEN.exe"'
    Pop $1
    Sleep 900
    IntOp $R0 $R0 + 1
    ${If} $R0 >= 4
      ${ExitDo}
    ${EndIf}
  ${Loop}
!macroend

!macro customInit
  !insertmacro StopValdenProcesses
!macroend

!macro customInstall
  !insertmacro StopValdenProcesses
!macroend

!macro customUnInstall
  !insertmacro StopValdenProcesses
!macroend
