!macro customInit
  nsExec::ExecToStack 'taskkill /IM "VALDEN.exe" /F'
  Pop $0
!macroend

!macro customUnInstall
  nsExec::ExecToStack 'taskkill /IM "VALDEN.exe" /F'
  Pop $0
!macroend
