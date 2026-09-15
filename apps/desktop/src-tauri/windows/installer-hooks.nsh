!macro ARTIFACTA_INSPECT_VERB EXTENSION
  WriteRegStr HKCU "Software\Classes\SystemFileAssociations\${EXTENSION}\shell\ArtifactaInspect" "" "Inspect with Artifacta"
  WriteRegStr HKCU "Software\Classes\SystemFileAssociations\${EXTENSION}\shell\ArtifactaInspect" "Icon" "$INSTDIR\${MAINBINARYNAME}.exe,0"
  WriteRegStr HKCU "Software\Classes\SystemFileAssociations\${EXTENSION}\shell\ArtifactaInspect\command" "" '$\"$INSTDIR\${MAINBINARYNAME}.exe$\" --analyze $\"%1$\"'
!macroend

!macro ARTIFACTA_REMOVE_INSPECT_VERB EXTENSION
  DeleteRegKey HKCU "Software\Classes\SystemFileAssociations\${EXTENSION}\shell\ArtifactaInspect"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\*\shell\Artifacta" "" "Inspect with Artifacta"
  WriteRegStr HKCU "Software\Classes\*\shell\Artifacta" "Icon" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
  WriteRegStr HKCU "Software\Classes\*\shell\Artifacta\command" "" '$\"$INSTDIR\${MAINBINARYNAME}.exe$\" --analyze $\"%1$\"'
  !insertmacro ARTIFACTA_INSPECT_VERB ".exe"
  !insertmacro ARTIFACTA_INSPECT_VERB ".dll"
  !insertmacro ARTIFACTA_INSPECT_VERB ".sys"
  !insertmacro ARTIFACTA_INSPECT_VERB ".scr"
  !insertmacro ARTIFACTA_INSPECT_VERB ".cpl"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; The installed binary calls documented userenv APIs. Failure is intentionally non-fatal so an
  ; active worker or an already-absent profile cannot prevent uninstall.
  ExecWait '$\"$INSTDIR\${MAINBINARYNAME}.exe$\" --cleanup-appcontainers'
  DeleteRegKey HKCU "Software\Classes\*\shell\Artifacta"
  !insertmacro ARTIFACTA_REMOVE_INSPECT_VERB ".exe"
  !insertmacro ARTIFACTA_REMOVE_INSPECT_VERB ".dll"
  !insertmacro ARTIFACTA_REMOVE_INSPECT_VERB ".sys"
  !insertmacro ARTIFACTA_REMOVE_INSPECT_VERB ".scr"
  !insertmacro ARTIFACTA_REMOVE_INSPECT_VERB ".cpl"
!macroend
