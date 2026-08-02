; Castiel NSIS Installer Script
; Build with: makensis castiel.nsi

!define APPNAME "Castiel"
!define VERSION "0.1.0"
!define PUBLISHER "Castiel"
!define INSTALLDIR "C:\Program Files\Castiel"
!define SERVICE_NAME "Castiel"

Name "${APPNAME}"
OutFile "castiel-${VERSION}-setup.exe"
InstallDir "${INSTALLDIR}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel admin
Unicode true

;--------------------------------
; Pages

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------
; Install Section

Section "Install"
    SetOutPath "$INSTDIR"

    ; Copy files
    File "castiel.exe"
    File "config.yaml"
    File /r "data"
    File "doh-killswitch.ps1"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Registry entries
    WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME} DNS Defense Daemon"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${PUBLISHER}"

    ; Install Windows Service
    nsExec::Exec 'sc.exe create ${SERVICE_NAME} binPath= "$INSTDIR\castiel.exe -config $INSTDIR\config.yaml" start= auto'
    nsExec::Exec 'sc.exe description ${SERVICE_NAME} "Castiel DNS Defense Daemon - DGA detection, tunneling prevention, DNSSEC validation"'
    nsExec::Exec 'sc.exe failure ${SERVICE_NAME} reset= 86400 actions= restart/5000/restart/10000/restart/30000'

    ; Configure DNS redirect
    nsExec::Exec 'netsh interface ip set dns "Ethernet" static 127.0.0.1'
    nsExec::Exec 'netsh interface ip set dns "Wi-Fi" static 127.0.0.1'

    ; Start service
    nsExec::Exec 'sc.exe start ${SERVICE_NAME}'

    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\${APPNAME}"
    CreateShortcut "$SMPROGRAMS\${APPNAME}\Castiel.lnk" "$INSTDIR\castiel.exe" "-config $INSTDIR\config.yaml"
    CreateShortcut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

    ; Show completion
    MessageBox MB_OK "Castiel ${VERSION} has been installed successfully.$\r$\n$\r$\nThe Castiel service is now running.$\r$\nDNS has been set to 127.0.0.1 on active adapters."
SectionEnd

;--------------------------------
; Uninstall Section

Section "Uninstall"
    ; Stop and delete service
    nsExec::Exec 'sc.exe stop ${SERVICE_NAME}'
    Sleep 2000
    nsExec::Exec 'sc.exe delete ${SERVICE_NAME}'

    ; Restore DNS
    nsExec::Exec 'netsh interface ip set dns "Ethernet" dhcp'
    nsExec::Exec 'netsh interface ip set dns "Wi-Fi" dhcp'

    ; Remove portproxy rules
    nsExec::Exec 'netsh interface portproxy delete v4tov4 listenport=53 protocol=tcp'
    nsExec::Exec 'netsh interface portproxy delete v4tov4 listenport=53 protocol=udp'

    ; Delete files
    Delete "$INSTDIR\castiel.exe"
    Delete "$INSTDIR\config.yaml"
    Delete "$INSTDIR\doh-killswitch.ps1"
    Delete "$INSTDIR\uninstall.exe"
    RMDir /r "$INSTDIR\data"
    RMDir "$INSTDIR"

    ; Remove shortcuts
    Delete "$SMPROGRAMS\${APPNAME}\Castiel.lnk"
    Delete "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${APPNAME}"

    ; Remove registry entries
    DeleteRegKey HKLM "Software\${APPNAME}"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

    MessageBox MB_OK "Castiel has been uninstalled.$\r$\n$\r$\nDNS has been restored to DHCP defaults."
SectionEnd
