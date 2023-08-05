@echo off

Title Detecting permissions...

net user "%username%" | find /i "*Administrators" >nul 2>&1
if errorlevel 1 GOTO :adminaccfail
if not errorlevel 1 GOTO :admincheck

:adminaccfail
echo This current user is not administrator.
pause
exit

:admincheck
net session >nul 2>&1
if errorlevel 1 GOTO :adminfail
if not errorlevel 1 GOTO :adminsuccess

:adminfail
echo Please launch in administrator.
pause
exit

:adminsuccess
Title Checking network status...

Timeout /T 1 /NoBreak>nul
Ping www.kernel.org -n 1 -w 1000>nul
if errorlevel 1 GOTO :networkfail
if not errorlevel 1 GOTO :networksuccess

:networkfail
echo Sorry, you need internet to apply DuckOS to your computer.
pause
exit

:networksuccess
Title DuckOS installation
echo Welcome to the DuckOS installation.
echo Before starting the installation, DuckOS will have to disable Windows Defender so that it doesn't interfere with the installation.
echo If you have any other kind of an antivirus, please disable it until the installation is complete.
pause

cls

echo Disabling Windows Defender...
sc stop WinDefend
echo Done.

cls

echo DuckOS is ready to be installed to your computer, add some more text here later.
et /P c=Yes (Y) or No (N)
if /I "%c%" EQU "Y" goto :microsoft_edge_question
if /I "%c%" EQU "N" goto :networksuccess
pause

cls

:microsoft_edge_question
echo Do you want Microsoft Edge?
et /P c=Yes (Y) or No (N)
if /I "%c%" EQU "Y" goto :remove_microsoft_edge
if /I "%c%" EQU "N" goto :onedrive_question

:remove_microsoft_edge
cls
Title Removing Microsoft Edge
echo Killing tasks
taskkill /F /IM MicrosoftEdge
taskkill /F /IM MicrosoftEdgeUpdate
taskkill /F /IM msedge
taskkill /F /IM msedgewebview2
echo Removing services
sc delete MicrosoftEdgeElevationService
sc delete edgeupdatem
sc delete edgeupdate
echo Removing registry
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1
REG DELETE "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMigratedBrowserPin" /f
REG DELETE "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" /f
REG DELETE "HKCR\CLSID\{1FCBE96C-1697-43AF-9140-2897C7C69767}" /f
REG DELETE "HKCR\AppID\{1FCBE96C-1697-43AF-9140-2897C7C69767}" /f
REG DELETE "HKLM\SOFTWARE\WOW6432Node\Microsoft\Edge" /f
REG DELETE "HKCR\Interface\{C9C2B807-7731-4F34-81B7-44FF7779522B} /f
REG DELETE "HKCR\TypeLib\{C9C2B807-7731-4F34-81B7-44FF7779522B}" /f
REG DELETE "HKCR\MSEdgeHTM" /f
REG DELETE "HKCR\MSEdgePDF" /f
REG DELETE "HKCR\MSEdgeMHT" /f
REG DELETE "HKCR\AppID\{628ACE20-B77A-456F-A88D-547DB6CEEDD5}" /f
REG DELETE "HKLM\SOFTWARE\Clients\StartMenuInternet\Microsoft Edge" /f
REG DELETE "HKLM\SOFTWARE\RegisteredApplications" /v "Microsoft Edge" /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" /f
REG DELETE "HKCR\.htm\OpenWithProgIds" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.html\OpenWithProgIds" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.shtml\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.svg\OpenWithProgIds" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.xht\OpenWithProgIds" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.xhtml\OpenWithProgIds" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.webp\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCR\.xml\OpenWithProgIds" /v "MSEdgeHTM" /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "MSEdgeHTM_microsoft-edge" /f
REG DELETE "HKCR\AppID\ie_to_edge_bho.dll" /f
REG DELETE "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Microsoft Edge Update" /f
REG DELETE "HKCU\SOFTWARE\RegisteredApplications" /v "Microsoft Edge" /f
REG DELETE "HKCU\SOFTWARE\Classes\.htm\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Classes\.html\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Classes\.shtml\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Classes\.svg\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Classes\.xht\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Classes\.xhtml\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Classes\.webp\OpenWithProgids" /v "MSEdgeHTM" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "MSEdgeHTM_microsoft-edge" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\Edge" /f
REG DELETE "HKCU\SOFTWARE\Microsoft\EdgeWebView" /f
REG DELETE "HKCR\AppID\{31575964-95F7-414B-85E4-0E9A93699E13}" /f
REG DELETE "HKCR\CLSID\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}" /f
REG DELETE "HKCR\WOW6432Node\CLSID\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}" /f
REG DELETE "HKCR\ie_to_edge_bho.IEToEdgeBHO" /f
REG DELETE "HKCR\ie_to_edge_bho.IEToEdgeBHO.1" /f
echo Removing Microsoft Edge
cd /d "%ProgramFiles(x86)%\Microsoft"
for /f "tokens=1 delims=\" %%i in ('dir /B /A:D "%ProgramFiles(x86)%\Microsoft\Edge\Application" ^| find "."') do (set "edge_chromium_package_version=%%i")
if defined edge_chromium_package_version (
		Edge\Application\%edge_chromium_package_version%\Installer\setup.exe --uninstall --force-uninstall --msedge --system-level --verbose-logging
		EdgeCore\%edge_chromium_package_version%\Installer\setup.exe --uninstall --force-uninstall --msedge --system-level --verbose-logging
		powershell.exe -Command "Get-AppxPackage *MicrosoftEdge* | Remove-AppxPackage"
	)
for /f "tokens=8 delims=\" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" ^| findstr "Microsoft-Windows-MicrosoftEdgeDevToolsClient-Package" ^| findstr "~~"') do (set "melody_package_name=%%i")
if defined melody_package_name (
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\%melody_package_name%" /v Visibility /t REG_DWORD /d 1 /f
		reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\%melody_package_name%\Owners" /va /f
		dism /online /Remove-Package /PackageName:%melody_package_name% /NoRestart
	)
goto :onedrive_question

:onedrive_question
cls
echo Do you want OneDrive?
et /P c=Yes (Y) or No (N)
if /I "%c%" EQU "Y" goto :remove_onedrive
if /I "%c%" EQU "N" goto :placeholder

:remove_onedrive
cls
pause
exit


:start_installation
Title Getting Ready...





