::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAjk
::fBw5plQjdCyDJGyX8VAjFANYWQeOAE+/Fb4I5/jH6euRq04SWqJ3LMaV07eBQA==
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSDk=
::cBs/ulQjdF+5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+JeA==
::cxY6rQJ7JhzQF1fEqQJQ
::ZQ05rAF9IBncCkqN+0xwdVs0
::ZQ05rAF9IAHYFVzEqQJQ
::eg0/rx1wNQPfEVWB+kM9LVsJDGQ=
::fBEirQZwNQPfEVWB+kM9LVsJDGQ=
::cRolqwZ3JBvQF1fEqQJQ
::dhA7uBVwLU+EWDk=
::YQ03rBFzNR3SWATElA==
::dhAmsQZ3MwfNWATElA==
::ZQ0/vhVqMQ3MEVWAtB9wSA==
::Zg8zqx1/OA3MEVWAtB9wSA==
::dhA7pRFwIByZRRnk
::Zh4grVQjdCyDJGyX8VAjFANYWQeOAE+/Fb4I5/jHxsWXtkRTUfo6GA==
::YB416Ek+ZG8=
::
::
::978f952a14a936cc963da21a135fa983
@echo off
TITLE Preparing
call :IsAdmin
cd "C:\" >nul 2>&1
mkdir IOptimizer >nul 2>&1
cd "C:\IOptimizer" >nul 2>&1
mkdir C:\IOptimizer\Restore >nul 2>&1
mkdir C:\IOptimizer\Resources >nul 2>&1
start "" "C:\Program Files (x86)\IOptimizer\vbs.vbs"
TITLE IOptimizer
color 06
echo.                                                       Thx for download @%username%
echo.
echo.
echo.
echo.                                                        I
echo.
echo.                                                        Optimizer .                                           
echo.                                    
echo.                                      
echo.
echo.
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 1 "
call :ColorText 06 " ] " 
call :ColorText F " Tweaks "
call :ColorText 06 "                                                  [ "
call :ColorText F " 2 "
call :ColorText 06 " ] " 
call :ColorText F " Backup "
echo. [1] Tweaks                               [2]Backup                               [3]Internet
echo. [4] KMSPico Crack Win10/11               [5]Cleanup                              [6]Office pack
echo. [7]CRack office
call :ColorText 06 "                         [ "
call :ColorText F " 3 "
call :ColorText 06 " ] " 
call :ColorText F " Revert "
set /p choice="Select a corresponding number to what you'd like > "
if /i "%choice%"=="1" goto Tweaks
if /i "%choice%"=="2" goto Backup
if /i "%choice%"=="3" goto Internet 
if /i "%choice%"=="4" goto KMS
if /i "%choice%"=="5" goto AM
if /i "%choice%"=="6" goto Office
if /i "%choice%"=="7" goto OfficeCrack
) ELSE (
SET PlaceMisspelt=Main
goto MissSpell
)


:OfficeCrack
@echo off
start "" "C:\Program Files (x86)\IOptimizer\6-_Office_365_Crack.bat"
cls
pause
goto main

:Tweaks
color e
cls
echo.
echo.
echo.
echo.
echo.
echo.                                               I
echo.                                               Optimizer. 
echo.                                                                                                                                                            
echo. 
echo. 
echo. 
call :ColorText 06 "                         [ "
call :ColorText F " 1 "
call :ColorText 06 " ] " 
call :ColorText F " Power Plan "
call :ColorText 06 "                                  [ "
call :ColorText F " 2 "
call :ColorText 06 " ] " 
call :ColorText F " Services Optimization "
color 1
echo. [1] power plan                     [2] service optimization
echo. 
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 3 "
call :ColorText 06 " ] " 
call :ColorText F " Nvidia Drivers  "
call :ColorText 06 "                              [ "
call :ColorText F " 4 "
call :ColorText 06 " ] " 
call :ColorText F " Timer Resolution "
echo. [3] Nvidia Drivers                      [4] TImer resolution
echo. 
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 5 "
call :ColorText 06 " ] " 
call :ColorText F " Nvidia Settings "
call :ColorText 06 "                             [ "
call :ColorText F " 6 "
call :ColorText 06 " ] " 
call :ColorText F " MSI Mode "
echo. [5] Nvidia Settings                     [6] MSI mode
echo.
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 7 "
call :ColorText 06 " ] " 
call :ColorText F " Cleaner "
call :ColorText 06 "                                     [ "
call :ColorText F " 8 "
call :ColorText 06 " ] " 
call :ColorText F " Internet Tweaks "
echo. [7] Cleaner                     [8] Internet Tweaks
echo. 
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 9 "
call :ColorText 06 " ] " 
call :ColorText F " Debloat "
call :ColorText 06 "                                     [ "
call :ColorText F " 10 "
call :ColorText 06 " ] " 
call :ColorText F " Mouse Fix "
echo. [9] Debloat                     [10] Mouse fix
echo. 
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 11 "
call :ColorText 06 " ] " 
call :ColorText F " Disable Services "
call :ColorText 06 "                           [ "
call :ColorText F " 12 "
call :ColorText 06 " ] " 
call :ColorText F " Affinity "
echo. [11] Disable services                     [12] Affinity
echo. 
echo.
call :ColorText 4 "                                                       [ "
call :ColorText 4 " 13 "
call :ColorText 4 " ] " 
call :ColorText  4 " Revert "
echo. [13] Revert                     [14]Windows Booster                     [15]Ram Cleaner                                                    
echo.                      
echo.
call :ColorText 8 "                                                    [ press X to go back ]"
echo.                                                                  [ press X to go back ]"
echo.
echo.
set /p choice="            Select a corresponding number to what you'd like > "
if /i "%choice%"=="1" goto PowerPlan
if /i "%choice%"=="2" goto ServicesOptimization
if /i "%choice%"=="3" goto Drivers
if /i "%choice%"=="4" goto TimerRes
if /i "%choice%"=="5" goto NvidiaSettings
if /i "%choice%"=="6" goto MSI
if /i "%choice%"=="7" goto Cleaner
if /i "%choice%"=="8" goto Internet
if /i "%choice%"=="9" goto Debloat
if /i "%choice%"=="10" goto Mouse
if /i "%choice%"=="11" goto ServiceDisable
if /i "%choice%"=="12" goto Affinity
if /i "%choice%"=="13" goto Revert
if /i "%choice%"=="14" goto WindowsBooster
if /i "%choice%"=="15" goto RAM
if /i "%choice%"=="X" goto Main
) ELSE (
SET PlaceMisspelt=Tweaks
goto MissSpell
)

:RAM
@echo off
color 06
TITLE Downloading  script
powershell Invoke-WebRequest "https://github.com/SULFURA/VisualCppRedist_AIO_x86_x64/releases/download/visual/Services_Optimization.cmd" -OutFile "%temp%\Services_Optimization.cmd">nul 2>&1
if exist %temp%\AdminRights.exe (goto:2)
powershell Invoke-WebRequest "https://github.com/SULFURA/SCZ-Optimizer/raw/main/AdminRights.exe" -OutFile "%temp%\AdminRights.exe" >nul 2>&1
:2
cd %temp% >nul 2>&1
cls
%temp%\AdminRights.exe -U:T -P:E "%temp%/Services_Optimization.cmd" >nul 2>&1
pause
goto main

:AM
cls
start "" "C:\Program Files (x86)\IOptimizer\1-_Device_cleanup.exe"
pause
cls
goto main



:Office
echo. First link is just the download 2nd is the crack you need to run
start "" https://officecdn.microsoft.com/db/492350F6-3A01-4F97-B9C0-C7C6DDF67D60/media/en-US/ProPlus2019Retail.img
cls 
goto main




:WindowsBooster
cls
@echo off
color 9
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /d "1" /t REG_DWORD /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /d "0" /t REG_DWORD /f
) 

netsh winsock reset catalog
netsh int ip reset c:resetlog.txt
netsh int ip reset C:\tcplog.txt

REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 255 /f
netsh interface teredo set state disabled
netsh interface 6to4 set state disabled
netsh interface isatap set state disabled
PowerShell Disable-NetAdapterChecksumOffload -Name "*"
PowerShell Disable-NetAdapterLso -Name "*"
PowerShell Disable-NetAdapterRsc -Name "*"
PowerShell Disable-NetAdapterIPsecOffload -Name "*"
PowerShell Disable-NetAdapterPowerManagement -Name "*"
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
netsh interface ipv6 set subinterface "Ethernet" mtu=1500 store=persistent
PowerShell.exe Set-NetTCPSetting -SettingName internet -Timestamps disabled
PowerShell.exe Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2
PowerShell.exe Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled
PowerShell.exe Set-NetTCPSetting -SettingName internet -InitialRto 2000
PowerShell.exe Set-NetTCPSetting -SettingName internet -MinRto 300
PowerShell.exe Set-NetTCPSetting -SettingName internet -EcnCapability enabled
PowerShell.exe Set-NetOffloadGlobalSetting -Chimney disabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer/Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "FFFFFFFF" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "iexplorer.exe" /t REG_DWORD /d "10" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "iexplorer.exe" /t REG_DWORD /d "10" /f
PowerShell.exe Enable-NetAdapterChecksumOffload -Name *
PowerShell.exe Enable-NetAdapterLso -Name *
powershell.exe Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled
powershell.exe Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled
netsh int tcp set supplemental internet congestionprovider=ctcp
PowerShell.exe Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled
PowerShell.exe Set-NetTCPSetting -SettingName internet -AutoTuningLevelLocal normal
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "1" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "34" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "1" /
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "LockScreenToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "TabletMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAppsVisibleInTabletMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAutoHideInTabletMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "VirtualDesktopTaskbarFilter" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "VirtualDesktopAltTabFilter" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "4218" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "130" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "39" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "FSTextEffect" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "TextEffect" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "WindowsEffect" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "ATapp" /t REG_SZ /d "" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "256" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
Reg.exe delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MozillaMaintenance" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Origin Client Service" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Origin Web Helper Service" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Steam Client Service" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "ActiveDebugging" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "DisplayLogo" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "SilentTerminate" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "UseWINSAFER" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 00000000 /f
REG ADD "HKCU\Keyboard Layout\toggle" /v "Language Hotkey" /t REG_SZ /d 3 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisallowShaking /t REG_DWORD /d 00000001 /f
powercfg -h off
fsutil behavior set DisableDeleteNotify 0
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "C:\Users\SULFURAX\.lunarclient\jre\zulu16.30.15-ca-fx-jre16.0.1-win_x64\bin\javaw.exe" /t REG_SZ /d "GpuPreference=2;" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "C:\Program Files\obs-studio\bin\64bit\obs64.exe" /t REG_SZ /d "GpuPreference=2;" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "C:\Program Files (x86)\Minecraft\runtime\jre-legacy\windows-x64\jre-legacy\bin\javaw.exe" /t REG_SZ /d "GpuPreference=2;" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "C:\Program Files\VEGAS\Vegas Pro 19\vegas190.exe" /t REG_SZ /d "GpuPreference=2;" /f
cls
pause
goto main






:Internet
netsh int tcp set global autotuninglevel=normal
netsh interface 6to4 set state disabled
netsh int isatap set state disable
netsh int tcp set global timestamps=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global chimney=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
netsh int ip set global icmpredirects=disabled
netsh int tcp set security mpp=disabled profiles=disabled
netsh int ip set global multicastforwarding=disabled
netsh int tcp set supplemental internet congestionprovider=ctcp
netsh interface teredo set state disabled
netsh winsock reset
netsh int isatap set state disable
netsh int ip set global taskoffload=disabled
netsh int ip set global neighborcachelimit=4096
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f
echo.
cls
goto Main




:KMS
start "" "C\Program Files (x86)\IOptimizer\zLS.bat


:Backup
powershell Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\' >nul 2>&1
powershell Checkpoint-Computer -Description 'Hone Restore Point' >nul 2>&1
for /F "tokens=2" %%i in ('date /t') do set date=%%i
set date1=%date:/=.%
md C:\zLRestore\Restore\%date1%
reg export HKCU C:\IOptimizer\Restore\HKLM.reg /y >nul 2>&1 & reg export HKCU C:\IOptimizer\Restore\%date1%\HKCU.reg /y >nul 2>&1
cls
goto main


:PowerPlan
cls
echo  -----------------------------------------------------------------------------
echo ^|                                Power Plan                                   ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|    This is a DESKTOP Power Plan, meaning it is not recommended if using     ^|
echo ^|  a laptop with the battery and may make it hot. Would you like to install?  ^|
echo  -----------------------------------------------------------------------------
set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinuePowerPlan
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=PowerPlan
goto MissSpell
)

:ContinuePowerPlan
cls
echo delete default windows powerplans? (recommended) Y or N
set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto delete
if /i "%choice%"=="N" goto keep
) ELSE (
SET PlaceMisspelt=ContinuePowerPlan
goto MissSpell



:ServicesOptimization
cls
echo  -----------------------------------------------------------------------------
echo ^|                          Services Optimization                              ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^| This tweak changes the split threshold for the service host to your amount  ^|
echo ^| of RAM, reverting the old behaviour of Windows(making services group togeth ^|
echo ^| -er). When one service fails in a service host, the service host process is ^|
echo ^|  terminated. This means that this tweak will make it so if one service fails^|
echo ^|  in a group, all the other ones will (due to the service host being         ^|
echo ^|  terminated). Would you like to install?                                    ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueServicesOptimization
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=ServicesOptimization
goto MissSpell
)

:ContinueServicesOptimization
cls
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /format:value') do set /a mem=%%i
set /a mem=%mem% + 1024000
cls
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d %mem% /f >nul 2>&1
goto tweaks



:NVIDIAGPU
cls
echo  -----------------------------------------------------------------------------
echo ^|                           NVIDIA GPU SETTINGS                               ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|  This will install the best tweaked driver right now for latency and fps,   ^|
echo ^|   This drivers are 732Mb and 1Gb so this will take a moment to download.    ^|
echo ^|                     (768,102,400 or 1,073,691,829 bytes)                    ^|
echo ^|                        Would you like to install?                           ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto Yah
if /i "%choice%"=="N" goto Nah
) ELSE (
SET PlaceMisspelt=NVIDIAGPU
goto MissSpell
)





:Nah
goto Tweaks


:Yah
echo Do you need shadowplay and other components of the driver? Y or N?

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto yeyeyeye
if /i "%choice%"=="N" goto nono
) ELSE (
SET PlaceMisspelt=Yah
goto MissSpell
)






:nono
TITLE Downloading Nvidia driver...
curl -L -o C:\Hone\Drivers\CLEAN.exe https://github.com/auraside/HoneCtrl/releases/latest/download/497.09.Hone.Tweaked.exe
timeout 1 >nul 2>&1
TITLE Executing DDU...
if exist C:\Hone\Resources\DDU\DDU.exe (goto alrinst2) else (goto installddu2)
:installddu2
curl -o C:\Hone\Resources\DDU.zip https://cdn.discordapp.com/attachments/798652558351794196/934970228792778752/DDU.zip
timeout 1 >nul 2>&1
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe Expand-Archive 'C:\Hone\Resources\DDU.zip' -DestinationPath 'C:\Hone\Resources' 
del "C:\Hone\Resources\DDU.zip"
:alrinst2
cd C:\Hone\Resources\DDU
DDU.exe -silent -cleannvidia
if exist C:\Hone\Drivers\choice.bat (del /Q C:\Hone\Drivers\choice.bat)
cd C:\Hone\Drivers
echo set driverchoice=clean >> choice.bat
goto Restartdriver


:yeyeyeye
TITLE Downloading Nvidia driver...
curl -L -o C:\Hone\Drivers\FULL.exe https://github.com/auraside/HoneCtrl/releases/latest/download/497.09.Hone.Default.exe
timeout 1 >nul 2>&1
TITLE Executing DDU...
if exist C:\Hone\Resources\DDU\DDU.exe (goto alrinst) else (goto installddu)
:installddu
curl -o C:\Hone\Resources\DDU.zip https://cdn.discordapp.com/attachments/798652558351794196/934970228792778752/DDU.zip
timeout 1 >nul 2>&1
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe Expand-Archive 'C:\Hone\Resources\DDU.zip' -DestinationPath 'C:\Hone\Resources' >nul 2>&1
del "C:\Hone\Resources\DDU.zip"
:alrinst
cd C:\Hone\Resources\DDU
DDU.exe -silent -cleannvidia
if exist C:\Hone\Drivers\choice.bat (del /Q C:\Hone\Drivers\choice.bat)
cd C:\Hone\Drivers
echo set driverchoice=bloat >> choice.bat
goto Restartdriver















:Restartdriver
cls
echo  -----------------------------------------------------------------------------
echo ^|                                 Restart                                     ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|             Your PC NEEDS to restart before installing the driver!          ^|
echo ^|             AFTER RESTARTING, PLEASE REOPEN THE HONE CONTROL PANEL          ^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo  -----------------------------------------------------------------------------
set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto Restart4
if /i "%choice%"=="N" goto Notrightnow
) ELSE (
SET PlaceMisspelt=Restartdriver
goto MissSpell
)







:Restart4
copy "%~f0" "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\HoneCtrl.bat"
cd C:\Hone
echo set justrestarted=1 >> driverinstall.bat
shutdown /s /t 60 /c "A restart is required, we'll do that now" /f /d p:0:0
timeout 5 
shutdown -a
shutdown /r /t 7 /c "Restarting automatically..." /f /d p:0:0
goto :eof






:Notrightnow
copy "%~f0" "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\HoneCtrl.bat"
cd C:\Hone
echo set justrestarted=1 >> driverinstall.bat
goto tweaks


:restartinstall
cd C:\Hone\Drivers 
call choice.bat
if %driverchoice%==clean (goto cleaninstall)
if %driverchoice%==bloat (goto bloatinstall) else (goto tweaks)


:cleaninstall
cd C:\Hone\Drivers
set justrestarted=0
if exist C:\Hone\driverinstall.bat (del /Q C:\Hone\driverinstall.bat)
start CLEAN.exe
goto main

:bloatinstall
cd C:\Hone\Drivers
set justrestarted=0
if exist C:\Hone\driverinstall.bat (del /Q C:\Hone\driverinstall.bat)
start FULL.exe
goto main




:TimerRes
cd C:\Hone
curl -o C:\Hone\CLOCKRES.exe https://cdn.discordapp.com/attachments/798314687321735199/923239120367673434/CLOCKRES.exe
timeout 1 >nul 2>&1
FOR /F "tokens=*" %%g IN ('CLOCKRES.exe ^| find "Current"') do set "currenttimer=%%g"
cls
echo  -----------------------------------------------------------------------------
echo ^|                            Timer Resoloution                                ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^| This tweak changes how fast your cpu refreshes! Would you like to install?  ^|
echo ^|                        %currenttimer%                     ^|
echo ^|                    If the service is installed correctly,                   ^|
echo ^|                the current resolution should read around 0.500ms            ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueTimerRes
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=TimerRes
goto MissSpell
)




:ContinueTimerRes
cls
curl -o C:\Hone\SetTimerResolutionService.exe https://cdn.discordapp.com/attachments/798314687321735199/923239064738627594/SetTimerResolutionService.exe
timeout 2 >nul 2>&1
sc config "STR" start= auto >nul 2>&1
NET START STR >nul 2>&1
bcdedit /set useplatformtick yes  
bcdedit /set disabledynamictick yes >nul 2>&1
cd C:\Hone >nul 2>&1
%windir%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /i SetTimerResolutionService.exe >nul 2>&1
sc config "STR" start= auto >nul 2>&1
NET START STR >nul 2>&1
goto tweaks


:MSI
cls
echo  -----------------------------------------------------------------------------
echo ^|                                 Msi Mode                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^| This tweak will enable MSI Mode for your gpu and network adapter! Would you ^|
echo ^|                           like to install?                                  ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueMSI
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=MSI
goto MissSpell
)


:ContinueMSI
cls
cd C:\Hone\Resources\
for /f %%g in ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
)
for /f %%g in ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "3" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority " /t REG_DWORD /d "3" /f >nul 2>&1
)
goto Tweaks





:Cleaner
cls
echo  -----------------------------------------------------------------------------
echo ^|                                  Cleaner                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|This tweak will clear adware, unused devices, and temp files, would you like ^|
echo ^|                   to install?  THIS WILL EMPTY YOUR RECYCLE BIN!!           ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueCleaner
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=Cleaner
goto MissSpell
)




:Internet
cls
echo  -----------------------------------------------------------------------------
echo ^|                          General Internet Tweaks                            ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|     This tweak will tweak internet settings! Would you like to install?     ^|
echo ^|            Disclaimer: Do not do this tweak if you are using Wi-Fi          ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueGeneral
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=Internet
goto MissSpell
)

:ContinueGeneral
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "00000010" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "00000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "00000006" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "00000005" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "00000004" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "00000007" /f  
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "00000016" /f  
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "00000016" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "00000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "4294967295" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "00000001" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "00065534" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000030" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "00000001" /f >nul 2>&1
netsh winsock reset catalog  
netsh int ip reset c:resetlog.txt  
netsh int ip reset C:\tcplog.txt  
netsh int tcp set supplemental Internet congestionprovider=ctcp  
netsh int tcp set heuristics disabled  
netsh int tcp set global initialRto=2000  
netsh int tcp set global autotuninglevel=normal  
netsh int tcp set global rsc=disabled  
netsh int tcp set global chimney=disabled  
netsh int tcp set global dca=enabled  
netsh int tcp set global netdma=disabled  
netsh int tcp set global ecncapability=enabled  
netsh int tcp set global timestamps=disabled  
netsh int tcp set global nonsackrttresiliency=disabled  
netsh int tcp set global rss=enabled  
netsh int tcp set global MaxSynRetransmissions=2 
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /d "1" /t REG_DWORD /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /d "1" /t REG_DWORD /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /d "0" /t REG_DWORD /f >nul 2>&1
) 
goto Tweaks






:Debloat
cls
echo  -----------------------------------------------------------------------------
echo ^|                                  Debloat                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|This tweak will debloat your system and disable telemetry! Would you like to ^|
echo ^|                                install?                                     ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueDebloat
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=Debloat
goto MissSpell
)












:ContinueDebloat
cls
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f   
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "OptimizeWindowsSearchResultsForScreenReaders" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f   
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f  
goto Tweaks








:Mouse
cls
echo  -----------------------------------------------------------------------------
echo ^|                                  Mouse Fix                                  ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|Disclaimer, Your Mouse will feel very different after this but you will get  ^|
echo ^|    used to it. This removes acceleration which makes your aim unconsistent  ^|
echo ^|                       Would you like to install?                            ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueMouse
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=Mouse
goto MissSpell
)







:ContinueMouse
echo what is your display scaling? 
echo go to settings , system , display , then type the scale percentage like 100 , 125
set /p choice=" Scale >  "
if /i "%choice%"=="100" goto 100
if /i "%choice%"=="125" goto 125
if /i "%choice%"=="150" goto 150
) ELSE (
SET PlaceMisspelt=ContinueMouse
goto MissSpell
)



:100
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /f  
goto tweaks


:125
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000100000000000000020000000000000003000000000000000400000000000" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /f  
goto tweaks



:150
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000303313000000000060662600000000009099390000000000C0CC4C0000000000" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /f  
goto tweaks


:ServiceDisable
cls
echo  -----------------------------------------------------------------------------
echo ^|                               Service Disable                               ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|         This will disable a ton of services and lowers memory usage!        ^|
echo ^|             Disclaimer: Do not this tweak if you are using Wi-Fi            ^|
echo ^|                          Would you like to install?                         ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueServiceDisable
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=ServiceDisable
goto MissSpell
)



:ContinueServiceDisable
cls
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AdobeFlashPlayerUpdateSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibtsiva" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f    
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wersvc" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\debugregsvc" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /d "2" /t REG_DWORD /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /d "3" /t REG_DWORD /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "3" /f   
goto tweaks




:affinity
cls
echo  -----------------------------------------------------------------------------
echo ^|                                 Affinity                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^| This tweak will spread devices on multiple cpu cores! Would you like to     ^|
echo ^|                                  install?                                   ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueAffinity
if /i "%choice%"=="N" goto Tweaks
) ELSE (
SET PlaceMisspelt=Affinity
goto MissSpell
)



:ContinueAffinity
for /f "tokens=*" %%f in ('wmic cpu get NumberOfCores /value ^| find "="') do set %%f
echo %NumberOfCores%
for /f "tokens=*" %%f in ('wmic cpu get NumberOfLogicalProcessors /value ^| find "="') do set %%f
echo %NumberOfLogicalProcessors%
if "%NumberOfCores%"=="2" goto Fail
if %NumberOfLogicalProcessors% gtr %NumberOfCores% (
echo You have HyperThreading Enabled!
goto CheckAmountOfCoresHT
) ELSE (
echo You have HyperThreading Disabled!
goto CheckAmountOfCores
)
pause


:CheckAmountOfCoresHT
if "%NumberOfCores%"=="4" goto 4coresHTEnabled
) else (
goto MoreThan4
)

:CheckAmountOfCores
if "%NumberOfCores%"=="4" goto 4coresHTDisabled
) else (
goto MoreThan4





:4coresHTEnabled
cd C:\Hone\Resources
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "30" /f >nul 2>&1
)
goto tweaks



:4coresHTDisabled
cd C:\Hone\Resources
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "08" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "02" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f >nul 2>&1
)
goto tweaks


:MoreThan4
cd C:\Hone\Resources
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "3" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "5" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
)
goto Tweaks

:Failed
echo you have 2 cores, affinity won't work!!!!!
timeout 1 >nul 2>&1
goto Tweaks

:ColorText
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul  
goto :eof

:Close
del /S /Q /F C:\Hone\Resources 
del /S /Q /F C:\Hone\Drivers
exit


:IsAdmin
Reg.exe add HKLM /F >nul 2>&1
IF %ERRORLEVEL%==0 goto :start
cls
TITLE NOT RUNNING AS ADMIN
curl -o %temp%\AdminMaker.exe https://cdn.discordapp.com/attachments/872722402948284468/883502694675922945/NSudoLG.exe
timeout 1 >nul 2>&1
copy "%~f0" "%~dp0\AdminRights.bat" >nul 2>&1
%temp%\AdminMaker -U:T -P:E "%~dp0\AdminRights.bat"
timeout 3 >nul 2>&1
exit
)

:MissSpell
cls
echo That is not a valid selection!
pause
goto %PlaceMisspelt%

:Revert
 
cls
echo.                                                       Thx for download @%username%
echo.
echo.
echo.
echo.                                                        I
echo.
echo.                                                        Optimizer .                                           
echo.                                    
echo.                                      
echo.
echo.
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 1 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Power Plan "
call :ColorText 06 "                                  [ "
call :ColorText F " 2 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Services Optimization "
echo. 1 Revert Power Plan
echo. 2 Revert Services Optimization
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 3 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Timer Resolution  "
call :ColorText 06 "                            [ "
call :ColorText F " 4 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Nvidia Settings "
echo. 3 Revert Timer Res
echo. 4 Revert Nvidia settings
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 5 "
call :ColorText 06 " ] " 
call :ColorText F " Revert MSI Mode "
call :ColorText 06 "                                    [ "
call :ColorText F " 6 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Internet Tweaks "
echo. 5 Revert MSI Mode
echo. 6 Revert Internet tweaks
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 7 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Debloat "
call :ColorText 06 "                                     [ "
call :ColorText F " 8 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Mouse Fix "
echo. 7 Revert Debloat
echo. 8 Revert Mouse Fix
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 9 "
call :ColorText 06 " ] " 
call :ColorText F " Enable Services "
call :ColorText 06 "                                    [ "
call :ColorText F " 10 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Affinities "
echo. 9 Enable Services
echo. 10 Revert Affinities
echo. 
call :ColorText 8 "                                                    [ press X to go back ]"
echo.                                                                  [ press X to go back ]"
echo.
echo.
set /p choice="            Select a corresponding number to what you'd like > "
if /i "%choice%"=="1" goto RevertPowerPlan
if /i "%choice%"=="2" goto RevertServicesOptimization 
if /i "%choice%"=="3" goto RevertTimerRes
if /i "%choice%"=="4" goto RevertNvidiaSettings
if /i "%choice%"=="5" goto RevertMSI
if /i "%choice%"=="6" goto RevertInternet
if /i "%choice%"=="7" goto RevertDebloat
if /i "%choice%"=="8" goto RevertMouse
if /i "%choice%"=="9" goto RevertServices
if /i "%choice%"=="10" goto RevertAffinities
if /i "%choice%"=="X" goto Main
) ELSE (
SET PlaceMisspelt=Revert
goto MissSpell
)


:RevertPowerPlan
cls
echo  -----------------------------------------------------------------------------
echo ^|                                Power Plan                                   ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|        This Will Revert Hones Power Plan! Would you like to continue?       ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertPowerPlan
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertPowerPlan
goto MissSpell
)


:ContinueRevertPowerPlan
powercfg -restoredefaultschemes
goto revert



:RevertServicesOptimization
cls
echo  -----------------------------------------------------------------------------
echo ^|                            Services Optimization                            ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|     This will revert Services Optimization! Would you like to continue?     ^|
echo  -----------------------------------------------------------------------------


set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertServicesOptimization
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertServicesOptimization
goto MissSpell
)



:ContinueRevertServicesOptimization
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d 3670016 /f 
goto revert


:RevertTimerRes
cls
cd c:\Hone
if exist C:\Hone\CLOCKRES.exe (goto alrinst3) else (goto installclockres)
:installclockres
curl -o C:\Hone\CLOCKRES.exe https://cdn.discordapp.com/attachments/798314687321735199/923239120367673434/CLOCKRES.exe
timeout 1 >nul 2>&1
:alrinst3
FOR /F "tokens=*" %%g IN ('CLOCKRES.exe ^| find "Current"') do set "currenttimer1=%%g"
cls
echo  -----------------------------------------------------------------------------
echo ^|                            Timer Resolution                                 ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|       This will revert timer resolution! Would you like to continue?        ^|
echo ^|                        %currenttimer1%                     ^|
echo ^|                    If the service is uninstalled correctly,                 ^|
echo ^|              the current resolution should NOT read around 0.500 ms         ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertTimerRes
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertTimerRes
goto MissSpell
)


:ContinueRevertTimerRes
cls
NET STOP STR >nul 2>&1
cd c:\Hone 
%windir%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /u SetTimerResolutionService.exe  >nul 2>&1
del /Q SetTimerResolutionService.exe >nul 2>&1
del /Q InstallUtil.InstallLog >nul 2>&1
del /Q SetTimerResolutionService.InstallLog >nul 2>&1
bcdedit /deletevalue useplatformclock   >nul 2>&1
bcdedit /deletevalue useplatformtick  >nul 2>&1
bcdedit /deletevalue disabledynamictick  >nul 2>&1
goto revert

:RevertNvidiaSettings
cls
echo.
echo.
echo.
echo.
echo.                                                                          .  
echo.                                                                       +N. 
echo.                                                              //        oMMs 
echo.                                                             +Nm`    ``yMMm- 
echo.                                                          ``dMMsoyhh-hMMd.  
echo.                                                          `yy/MMMMNh:dMMh`   
echo.                                                         .hMM.sso++:oMMs`    
echo.                                                        -mMMy:osyyys.No      
echo.                                                       :NMMs-oo+/syy:-       
echo.                                                      /NMN+ ``   :ys.        
echo.                                                     `NMN:        +.         
echo.                                                     om-                    
echo.                                                      `.                     
echo.
echo.
echo.
call :ColorText 06 "                         [ "
call :ColorText F " 1 "
call :ColorText 06 " ] " 
call :ColorText F " Revert KBoost "
call :ColorText 06 "                                                [ "
call :ColorText F " 2 "
call :ColorText 06 " ] " 
call :ColorText F " Revert Profile Inspector "
echo.
echo.
echo.
call :ColorText 8 "                                                    [ press X to go back ]"
echo.
echo.
echo.
set /p choice="            Select a corresponding number to what you'd like > "
if /i "%choice%"=="1" goto RevertKBoost
if /i "%choice%"=="2" goto RevertProfileInspector
if /i "%choice%"=="X" goto Revert
) ELSE (
SET PlaceMisspelt=RevertNvidiaSettings
goto MissSpell
)

:RevertKBoost
cls
echo  -----------------------------------------------------------------------------
echo ^|                                   KBoost                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|            This will revert KBoost! Would you like to continue?             ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertKBoost
if /i "%choice%"=="N" goto RevertNvidiaSettings
) ELSE (
SET PlaceMisspelt=RevertKBoost
goto MissSpell
)

:ContinueRevertKBoost
cls
for /f %%a in ('r ^| findstr  "HKEY"') do ( 
Reg.exe delete "%%a" /v "PowerMizerLevel" /f >nul 2>&1
 )
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr  "HKEY"') do ( 
Reg.exe delete "%%a" /v "PowerMizerLevelAC" /f >nul 2>&1
 )
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr  "HKEY"') do ( 
Reg.exe delete "%%a" /v "PerfLevelSrc" /f >nul 2>&1
 )
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr  "HKEY"') do ( 
Reg.exe delete "%%a" /v "PowerMizerEnable" /f >nul 2>&1
 )
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr  "HKEY"') do (  
Reg.exe delete "%%a" /v "DisableDynamicPstate" /f >nul 2>&1
 )
goto Restart1

:Restart1
cls
echo  -----------------------------------------------------------------------------
echo ^|                                  Restart                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                Your PC needs to restart to apply these changes!             ^|
echo ^|                      Do you want to restart right now?                      ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo  -----------------------------------------------------------------------------
set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertKBoost2
if /i "%choice%"=="N" goto RevertNvidiaSettings
) ELSE (
SET PlaceMisspelt=Restart1
goto MissSpell
)

:ContinueRevertKBoost2
cls
copy "%~f0" "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\HoneCtrl.bat" >nul 2>&1
shutdown /s /t 60 /c "KBoost requires a restart, it's disabled" /f /d p:0:0
timeout 5 >nul 2>&1
shutdown -a
shutdown /r /t 7 /c "Restarting automatically..." /f /d p:0:0
goto :eof


:RevertProfileInspector
cls
echo  -----------------------------------------------------------------------------
echo ^|                          Nvidia Profile Inspector & Tweaks                  ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|             This will revert Nvidia Profile Inspector & Tweaks,             ^|  
echo ^|                         Would you like to continue ?                        ^|           
echo  -----------------------------------------------------------------------------


set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertProfileInspector
if /i "%choice%"=="N" goto RevertNvidiaSettings
) ELSE (
SET PlaceMisspelt=RevertProfileInspector
goto MissSpell
)
:ContinueRevertProfileInspector
cls
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr  "HKEY"') do ( 
Reg.exe del "%%a" /v "RMHdcpKeyglobZero" /f >nul 2>&1
 )
curl -o C:\Hone\Resources\NVPI.exe https://cdn.discordapp.com/attachments/798652558351794196/847124457637806080/nvidiaProfileInspector.exe
timeout 1 >nul 2>&1
curl -o C:\Hone\Resources\Revert.nip https://cdn.discordapp.com/attachments/872722402948284468/901734515867799552/Base_Profile.nip
timeout 1 >nul 2>&1
cd C:\Hone\Resources\ >nul 2>&1
NVPI.exe "Revert.nip" >nul 2>&1
goto RevertNvidiaSettings


:RevertMSI
cls
echo  -----------------------------------------------------------------------------
echo ^|                                 Msi Mode                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|     This will revert MSI Mode priorities! Would you like to continue   ?    ^|             
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueMSIRevert
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertMSI
goto MissSpell
)


:ContinueMSIRevert
cls
cd C:\Hone\Resources\
for /f %%g in ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /f >nul 2>&1
)
for /f %%g in ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority " /f >nul 2>&1
)
goto Revert

:RevertInternet
cls
echo  -----------------------------------------------------------------------------
echo ^|                            General Internet Tweaks                          ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^| This tweak will revert general internet tweaks! Would you like to continue? ^|             
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertGeneral
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertInternet
goto MissSpell
)

:ContinueRevertGeneral
cls
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /f >nul 2>&1
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /f >nul 2>&1
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /f >nul 2>&1
) 
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTaskOffload" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableTaskOffload" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "00000010" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "00000020" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "00000499" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "00000500" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "00002000" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "00002001" /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "00000002" /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "00000004" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /f >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /f >nul 2>&1
netsh winsock reset catalog >nul 2>&1
netsh int ip reset c:resetlog.txt >nul 2>&1
netsh int ip reset C:\tcplog.txt >nul 2>&1
netsh int tcp set heuristics default >nul 2>&1
netsh int tcp set supplemental Internet congestionprovider=default >nul 2>&1
netsh int tcp set global initialRto=3000 >nul 2>&1
netsh int tcp set global MaxSynRetransmissions=2 >nul 2>&1
netsh int tcp set global autotuninglevel=default >nul 2>&1
netsh int tcp set global rss=default >nul 2>&1
netsh int tcp set global rsc=default >nul 2>&1
netsh int tcp set global chimney=default >nul 2>&1
netsh int tcp set global dca=default >nul 2>&1
netsh int tcp set global netdma=default >nul 2>&1
netsh int tcp set global ecncapability=default >nul 2>&1
netsh int tcp set global timestamps=default >nul 2>&1
netsh int tcp set global nonsackrttresiliency=default >nul 2>&1
goto Revert

:RevertDebloat
cls
echo  -----------------------------------------------------------------------------
echo ^|                                  Debloat                                    ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|  This will revert debloating in your system and enable telemetry! Would you ^| 
echo ^|                               like to continue?                             ^|
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertDebloat
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertDebloat
goto MissSpell
)

:ContinueRevertDebloat
cls
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "Allow Telemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /f >nul 2>&1
Reg.exe delete "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /f >nul 2>&1
Reg.exe delete "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess" /f >nul 2>&1
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Speech" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\OneDrive" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Siuf" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "1" /f  
goto Revert

:RevertMouse
cls
echo  -----------------------------------------------------------------------------
echo ^|                                 Mouse Fix                                   ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|           This will revert mouse fix! Would you like to continue?           ^|             
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertMouse
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertMouse
goto MissSpell
)

:ContinueRevertMouse 
cls
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000156e000000000000004001000000000029dc0300000000000000280000000000" /f  
Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000fd11010000000000002404000000000000fc12000000000000c0bb0100000000" /f  
goto Revert


:RevertServices
cls
echo  -----------------------------------------------------------------------------
echo ^|                               Service Enable                                ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|  This will reenable the services disabled! Would you like to continue?      ^|             
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertServiceDisable
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertServices
goto MissSpell
)

:ContinueRevertServiceDisable
cls
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AdobeFlashPlayerUpdateSvc" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibtsiva" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "2" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "3" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "2" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "2" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "3" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "3" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "3" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "2" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wersvc" /v "Start" /t REG_DWORD /d "3" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService" /v "Start" /t REG_DWORD /d "2" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "2" /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "2" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\debugregsvc" /v "Start" /t REG_DWORD /d "3" /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /d "2" /t REG_DWORD /f  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /d "3" /t REG_DWORD /f 
goto Revert

:RevertAffinities
cls
echo  -----------------------------------------------------------------------------
echo ^|                                  Affinity                                   ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|                                                                             ^|
echo ^|    Type the letter Y for Yes or N for No, below                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|    [Y] Continue                                                             ^|
echo ^|    [N] Exit                                                                 ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|                                                                             ^|
echo ^|-----------------------------------------------------------------------------^|
echo ^|         This will revert affinities! Would you like to continue?            ^|             
echo  -----------------------------------------------------------------------------

set /p choice="Y or N >  "
if /i "%choice%"=="Y" goto ContinueRevertAffinity
if /i "%choice%"=="N" goto Revert
) ELSE (
SET PlaceMisspelt=RevertAffinities
goto MissSpell
)

:ContinueRevertAffinity
cls
for /f "tokens=*" %%f in ('wmic cpu get NumberOfCores /value ^| find "="') do set %%f
echo %NumberOfCores%
for /f "tokens=*" %%f in ('wmic cpu get NumberOfLogicalProcessors /value ^| find "="') do set %%f
echo %NumberOfLogicalProcessors%
if "%NumberOfCores%"=="2" goto Fail
cd C:\Hone\Resources
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /f >nul 2>&1
)
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
)
goto revert

:End
del %0


