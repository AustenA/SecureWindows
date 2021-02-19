Title Secure Windows Script

REM Remote Desktop
set /p Chk="Enable remote desktop (y/n)"
if %Chk%==y (
	REM Enable
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	reg ADD "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 6969 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
)
if %Chk%==n (
	REM Disable
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	netsh advfirewall firewall set service type = remotedesktop mode = disable
	sc config iphlpsvc start= disabled >> nul 2>&1
	sc stop iphlpsvc >> nul 2>&1
	sc config umrdpservice start= disabled >> nul 2>&1
	sc stop umrdpservice >> nul 2>&1
	sc config termservice start= disabled >> nul 2>&1
	sc stop termservice >> nul 2>&1

)
set loca=%~dp0
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F >> nul 2>&1

reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F >> nul 2>&1


netsh advfirewall firewall set multicastbroadcastresponse disable
netsh advfirewall firewall set multicastbroadcastresponse mode=disable profile=all

setx PATH "%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\"

REM Disable Guest Account
net user Guest /active:no

REM Disable Administrator Account
net user Administrator /active:no

REM Turn on Firewall
netsh advfirewall set allprofiles state on


REM account password policy set
net accounts /FORCELOGOFF:30 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:2 /UNIQUEPW:24 /lockoutwindow:30 /lockoutduration:10 /lockoutthreshold:10

REM Stop Sharing C Drive
net share C:\ /delete

REM Enables DEP
bcdedit.exe /set {current} nx AlwaysOn

REM Turns on Auditing.
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

Set-AuditPolicy -Policy "'Credential Validation'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Application Group Management'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Computer Account Management'" -Success "enable" -Failure "enable"


REM Flush DNS
ipconfig /flushdns

REM Writing over the hosts file
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts

REM Get All The Profiles
netsh advfirewall set Domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set Domainprofile logging maxfilesize 20000
netsh advfirewall set Privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set Privateprofile logging maxfilesize 20000
netsh advfirewall set Publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set Publicprofile logging maxfilesize 20000
netsh advfirewall set Publicprofile logging droppedconnections enable
netsh advfirewall set Publicprofile logging allowedconnections enable
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable

REM Delete Startup folders 
for /d %%D in (C:\Users\*) do for %%F in ("%%~fD\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*") do del /F /Q "%%~fF"

del /F /Q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*"

del /F /Q "C:\autoexec.bat"

REM Deletes Scripts 
del /F /Q C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup
del /F /Q C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Shutdown
del /F /Q C:\WINDOWS\System32\GroupPolicy\User\Scripts\Logon
del /F /Q C:\WINDOWS\System32\GroupPolicy\User\Scripts\Logoff

Del /S /F /Q %temp% 
Del /S /F /Q %Windir%\Temp


REM Turns on UAC
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

REM UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableVirtualization /T REG_DWORD /D 1 /F >> nul 2>&1


REM Lock Screen Stuff
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreenCamera /T REG_DWORD /D 1 /F
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreenSlideshow /T REG_DWORD /D 1 /F
reg add HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization /v AllowInputPersonalization /T REG_DWORD /D 0 /F

REM Firewall
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /V EnableFirewall /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /V EnableFirewall /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile /V EnableFirewall /T REG_DWORD /D 1 /F 

reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /V DefaultInboundAction /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /V DefaultInboundAction /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile /V DefaultInboundAction /T REG_DWORD /D 1 /F

reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /V DefaultOutboundAction /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /V DefaultOutboundAction /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile /V DefaultOutboundAction /T REG_DWORD /D 1 /F

reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /V DisableNotifications /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /V DisableNotifications /T REG_DWORD /D 1 /F 
reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile /V DisableNotifications /T REG_DWORD /D 1 /F




REM Disable tailored experiences 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f

echo Cleaning startup files
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /VA /F >> nul 2>&1
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F >> nul 2>&1
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /VA /F >> nul 2>&1
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F >> nul 2>&1

reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /V ctfmon /T REG_SZ /D C:\Windows\System32\ctfmon.exe /F >> nul 2>&1

reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoDriveTypeAutorun /T REG_DWORD /D 255 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoDriveTypeAutorun /T REG_DWORD /D 255 /F >> nul 2>&1
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoAutorun /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoAutorun /T REG_DWORD /D 1 /F >> nul 2>&1

REM Windows automatic updates
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
REM Enable Auto Updates Download and install
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F >> nul 2>&1

REM NTP server to pool.ntp.org
reg add "HKLM\SOFTWARE\Policies\Microsoft\W32time\Parameters" /v "NtpServer" /t REG_SZ /d "pool.ntp.org,0x8" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\W32time\Parameters" /v "Type" /t REG_SZ /d "NTP" /f

REM Windows Explorer Settings
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" /v "CheckedValue" /t REG_DWORD /d 0 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /F

REM Disable Dump file creation
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
REM Disable Autorun
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f

REM Disable sticky keys
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f

REM Enable Windows Defender.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
REM Configure Windows Defender.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f

REM Disable picture passwords.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "BlockDomainPicturePassword" /t REG_DWORD /d 1 /f

REM Disable Windows Update deferrals.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdates" /t REG_DWORD /d 0 /f

REM Disable Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f

REM Force enable Data Execution Prevention (DEP).
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f
REM Prevent print driver installs 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
REM Disable  driveAutorun.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
REM Limit local account use of blank passwords to console
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
REM Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
REM Automatic Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f


echo pref("general.config.obscure_value", 0); // only needed if you do not want to obscure the content with ROT-13 > "C:\Program Files (x86)\Mozilla Firefox\defaults\pref\local-settings.js"
echo pref("general.config.filename", "mozilla.cfg"); >> "C:\Program Files (x86)\Mozilla Firefox\defaults\pref\local-settings.js"
echo pref("general.config.obscure_value", 0); // only needed if you do not want to obscure the content with ROT-13 > "C:\Program Files\Mozilla Firefox\defaults\pref\local-settings.js"
echo pref("general.config.filename", "mozilla.cfg"); >> "C:\Program Files\Mozilla Firefox\defaults\pref\local-settings.js"

REM Sets Custom Mozilla config
copy /Y "%~dp0BlankTemplates\Basic\mozilla.cfg" "C:\Program Files (x86)\Mozilla Firefox\mozilla.cfg"
copy /Y "%~dp0BlankTemplates\Basic\mozilla.cfg" "C:\Program Files\Mozilla Firefox\mozilla.cfg"

CD /D C:

dism /online /disable-feature /featurename:TFTP
dism /online /disable-feature /featurename:TelnetClient
dism /online /disable-feature /featurename:TelnetServer
dism /online /disable-feature /featurename:"SMB1Protocol"

REM Stopping Services. "How Many?" Yes.
set servicesD=SysMain seclogon TapiSrv p2pimsvc simptcp fax Msftpsvc iprip ftpsvc RasAuto W3svc Smtpsvc Dfs TrkWks MSDTC ERSvc NtFrs Iisadmin IsmServ WmdmPmSN helpsvc Spooler RDSessMgr RSoPProv SCardSvr Sacsvr TermService uploadmgr VDS VSS WINS CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper UmRdpService SessionEnv Server TeamViewer TeamViewer7 HomeGroupListener HomeGroupProvider AxInstSV AXInstSV Netlogon lltdsvc iphlpsvc AdobeARMservice tlntsvr msftpsvc snmptrap ssdpsrv termservice sessionenv Messenger upnphos WAS RemoteAccess mnmsrvc NetTcpPortSharing RasMan TabletInputService RpcSs SENS EventSystem XblAuthManager XblGameSave XboxGipSvc xboxgip xbgm wecsvc WerSvc PNRPAutoReg MSiSCSI wercplsupport PNRPsvc dmwappushservice DiagTrack DNS ERSVC RetailDemo WinRM WMPNetworkSvc HTTPFilter IISADMIN MSFTPSVC MSFtpsvc RPCLocator RsoPProv SMTPSVC SZCSVC bthserv mcx2svc telnet MapsBroker Browser lfsvc bthhfsrv irmon xblauthmanager xblgamesave xboxnetapisvc LxssManager ScardSvr ICS icscvc ShellHWDetection Telephony Tlntsvr Uploadmgr W3SVC WinHttpAutoProxySvc p2psvc SNMP WMSvc
set servicesM=dmserver SrvcSurg
set servicesG=Dhcp Dnscache NtLmSsp eventlog mpssvc wuauserv EventLog MpsSvc WinDefend WdNisSvc Sense Schedule SCardSvr ScDeviceEnum SCPolicySvc wscsvc
for %%a in (%servicesD%) do (
	sc stop "%%a"
	sc config "%%a" start= disabled
)
for %%b in (%servicesM%) do (
	sc config "%%b" start= demand
)

for %%c in (%servicesG%) do (
	sc config "%%c" start= auto
)
REM Services that are an automatic (delayed) start.
for %%S in (windefend,sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)
sc delete DiagTrack
sc delete dmwappushservice

REM Disabling Windows Features
set features=IIS-WebServerRole IIS-CommonHttpFeatures IIS-HttpErrors IIS-HttpRedirect IIS-ApplicationDevelopment IIS-NetFxExtensibility IIS-NetFxExtensibility45 IIS-HealthAndDiagnostics IIS-HttpLogging IIS-LoggingLibraries IIS-RequestMonitor IIS-HttpTracing IIS-Security IIS-URLAuthorization IIS-RequestFiltering IIS-IPSecurity IIS-Performance IIS-HttpCompressionDynamic IIS-WebServerManagementTools IIS-ManagementScriptingTools IIS-IIS6ManagementCompatibility IIS-Metabase IIS-HostableWebCore IIS-StaticContent IIS-DefaultDocument IIS-DirectoryBrowsing IIS-WebDAV IIS-WebSockets IIS-ApplicationInit IIS-ASPNET IIS-ASPNET45 IIS-ASP IIS-CGI IIS-ISAPIExtensions IIS-ISAPIFilter IIS-ServerSideIncludes IIS-CustomLogging IIS-BasicAuthentication IIS-HttpCompressionStatic IIS-ManagementConsole IIS-ManagementService IIS-WMICompatibility IIS-LegacyScripts IIS-LegacySnapIn IIS-FTPServer IIS-FTPSvc IIS-FTPExtensibility TFTP TelnetClient TelnetServer
for %%a in (%features%) do dism /online /NoRestart /disable-feature /featurename:%%a

attrib -h -r -s %windir%\system32\catroot2
attrib -h -r -s %windir%\system32\catroot2\*.*
net stop wuauserv
net stop CryptSvc
net stop BITS

ren %windir%\system32\catroot2 catroot2.old
ren %windir%\SoftwareDistribution sold.old
ren "%ALLUSERSPROFILE%\application data\Microsoft\Network\downloader" downloader.old

net Start BITS
net start CryptSvc
net start wuauserv

reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f

REM Searches for Rootkits
gpupdate /force
powershell Invoke-WebRequest -OutFile MBRTKit.exe https://data-cdn.mbamupdates.com/web/mbar-1.10.3.1001.exe
MBRTKit.exe

sc config trustedinstaller start= auto
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow


