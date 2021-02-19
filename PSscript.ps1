Set-ADDomainMode -identity $env:USERDNSDOMAIN -DomainMode Windows2016Domain
$Forest = Get-ADForest
Set-ADForestMode -Identity $Forest -Server $Forest.SchemaMaster -ForestMode Windows2016Forest

sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
sc.exe config mrxsmb20 start= disabled

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 -Force

#Remove Exclusions from Windows Defender
(Get-MpPreference).ExclusionPath | ForEach { if( $_ ) {Invoke-Expression ("Remove-MpPreference -ExclusionPath '" + $_ + "' -Force")}}
(Get-MpPreference).ExclusionExtension | ForEach { if( $_ ) {Invoke-Expression ("Remove-MpPreference -ExclusionExtension '" + $_ + "' -Force")}}
(Get-MpPreference).ExclusionProcess | ForEach { if( $_ ) {Invoke-Expression ("Remove-MpPreference -ExclusionProcess '" + $_ + "' -Force")}}

#Configure Windows Defender
Set-MpPreference -SignatureScheduleDay Everyday -SignatureScheduleTime 120 -CheckForSignaturesBeforeRunningScan $true -DisableArchiveScanning $false -DisableAutoExclusions $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -DisableCatchupFullScan $false -DisableCatchupQuickScan $false -DisableEmailScanning $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false -DisablePrivacyMode $false -DisableRealtimeMonitoring $false -DisableRemovableDriveScanning $false -DisableRestorePoint $false -DisableScanningMappedNetworkDrivesForFullScan $false -DisableScanningNetworkFiles $false -DisableScriptScanning $false -HighThreatDefaultAction Remove -LowThreatDefaultAction Quarantine -MAPSReporting 0 -ModerateThreatDefaultAction Quarantine -PUAProtection Enabled -QuarantinePurgeItemsAfterDelay 1 -RandomizeScheduleTaskTimes $false -RealTimeScanDirection 0 -RemediationScheduleDay 0 -RemediationScheduleTime 100 -ReportingAdditionalActionTimeOut 5 -ReportingCriticalFailureTimeOut 6 -ReportingNonCriticalTimeOut 7 -ScanAvgCPULoadFactor 50 -ScanOnlyIfIdleEnabled $false -ScanPurgeItemsAfterDelay 15 -ScanScheduleDay 0 -ScanScheduleQuickScanTime 200 -ScanScheduleTime 200 -SevereThreatDefaultAction Remove -SignatureAuGracePeriod 30 -SignatureUpdateCatchupInterval 1 -SignatureUpdateInterval 1 -SubmitSamplesConsent 2 -UILockdown $false -UnknownThreatDefaultAction Quarantine -Force

Enable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null

#Domain Firewall
Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

#Public Firewall
Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowLocalFirewallRules False -AllowLocalIPsecRules False -LogFileName %SYSTEMROOT%\System32\logfiles\firewall\publicfw.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

#Private Firewall
Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName %SYSTEMROOT%\System32\logfiles\firewall\privatefw.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue

#Enable Structured Exception Handling Overwrite Protection
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -value 0 | out-null


#Enable Structured Exception Handling Overwrite Protection
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name DisableExceptionChainValidation -value 0 | out-null

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -force

Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue

$Processes = @(get-process | select-object name,company,path -uniq |
        where-object {$_.Path -like 'C:\Program Files\*' -or $_.Path -like 'C:\ProgramData\*' -and $_.Company -notmatch "Google" -and $_.Company -notmatch "Opera" -and $_.Company -notmatch "Mozilla" -and $_.Company -notmatch "VMware"})
foreach($Process in $Processes){
    Stop-Process -name $Process.name -force
}