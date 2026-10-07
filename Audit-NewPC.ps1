<#
====================================================================
 Audit-NewPC.ps1  -  DEEP read-only forensic audit of THIS machine
====================================================================
 Captures: hardware, NVMe SMART/wear, battery health, GPU/display,
 TPM/SecureBoot/virtualization, activation, touchpad/input, installed
 programs (registry + Appx + provisioned), optional features, startup,
 services, scheduled tasks, drivers + problem devices, network/firewall,
 power, Defender/BitLocker posture, AI+bloat+privacy posture, top RAM
 processes, folder tree, file inventory, pending reboot, hotfixes.

 SAFETY: READ-ONLY. No Set-/Remove-/Stop-/Disable- against the system.
         It only WRITES a report folder on your Desktop (+ a battery
         report and a DEGARBAGE-PLAN.md of suggested fixes it does NOT run).
         Does not read cloud file contents (no OneDrive/Dropbox hydration).
 RUN   : Start > Terminal (ADMIN for fullest data), then:
            Set-ExecutionPolicy -Scope Process Bypass -Force
            C:\path\to\Audit-NewPC.ps1
 OUT   : Desktop\NewPC-Audit-<timestamp>\  (report.md, DEGARBAGE-PLAN.md, CSVs)
====================================================================
#>

$TREE_DEPTH = 3   # EDIT: folder tree depth

$ts  = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path ([Environment]::GetFolderPath("Desktop")) "NewPC-Audit-$ts"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$report   = Join-Path $out "report.md"
$degarbage= Join-Path $out "DEGARBAGE-PLAN.md"
Start-Transcript -Path (Join-Path $out "run-log.txt") | Out-Null

# ---------- helpers ----------
function Add-Section($title, $body) { Add-Content $report "`n## $title`n"; Add-Content $report $body }
function Try-Get($label, $script) {
    Write-Host "[*] $label" -ForegroundColor Cyan
    try { & $script } catch { "  (could not read: $($_.Exception.Message))" }
}
function Get-RegVal($path, $name) {
    try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null }
}
function Write-Tree($path, $depth, $maxDepth, [System.Text.StringBuilder]$sb) {
    if ($depth -gt $maxDepth) { return }
    Get-ChildItem $path -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
        [void]$sb.AppendLine(('  ' * $depth) + $_.Name)
        Write-Tree $_.FullName ($depth + 1) $maxDepth $sb
    }
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Content $report "# New PC Deep Audit"
Add-Content $report "Generated: $(Get-Date)   Admin: $isAdmin"
Add-Content $report "Machine: $env:COMPUTERNAME   User: $env:USERNAME"
if (-not $isAdmin) { Add-Content $report "`n> NOTE: not elevated. Some sections (Appx -AllUsers, BitLocker, provisioned packages, full Defender) will be partial. Re-run as Admin for everything." }

# ---------- SYSTEM / HARDWARE ----------
Add-Section "System & Hardware" (Try-Get "System" {
    $os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem
    $bi=Get-CimInstance Win32_BIOS; $cpu=Get-CimInstance Win32_Processor; $bb=Get-CimInstance Win32_BaseBoard
@"
OS:        $($os.Caption) $($os.Version) (Build $($os.BuildNumber))  $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion)
Edition:   $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID)
Installed: $($os.InstallDate)
Model:     $($cs.Manufacturer) $($cs.Model)  ($($cs.SystemFamily))
Board:     $($bb.Manufacturer) $($bb.Product)  SN $($bb.SerialNumber)
BIOS:      $($bi.Manufacturer) $($bi.SMBIOSBIOSVersion)  ($($bi.ReleaseDate))
CPU:       $($cpu.Name)  $($cpu.NumberOfCores)C/$($cpu.NumberOfLogicalProcessors)T  $([math]::Round($cpu.MaxClockSpeed/1000,2))GHz
RAM:       $([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB
"@ })

Add-Section "Memory Modules" (Try-Get "RAM" {
    (Get-CimInstance Win32_PhysicalMemory | Select-Object @{n='GB';e={[math]::Round($_.Capacity/1GB,0)}},
      Speed, Manufacturer, PartNumber, @{n='Slot';e={$_.DeviceLocator}} | Format-Table -Auto | Out-String) })

# ---------- STORAGE HEALTH (NVMe SMART / wear) ----------
Add-Section "Storage - Disks & Health" (Try-Get "Storage" {
    $d = Get-Disk | Select-Object Number, FriendlyName, @{n='GB';e={[math]::Round($_.Size/1GB,0)}}, HealthStatus, PartitionStyle, BusType |
         Format-Table -Auto | Out-String
    $rel = foreach ($pd in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        $rc = $pd | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        [pscustomobject]@{ Disk=$pd.FriendlyName; Media=$pd.MediaType; Health=$pd.HealthStatus
            Wear=$rc.Wear; TempC=$rc.Temperature; PowerOnHrs=$rc.PowerOnHours
            ReadErr=$rc.ReadErrorsTotal; WriteErr=$rc.WriteErrorsTotal }
    }
    $v = Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemType,
         @{n='SizeGB';e={[math]::Round($_.Size/1GB,0)}}, @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,0)}},
         HealthStatus | Format-Table -Auto | Out-String
    "$d`nReliability (NVMe wear % / temp / hours / errors):`n$($rel | Format-Table -Auto | Out-String)`nVolumes:`n$v" })

# ---------- BATTERY HEALTH ----------
Add-Section "Battery Health" (Try-Get "Battery" {
    $b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    $full = (Get-CimInstance -Namespace root\wmi -Class BatteryFullChargedCapacity -ErrorAction SilentlyContinue).FullChargedCapacity
    $design = (Get-CimInstance -Namespace root\wmi -Class BatteryStaticData -ErrorAction SilentlyContinue).DesignedCapacity
    $health = if ($design) { [math]::Round(($full/$design)*100,1) } else { 'n/a' }
    powercfg /batteryreport /output (Join-Path $out "battery-report.html") 2>$null | Out-Null
    "Name: $($b.Name)  Status: $($b.BatteryStatus)`nDesign capacity: $design mWh  Full-charge now: $full mWh`nHealth (full/design): $health %`nFull HTML report -> battery-report.html" })

# ---------- GPU / DISPLAY ----------
Add-Section "GPU & Display" (Try-Get "GPU" {
    $g = Get-CimInstance Win32_VideoController | Select-Object Name,
         @{n='VRAM_GB';e={[math]::Round($_.AdapterRAM/1GB,1)}}, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate |
         Format-Table -Auto | Out-String
    $g })

# ---------- SECURITY HARDWARE ----------
Add-Section "TPM / Secure Boot / Virtualization" (Try-Get "SecHW" {
    $tpm = try { Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled | Format-List | Out-String } catch { "TPM: needs admin" }
    $sb  = try { "Secure Boot: $(Confirm-SecureBootUEFI)" } catch { "Secure Boot: not UEFI or needs admin" }
    $dg  = try { (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard -ErrorAction Stop |
            Select-Object @{n='VBS';e={$_.VirtualizationBasedSecurityStatus}}, SecurityServicesRunning | Format-List | Out-String) } catch { "DeviceGuard: n/a" }
    $virt = (Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled
    "$tpm`n$sb`nVirtualization firmware enabled (BIOS SVM): $virt`n$dg" })

# ---------- ACTIVATION ----------
Add-Section "Windows Activation" (Try-Get "Activation" {
    $p = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue |
         Select-Object Name, @{n='Status';e={switch($_.LicenseStatus){0{'Unlicensed'}1{'Licensed'}2{'OOB Grace'}3{'OOT Grace'}4{'Non-Genuine'}5{'Notification'}6{'Extended Grace'}}}}, PartialProductKey
    ($p | Format-Table -Auto | Out-String) })

# ---------- TOUCHPAD / INPUT ----------
Add-Section "Touchpad / Input Settings" (Try-Get "Touchpad" {
    $ptp = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad"
    $vals = try { Get-ItemProperty $ptp -ErrorAction Stop | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } catch { "No PrecisionTouchPad key (may be a non-precision touchpad)." }
    $mouse = Get-ItemProperty "HKCU:\Control Panel\Mouse" -ErrorAction SilentlyContinue | Select-Object MouseSpeed, MouseSensitivity, SwapMouseButtons | Format-List | Out-String
    "PrecisionTouchPad:`n$vals`nMouse:`n$mouse" })

# ---------- INSTALLED PROGRAMS ----------
Write-Host "[*] Installed programs (registry + Appx)" -ForegroundColor Cyan
$paths='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
$apps = foreach($p in $paths){ Get-ItemProperty $p -EA SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate }
$apps = $apps | Sort-Object DisplayName -Unique
$apps | Export-Csv (Join-Path $out "installed-programs.csv") -NoTypeInformation
Get-AppxPackage | Select-Object Name, Version, PublisherDisplayName, NonRemovable |
    Sort-Object Name | Export-Csv (Join-Path $out "appx-packages.csv") -NoTypeInformation
if ($isAdmin) {
    Get-AppxProvisionedPackage -Online -EA SilentlyContinue | Select-Object DisplayName, Version |
        Export-Csv (Join-Path $out "appx-provisioned.csv") -NoTypeInformation
}
Add-Section "Installed Programs ($($apps.Count))" "Desktop apps -> installed-programs.csv. Store/Appx -> appx-packages.csv. Provisioned (new-user) -> appx-provisioned.csv.`nFirst 50 desktop apps:`n`n$([string]::Join("`n",($apps.DisplayName|Select-Object -First 50)))"

# ---------- OPTIONAL FEATURES ----------
if ($isAdmin) {
    Add-Section "Windows Optional Features (enabled)" (Try-Get "Features" {
        (Get-WindowsOptionalFeature -Online -EA SilentlyContinue | Where-Object State -eq 'Enabled' |
          Select-Object -Expand FeatureName | Sort-Object) -join "`n" })
}

# ---------- STARTUP ----------
Add-Section "Startup (Run keys + folders + WMI)" (Try-Get "Startup" {
    $runKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
               'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    $r = foreach($k in $runKeys){ $p=Get-ItemProperty $k -EA SilentlyContinue; if($p){ $p.PSObject.Properties|Where-Object {$_.Name -notlike 'PS*'}|ForEach-Object{"[$k] $($_.Name) = $($_.Value)"} } }
    $folders = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    $f = foreach($fp in $folders){ Get-ChildItem $fp -EA SilentlyContinue | ForEach-Object{"[Startup folder] $($_.Name)"} }
    (($r + $f) -join "`n") })

# ---------- SERVICES (non-Microsoft, running) ----------
Add-Section "Third-Party Services (running)" (Try-Get "Services" {
    (Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch 'C:\\WINDOWS' -and $_.State -eq 'Running' } |
      Select-Object Name, StartMode, PathName | Sort-Object Name | Format-Table -Auto | Out-String) })

# ---------- SCHEDULED TASKS (non-Microsoft) ----------
Add-Section "Third-Party Scheduled Tasks" (Try-Get "Tasks" {
    (Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' } |
      Select-Object TaskName, TaskPath | Format-Table -Auto | Out-String) })

# ---------- DRIVERS + PROBLEM DEVICES ----------
Add-Section "Problem Devices (error codes)" (Try-Get "ProblemDev" {
    $bad = Get-PnpDevice -EA SilentlyContinue | Where-Object { $_.Status -ne 'OK' -and $_.Class -ne $null } |
           Select-Object Status, Class, FriendlyName, InstanceId
    if ($bad) { ($bad | Format-Table -Auto | Out-String) } else { "All devices report OK (no yellow-bang)." } })
Get-CimInstance Win32_PnPSignedDriver -EA SilentlyContinue |
  Where-Object { $_.Manufacturer -and $_.Manufacturer -notmatch 'Microsoft' -and $_.DeviceName } |
  Select-Object DeviceName, DriverVersion, Manufacturer, DriverDate | Sort-Object DeviceName -Unique |
  Export-Csv (Join-Path $out "drivers.csv") -NoTypeInformation
Add-Content $report "`n(Third-party drivers -> drivers.csv)`n"

# ---------- NETWORK ----------
Add-Section "Network" (Try-Get "Net" {
    $ipc = Get-NetIPConfiguration -EA SilentlyContinue | Select-Object InterfaceAlias,
           @{n='IPv4';e={($_.IPv4Address.IPAddress) -join ','}}, @{n='GW';e={$_.IPv4DefaultGateway.NextHop}},
           @{n='DNS';e={($_.DNSServer.ServerAddresses) -join ','}} | Format-Table -Auto | Out-String
    $proxy = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue |
             Select-Object ProxyEnable, ProxyServer | Format-List | Out-String
    $fw = Get-NetFirewallProfile -EA SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -Auto | Out-String
    "Interfaces:`n$ipc`nProxy:`n$proxy`nFirewall profiles:`n$fw" })

# ---------- POWER ----------
Add-Section "Power Plan" (Try-Get "Power" {
    "$(powercfg /getactivescheme 2>$null | Out-String)`n$(powercfg /list 2>$null | Out-String)" })

# ---------- DEFENDER / BITLOCKER ----------
Add-Section "Security Posture" (Try-Get "Defender" {
    $mp = try { Get-MpComputerStatus -EA Stop | Select-Object AMRunningMode, RealTimeProtectionEnabled, TamperProtectionSource, AntivirusEnabled, AntispywareEnabled | Format-List | Out-String } catch { "Defender status n/a (third-party AV like CrowdStrike may own it)." }
    $bl = try { Get-BitLockerVolume -EA Stop | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage | Format-Table -Auto | Out-String } catch { "BitLocker: needs admin." }
    "$mp`nBitLocker:`n$bl" })

# ====================  AI / BLOAT / PRIVACY POSTURE  ====================
Write-Host "[*] AI / bloat / privacy posture (the de-garbage scan)" -ForegroundColor Yellow
$findings = New-Object System.Collections.Generic.List[object]
function Note($item,$state,$fix){ $findings.Add([pscustomobject]@{ Item=$item; State=$state; Fix=$fix }) }

# Copilot app
$cop = Get-AppxPackage -Name "*Copilot*" -EA SilentlyContinue
Note "Copilot app installed" $(if($cop){"YES: $($cop.Name -join ', ')"}else{"no"}) 'Get-AppxPackage -AllUsers *Copilot* | Remove-AppxPackage'
# Copilot policy block
$copPol = Get-RegVal 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot'
Note "Copilot policy block (TurnOffWindowsCopilot)" $(if($copPol -eq 1){"ON (blocked)"}else{"not set"}) 'reg add HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f'
# Copilot taskbar button
$copBtn = Get-RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowCopilotButton'
Note "Copilot taskbar button" $(if($copBtn -eq 1){"shown"}elseif($copBtn -eq 0){"hidden"}else{"default"}) 'Settings > Personalization > Taskbar > Copilot Off'
# Recall (Copilot+ only; likely absent on Ryzen 6850U)
$recall = if($isAdmin){ (Get-WindowsOptionalFeature -Online -FeatureName Recall -EA SilentlyContinue).State } else { 'need admin' }
Note "Recall feature" $(if($recall){"$recall"}else{"not present"}) 'Disable-WindowsOptionalFeature -Online -FeatureName Recall -NoRestart  (only if Enabled)'
# Telemetry
$telem = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry'
Note "Telemetry policy (AllowTelemetry)" $(if($null -ne $telem){"$telem (0=Security,1=Basic)"}else{"not set (default Full)"}) 'reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 0 /f'
# Advertising ID
$adid = Get-RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled'
Note "Advertising ID" $(if($adid -eq 0){"off"}else{"on/default"}) 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f'
# Web search in Start
$bing = Get-RegVal 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions'
Note "Web/Bing suggestions in Start search" $(if($bing -eq 1){"disabled"}else{"on/default"}) 'reg add HKCU\Software\Policies\Microsoft\Windows\Explorer /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f'
# Suggested content / ads
$cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$sugg = Get-RegVal $cdm 'SystemPaneSuggestionsEnabled'
Note "Start/Settings suggested content (ads)" $(if($sugg -eq 0){"off"}else{"on/default"}) "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f (+ SubscribedContent-338388Enabled, -338389Enabled, -310093Enabled = 0)"
$silent = Get-RegVal $cdm 'SilentInstalledAppsEnabled'
Note "Auto-installed promoted apps" $(if($silent -eq 0){"off"}else{"on/default"}) 'reg add ...ContentDeliveryManager /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f'
# Consumer features
$consumer = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures'
Note "Windows consumer features (suggested 3rd-party apps)" $(if($consumer -eq 1){"disabled"}else{"on/default"}) 'reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f'
# Widgets / Web Experience Pack
$web = Get-AppxPackage -Name "*WebExperience*" -EA SilentlyContinue
Note "Widgets / Web Experience Pack" $(if($web){"installed"}else{"not present"}) 'Get-AppxPackage *WebExperience* | Remove-AppxPackage'
# Edge Copilot sidebar
$edgeHub = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled'
Note "Edge Copilot/Hubs sidebar" $(if($edgeHub -eq 0){"disabled"}else{"on/default"}) 'reg add HKLM\SOFTWARE\Policies\Microsoft\Edge /v HubsSidebarEnabled /t REG_DWORD /d 0 /f'

$findings | Export-Csv (Join-Path $out "ai-bloat-posture.csv") -NoTypeInformation
Add-Section "AI / Bloat / Privacy Posture" (($findings | Format-Table Item, State -Auto | Out-String) + "`nFull table with fix commands -> ai-bloat-posture.csv and DEGARBAGE-PLAN.md")

# write the actionable (NOT executed) remediation plan
$dg = New-Object System.Text.StringBuilder
[void]$dg.AppendLine("# DE-GARBAGE PLAN (review, then run what you want - nothing here was executed)")
[void]$dg.AppendLine("# Make a restore point first:  Checkpoint-Computer -Description 'pre-degarbage' -RestorePointType MODIFY_SETTINGS")
[void]$dg.AppendLine("")
foreach ($f in $findings) {
    [void]$dg.AppendLine("## $($f.Item)  [now: $($f.State)]")
    [void]$dg.AppendLine($f.Fix)
    [void]$dg.AppendLine("")
}
[void]$dg.AppendLine("# Keep (do NOT remove): OneDrive (you use A Glitch), Edge (client profiles), Defender unless CrowdStrike owns AV.")
$dg.ToString() | Out-File $degarbage -Encoding UTF8

# ---------- TOP RAM PROCESSES ----------
Add-Section "Top 15 Processes by RAM" (Try-Get "Proc" {
    (Get-Process | Sort-Object WS -Descending | Select-Object -First 15 Name,
      @{n='RAM_MB';e={[math]::Round($_.WS/1MB,0)}}, Id | Format-Table -Auto | Out-String) })

# ---------- FOLDER TREE + APPDATA + DISK ----------
Write-Host "[*] Folder tree + inventory" -ForegroundColor Cyan
$sb = New-Object System.Text.StringBuilder
foreach ($root in @("$env:USERPROFILE","$env:USERPROFILE\Dropbox","$env:OneDrive")) {
    if ($root -and (Test-Path $root)) { [void]$sb.AppendLine("`n===== $root ====="); Write-Tree $root 0 $TREE_DEPTH $sb }
}
$sb.ToString() | Out-File (Join-Path $out "folders-tree.txt") -Encoding UTF8
Add-Section "Folder Layout" "Full tree (depth $TREE_DEPTH) -> folders-tree.txt"
Add-Section "Largest Folders In Profile" (Try-Get "Folder sizes" {
    Get-ChildItem $env:USERPROFILE -Directory -Force -EA SilentlyContinue | ForEach-Object {
        $sz=(Get-ChildItem $_.FullName -Recurse -File -Force -EA SilentlyContinue | Measure-Object Length -Sum).Sum
        [pscustomobject]@{ Folder=$_.Name; GB=[math]::Round(($sz/1GB),2) }
    } | Sort-Object GB -Descending | Format-Table -Auto | Out-String })

# ---------- PENDING REBOOT + HOTFIXES ----------
Add-Section "Pending Reboot & Recent Updates" (Try-Get "Reboot" {
    $pend = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $hf = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn | Format-Table -Auto | Out-String)
    "Pending reboot: $pend`nRecent hotfixes:`n$hf" })

Add-Section "PATH" ($env:PATH -replace ';', "`n")

# ====================  SELF-VERIFICATION  ====================
Write-Host "[*] Verifying outputs..." -ForegroundColor Yellow
$expected = "report.md","installed-programs.csv","appx-packages.csv","ai-bloat-posture.csv","DEGARBAGE-PLAN.md","folders-tree.txt"
$verify = foreach($f in $expected){ $p=Join-Path $out $f; [pscustomobject]@{ File=$f; Exists=(Test-Path $p); KB=$(if(Test-Path $p){[math]::Round((Get-Item $p).Length/1KB,1)}else{0}) } }
$summary = @"
Admin run:        $isAdmin
Desktop apps:     $($apps.Count)
AI/bloat checks:  $($findings.Count)
Outputs:
$($verify | Format-Table -Auto | Out-String)
"@
Add-Section "Verification Summary" $summary
Write-Host $summary -ForegroundColor Green
Stop-Transcript | Out-Null
Write-Host "DONE -> $out" -ForegroundColor Green
Start-Process $out
