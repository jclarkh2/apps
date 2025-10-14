
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    Break
}

$ProgressPreference = 'SilentlyContinue'

$logDir = "C:\Logs"
$logFile = Join-Path $logDir "SoftwareInstallation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$htmlReportFile = Join-Path $logDir "InstallationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

$script:tempDir = "C:\Temp\LabSetup"
if (-not (Test-Path $script:tempDir)) {
    New-Item -ItemType Directory -Path $script:tempDir -Force | Out-Null
}

$script:installationResults = @()
$script:needsRestart = $false

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level]: $Message"
    Write-Host $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

function Show-InstallProgress {
    param (
        [string]$Activity,
        [int]$TotalSteps,
        [int]$CurrentStep
    )
    $percentComplete = [math]::Min(100, [math]::Round(($CurrentStep / $TotalSteps) * 100))
    Write-Progress -Activity $Activity -Status "$percentComplete% Complete" -PercentComplete $percentComplete
}

function Get-WebFile {
    param (
        [string]$Url,
        [string]$OutputPath,
        [int]$MaxRetries = 3
    )
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            if ($retryCount -gt 0) {
                Write-Log "Retry attempt $retryCount of $MaxRetries for: $Url"
                Start-Sleep -Seconds (5 * $retryCount)
            } else {
                Write-Log "Downloading from: $Url"
            }
            
            try {
                Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
                
                if (Test-Path $OutputPath) {
                    $fileSize = (Get-Item $OutputPath).Length / 1MB
                    Write-Log "Download completed: $OutputPath (Size: $([math]::Round($fileSize, 2)) MB)"
                    return $true
                } else {
                    Write-Log "Download failed: File not found at $OutputPath"
                }
            } catch {
                Write-Log "Download failed, trying alternative method..."
                try {
                    $webClient = New-Object System.Net.WebClient
                    $webClient.Headers.Add("User-Agent", "PowerShell")
                    $webClient.DownloadFile($Url, $OutputPath)
                    
                    if (Test-Path $OutputPath) {
                        $fileSize = (Get-Item $OutputPath).Length / 1MB
                        Write-Log "Download completed using WebClient: $OutputPath (Size: $([math]::Round($fileSize, 2)) MB)"
                        return $true
                    }
                } finally {
                    if ($webClient) {
                        $webClient.Dispose()
                    }
                }
            }
        } catch {
            Write-Log "Error downloading file (attempt $($retryCount + 1)): $_"
        }
        
        $retryCount++
    }
    
    Write-Log "Failed to download after $MaxRetries attempts: $Url" -Level Error
    return $false
}

function Test-NetworkConnectivity {
    Write-Log "Checking network connectivity..."
    
    $testUrls = @(
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://dl.google.com"
    )
    
    foreach ($url in $testUrls) {
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 -Method Head
            if ($response.StatusCode -eq 200) {
                Write-Log "Network connectivity confirmed via $url"
                return $true
            }
        } catch {
            Write-Log "Failed to connect to $url"
        }
    }
    
    Write-Log "Network connectivity check failed!" -Level Error
    return $false
}

function Test-DiskSpace {
    param(
        [int]$RequiredSpaceGB = 20
    )
    
    Write-Log "Checking available disk space..."
    
    $systemDrive = $env:SystemDrive
    $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    
    Write-Log "Available space on $systemDrive : $freeSpaceGB GB"
    
    if ($freeSpaceGB -lt $RequiredSpaceGB) {
        Write-Log "Insufficient disk space! Required: $RequiredSpaceGB GB, Available: $freeSpaceGB GB" -Level Error
        return $false
    }
    
    Write-Log "Disk space check passed"
    return $true
}

function Add-InstallationResult {
    param(
        [string]$Software,
        [bool]$Success,
        [string]$Message = ""
    )
    
    $script:installationResults += [PSCustomObject]@{
        Software = $Software
        Success = $Success
        Status = if ($Success) { "[OK] Installed" } else { "[FAIL] Failed" }
        Message = $Message
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Get-WindowsBuildNumber {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [System.Version]$osInfo.Version
    return $osVersion.Build
}

function Set-TimeZoneEST {
    Write-Log "Configuring time zone to Eastern Standard Time..."
    
    try {
        $currentTimeZone = (Get-TimeZone).Id
        $targetTimeZone = "Eastern Standard Time"
        
        if ($currentTimeZone -ne $targetTimeZone) {
            Set-TimeZone -Id $targetTimeZone
            Write-Log "Time zone set to $targetTimeZone"
            return $true
        } else {
            Write-Log "Time zone already set to $targetTimeZone"
            return $true
        }
    } catch {
        Write-Log "Failed to set time zone: $_" -Level Error
        return $false
    }
}

function Set-WindowsUpdateSettings {
    Write-Log "Configuring Windows Update settings..."
    
    try {
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $auPath)) {
            New-Item -Path $auPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 3 -Type DWord -Force
        Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
        
        Write-Log "Windows Update configured successfully"
        return $true
    } catch {
        Write-Log "Failed to configure Windows Update: $_" -Level Error
        return $false
    }
}

function Set-PowerShellExecutionPolicy {
    Write-Log "Checking PowerShell execution policy..."
    
    $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
    
    if ($currentPolicy -eq "Restricted" -or $currentPolicy -eq "Undefined") {
        try {
            $output = Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>&1
            
            $newPolicy = Get-ExecutionPolicy -Scope LocalMachine
            if ($newPolicy -ne "Restricted" -and $newPolicy -ne "Undefined") {
                Write-Log "PowerShell execution policy set to $newPolicy"
                return $true
            }
            
            $effectivePolicy = Get-ExecutionPolicy
            if ($effectivePolicy -ne "Restricted" -and $effectivePolicy -ne "Undefined") {
                Write-Log "PowerShell execution policy is managed by Group Policy (effective policy: $effectivePolicy)"
                return $true
            }
            
            Write-Log "Could not set execution policy (may be restricted by Group Policy)" -Level Warning
            return $true  # Don't fail the script for this
            
        } catch {
            Write-Log "Error checking execution policy: $_" -Level Warning
            return $true  # Don't fail the script for this
        }
    } else {
        Write-Log "PowerShell execution policy is already set to $currentPolicy"
        return $true
    }
}

function Test-DomainMembership {
    Write-Log "Checking domain membership..."
    
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain
        
        if ($isDomainJoined) {
            $domain = $computerSystem.Domain
            Write-Log "Computer is joined to domain: $domain"
            
            if ($domain -like "*AWINYC*" -or $domain -like "*americaworks.com*") {
                Write-Log "Confirmed membership in AWINYC domain"
                return $true
            } else {
                Write-Log "Computer is domain-joined but not to AWINYC domain (Domain: $domain)"
                return $true
            }
        } else {
            Write-Log "Computer is NOT joined to a domain (Workgroup: $($computerSystem.Workgroup))"
            return $false
        }
    } catch {
        Write-Log "Error checking domain membership: $_" -Level Error
        return $false
    }
}

function New-ClientLocalUser {
    Write-Log "Creating local user account 'Client'..."
    
    try {
        $password = ConvertTo-SecureString "awjobs" -AsPlainText -Force
        
        $existingUser = Get-LocalUser -Name "Client" -ErrorAction SilentlyContinue
        
        if ($existingUser) {
            Write-Log "Local user 'Client' already exists"
            
            try {
                $existingUser | Set-LocalUser -Password $password -PasswordNeverExpires $true
                Write-Log "Updated 'Client' user: password set, never expires"
            } catch {
                Write-Log "Could not update password for existing 'Client' user: $_" -Level Warning
            }
            
            return $true
        }
        
        $newUser = New-LocalUser -Name "Client" -Description "Local client user account" -Password $password -ErrorAction Stop
        
        Set-LocalUser -Name "Client" -PasswordNeverExpires $true
        
        Add-LocalGroupMember -Group "Users" -Member "Client" -ErrorAction SilentlyContinue
        
        Write-Log "Successfully created local user 'Client' with password"
        Write-Log "User 'Client' added to Users group"
        
        return $true
        
    } catch {
        Write-Log "Failed to create local user 'Client': $_" -Level Error
        return $false
    }
}

function New-HTMLReport {
    $successCount = ($script:installationResults | Where-Object { $_.Success -eq $true }).Count
    $failCount = ($script:installationResults | Where-Object { $_.Success -eq $false }).Count
    $totalCount = $script:installationResults.Count
    
    $computerName = $env:COMPUTERNAME
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Caption
    $buildNumber = Get-WindowsBuildNumber
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Lab Computer Installation Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-box { padding: 20px; border-radius: 5px; text-align: center; }
        .success-box { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .fail-box { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .total-box { background-color: #d1ecf1; border: 1px solid #bee5eb; }
        .summary-number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .summary-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #3498db; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .success { color: #28a745; font-weight: bold; }
        .failed { color: #dc3545; font-weight: bold; }
        .info-section { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .info-row { display: flex; justify-content: space-between; padding: 5px 0; }
        .info-label { font-weight: bold; color: #495057; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Lab Computer Installation Report</h1>
        
        <div class="info-section">
            <div class="info-row">
                <span class="info-label">Computer Name:</span>
                <span>$computerName</span>
            </div>
            <div class="info-row">
                <span class="info-label">Operating System:</span>
                <span>$osVersion (Build $buildNumber)</span>
            </div>
            <div class="info-row">
                <span class="info-label">Report Generated:</span>
                <span>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</span>
            </div>
            <div class="info-row">
                <span class="info-label">Time Zone:</span>
                <span>$(Get-TimeZone | Select-Object -ExpandProperty Id)</span>
            </div>
        </div>
        
        <h2>Installation Summary</h2>
        <div class="summary">
            <div class="summary-box success-box">
                <div class="summary-number">$successCount</div>
                <div class="summary-label">Successful</div>
            </div>
            <div class="summary-box fail-box">
                <div class="summary-number">$failCount</div>
                <div class="summary-label">Failed</div>
            </div>
            <div class="summary-box total-box">
                <div class="summary-number">$totalCount</div>
                <div class="summary-label">Total</div>
            </div>
        </div>
        
        <h2>Installation Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Software</th>
                    <th>Status</th>
                    <th>Message</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($result in $script:installationResults) {
        $statusClass = if ($result.Success) { "success" } else { "failed" }
        $html += @"
                <tr>
                    <td>$($result.Software)</td>
                    <td class="$statusClass">$($result.Status)</td>
                    <td>$($result.Message)</td>
                    <td>$($result.Timestamp)</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <div class="footer">
            <p>Log file location: $logFile</p>
            <p>Generated by Lab Computer Configuration Script</p>
        </div>
    </div>
</body>
</html>
"@
    
    try {
        Set-Content -Path $htmlReportFile -Value $html -Force
        Write-Log "HTML report generated: $htmlReportFile"
        return $true
    } catch {
        Write-Log "Failed to generate HTML report: $_" -Level Error
        return $false
    }
}

function Test-ApplicationInstalled {
    param (
        [string]$ApplicationName,
        [string]$Publisher = ""
    )
    
    $installed = $false
    
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    
    foreach ($path in $paths) {
        $installed = $installed -or (
            Get-ItemProperty $path | 
            Where-Object { 
                $_.DisplayName -like "*$ApplicationName*" -and
                ($Publisher -eq "" -or $_.Publisher -like "*$Publisher*")
            }
        )
        if ($installed) { break }
    }
    
    if ($installed) {
        Write-Log "$ApplicationName is already installed"
        return $true
    }
    return $false
}

function Test-TeamsInstalled {
    
    try {
        $teamsApp = Get-AppxPackage -Name "MSTeams*"
        if ($teamsApp) {
            Write-Log "Found Teams Store app version: $($teamsApp.Version)"
            return $true
        }

        $traditionalPaths = @(
            "${env:ProgramFiles}\Microsoft\Teams\current\Teams.exe",
            "${env:LocalAppData}\Microsoft\WindowsApps\MicrosoftTeams_8wekyb3d8bbwe\msteams.exe"
        )

        foreach ($path in $traditionalPaths) {
            if (Test-Path $path) {
                Write-Log "Found Teams at traditional path: $path"
                return $true
            }
        }
    
        $teamsPath = "${env:ProgramFiles}\WindowsApps\MSTeams_*_*__8wekyb3d8bbwe\ms-teams.exe"
        $newTeamsPath = (Get-ChildItem -Path $teamsPath -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
        if ($newTeamsPath) {
            Write-Log "Found Teams at: $newTeamsPath"
            return $true
        }
    
        Write-Log "Teams is not installed"
        return $false
    } catch {
        Write-Log "Error checking Teams installation: $_"
        return $false
    }
}

function Test-ZoomInstalled { 
    $zoomPaths = @(
        "${env:ProgramFiles}\Zoom\bin\Zoom.exe",
        "${env:ProgramFiles(x86)}\Zoom\bin\Zoom.exe",
        "$env:APPDATA\Zoom\bin\Zoom.exe"
    )
    
    foreach ($path in $zoomPaths) {
        if (Test-Path $path) {
            Write-Log "Found Zoom executable at: $path"
            return $true
        }
    }    

    $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
        Where-Object { 
            $_.DisplayName -like "*Zoom*" -and 
            $_.DisplayName -notlike "*Outlook*" -and 
            $_.Publisher -like "*Zoom*" 
        }

    if ($installed) {
        Write-Log "Found Zoom in registry: $($installed.DisplayName)"
        return $true
    }
    
    Write-Log "Zoom is not installed, proceeding with installation..."
    return $false
}

function Install-Chrome {
    Write-Log "Installing Google Chrome..."
    if (Test-ApplicationInstalled -ApplicationName "Google Chrome" -Publisher "Google") {
        Write-Log "Skipping Chrome installation as it's already installed"
        return $true
    }
    
    try {
        Get-Process -Name "chrome" -ErrorAction SilentlyContinue | ForEach-Object { 
            Write-Log "Stopping existing Chrome process..."
            $_.Kill()
            $_.WaitForExit()
        }
        
        $chromeUrl = "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi"
        $chromePath = Join-Path $script:tempDir "ChromeSetup.msi"
        
        if (Get-WebFile -Url $chromeUrl -OutputPath $chromePath) {
            Write-Log "Installing Chrome using MSI..."
            
            $arguments = @(
                "/i",
                "`"$chromePath`"",
                "/qn",                  # Silent installation
                "/norestart",          # Prevent restart
                "ALLUSERS=1",          # Install for all users
                "NOGOOGLEUPDATER=0"    # built-in updater
            )
            
            $process = Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow -PassThru
            
            if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) { # 0 = success, 3010 = success but restart required
                Start-Sleep -Seconds 5
                $installed = Test-ApplicationInstalled -ApplicationName "Google Chrome" -Publisher "Google"
                if ($installed) {
                    Write-Log "Chrome installation completed successfully"
                    return $true
                }
            }
            
            Write-Log "Chrome installer exited with code: $($process.ExitCode)"
        }
        
        return $false
    } catch {
        Write-Log "Error during Chrome installation: $_"
        return $false
    }
    return $false
}

function Install-Teams {
    Write-Log "Installing Microsoft Teams..."
    if (Test-TeamsInstalled) {
        Write-Log "Teams is already installed"
        return $true
    }

    try {
        $teamsUrl = "https://go.microsoft.com/fwlink/?linkid=2243204`&clcid=0x409"  # Link to TeamsBootstrapper.exe
        $teamsPath = Join-Path $script:tempDir "TeamsBootstrapper.exe"
        
        if (Get-WebFile -Url $teamsUrl -OutputPath $teamsPath) {
            Write-Log "Installing new Teams client..."
            Start-Process -FilePath $teamsPath -ArgumentList "--provision-admin" -Wait -NoNewWindow
            
            $retries = 0
            $maxRetries = 12
            do {
                Start-Sleep -Seconds 10
                $installed = Test-TeamsInstalled
                $retries++
            } while (-not $installed -and $retries -lt $maxRetries)
            
            if ($installed) {
                Write-Log "Teams installation completed successfully"
                return $true
            } else {
                Write-Log "Teams installation verification failed after 2 minutes"
                return $false
            }
        }
    } catch {
        Write-Log "Error during Teams installation: $_"
        return $false
    }
    
    return $false
}

function Install-Zoom {
    Write-Log "Installing Zoom..."
    
    if (Test-ZoomInstalled) {
        Write-Log "Skipping Zoom installation as it's already installed"
        return $true
    }
    
    $zoomUrl = "https://zoom.us/client/latest/ZoomInstallerFull.msi"
    $zoomPath = Join-Path $script:tempDir "ZoomInstaller.msi"
    
    if (Get-WebFile -Url $zoomUrl -OutputPath $zoomPath) {
        Start-Process "msiexec.exe" -ArgumentList "/i `"$zoomPath`" /qn" -Wait -NoNewWindow
        
        Start-Sleep -Seconds 5
        if (Test-ZoomInstalled) {
            Write-Log "Zoom installation successful"
            return $true
        }
    }
    
    Write-Log "Zoom installation failed"
    return $false
}

function Install-Firefox {
    Write-Log "Installing Firefox..."
    if (Test-ApplicationInstalled -ApplicationName "Firefox" -Publisher "Mozilla") {
        Write-Log "Skipping Firefox installation as it's already installed"
        return $true
    }

    $firefoxUrl = "https://download.mozilla.org/?product=firefox-msi-latest-ssl`&os=win64`&lang=en-US"
    $firefoxPath = Join-Path $script:tempDir "FirefoxSetup.msi"
    if (Get-WebFile -Url $firefoxUrl -OutputPath $firefoxPath) {
        Start-Process "msiexec.exe" -ArgumentList "/i `"$firefoxPath`" /qn" -Wait -NoNewWindow
        return Test-ApplicationInstalled -ApplicationName "Firefox" -Publisher "Mozilla"
    }
    return $false
}

function Install-NotepadPlusPlus {
    Write-Log "Installing Notepad++..."
    if (Test-ApplicationInstalled -ApplicationName "Notepad++" -Publisher "Notepad++ Team") {
        Write-Log "Skipping Notepad++ installation as it's already installed"
        return $true
    }

    try {
        $nppUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.2/npp.8.6.2.Installer.x64.exe"
        $nppPath = Join-Path $script:tempDir "NotepadPlusPlus.exe"
        
        if (Get-WebFile -Url $nppUrl -OutputPath $nppPath) {
            Write-Log "Installing Notepad++..."
            Start-Process -FilePath $nppPath -ArgumentList "/S" -Wait -NoNewWindow
            Start-Sleep -Seconds 5
            return Test-ApplicationInstalled -ApplicationName "Notepad++" -Publisher "Notepad++ Team"
        }
    }
    catch {
        Write-Log "Error during Notepad++ installation: $_"
        
        Write-Log "Trying fallback URL..."
        $fallbackUrl = "https://downloads.sourceforge.net/notepad-plus/npp.8.6.2.Installer.x64.exe"
        $nppPath = Join-Path $script:tempDir "NotepadPlusPlus.exe"
        
        if (Get-WebFile -Url $fallbackUrl -OutputPath $nppPath) {
            Write-Log "Installing Notepad++ using fallback version..."
            Start-Process -FilePath $nppPath -ArgumentList "/S" -Wait -NoNewWindow
            Start-Sleep -Seconds 5
            return Test-ApplicationInstalled -ApplicationName "Notepad++" -Publisher "Notepad++ Team"
        }
    }
    return $false
}

function Install-AdobeReader {
    Write-Log "Installing Adobe Reader DC..."
    
    $adobePaths = @(
        "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
        "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    )
    
    foreach ($path in $adobePaths) {
        if (Test-Path $path) {
            Write-Log "Found Adobe Reader/Acrobat at: $path"
            return $true
        }
    }
    
    $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
        Where-Object { 
            ($_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*") -and 
            $_.Publisher -like "*Adobe*" 
        }

    if ($installed) {
        Write-Log "Found Adobe Reader in registry: $($installed.DisplayName)"
        return $true
    }

    Write-Log "Adobe Reader is not installed, proceeding with installation..."
    $adobeUrl = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/2300320269/AcroRdrDC2300320269_en_US.exe"
    $adobePath = Join-Path $script:tempDir "AdobeReaderSetup.exe"
    
    if (Get-WebFile -Url $adobeUrl -OutputPath $adobePath) {
        Write-Log "Installing Adobe Reader..."
        Start-Process -FilePath $adobePath -ArgumentList "/sAll /rs /msi /norestart /quiet EULA_ACCEPT=YES" -Wait -NoNewWindow
        
        foreach ($path in $adobePaths) {
            if (Test-Path $path) {
                Write-Log "Adobe Reader installation successful, found at: $path"
                return $true
            }
        }
        
        $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
            Where-Object { 
                ($_.DisplayName -like "*Adobe Acrobat Reader*" -or $_.DisplayName -like "*Adobe Acrobat DC*") -and 
                $_.Publisher -like "*Adobe*" 
            }
        
        if ($installed) {
            Write-Log "Adobe Reader installation verified in registry"
            return $true
        }
        
        Write-Log "Adobe Reader installation failed - not found in registry"
    }
    
    return $false
}

function Install-Java {
    Write-Log "Installing Java..."
    if (Test-ApplicationInstalled -ApplicationName "Java" -Publisher "Oracle") {
        Write-Log "Skipping Java installation as it's already installed"
        return $true
    }

    try {     
        $javaUrl = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=249553_4d245f941845490c91360409ecffb3b4"
        $javaPath = Join-Path $script:tempDir "JavaSetup.exe"
        
        if (Get-WebFile -Url $javaUrl -OutputPath $javaPath) {
            Write-Log "Installing Java..."
            Start-Process -FilePath $javaPath -ArgumentList "/s" -Wait -NoNewWindow
            
            Start-Sleep -Seconds 5
            $installed = Test-ApplicationInstalled -ApplicationName "Java" -Publisher "Oracle"
            if ($installed) {
                Write-Log "Java installation completed successfully"
                return $true
            } else {
                Write-Log "Java installation failed - not found in registry"
                return $false
            }
        }
    } catch {
        Write-Log "Error during Java installation: $_"
        
        Write-Log "Trying fallback URL..."        
        $fallbackUrl = "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=248242_ce59cff5c23f4e2eaf4e778a117d4c5b"
        $javaPath = Join-Path $script:tempDir "JavaSetup.exe"
        
        if (Get-WebFile -Url $fallbackUrl -OutputPath $javaPath) {
            Write-Log "Installing Java using fallback version..."
            Start-Process -FilePath $javaPath -ArgumentList "/s" -Wait -NoNewWindow
            
            Start-Sleep -Seconds 5
            return Test-ApplicationInstalled -ApplicationName "Java" -Publisher "Oracle"
        }
    }
    return $false
}

function Install-7Zip {
    Write-Log "Installing 7-Zip..."
    if (Test-ApplicationInstalled -ApplicationName "7-Zip") {
        Write-Log "Skipping 7-Zip installation as it's already installed"
        return $true
    }

    $7zipUrl = "https://7-zip.org/a/7z2301-x64.exe"
    $7zipPath = Join-Path $script:tempDir "7zipSetup.exe"
    if (Get-WebFile -Url $7zipUrl -OutputPath $7zipPath) {
        Start-Process -FilePath $7zipPath -ArgumentList "/S" -Wait -NoNewWindow
        return Test-ApplicationInstalled -ApplicationName "7-Zip"
    }
    return $false
}

function Install-VLC {
    Write-Log "Installing VLC Media Player..."
    if (Test-ApplicationInstalled -ApplicationName "VLC media player" -Publisher "VideoLAN") {
        Write-Log "Skipping VLC installation as it's already installed"
        return $true
    }

    $vlcUrls = @(
        "https://download.videolan.org/pub/videolan/vlc/last/win64/vlc-3.0.21-win64.exe",
        "https://mirror.csclub.uwaterloo.ca/vlc/vlc/3.0.21/win64/vlc-3.0.21-win64.exe",
        "https://ftp.osuosl.org/pub/videolan/vlc/3.0.21/win64/vlc-3.0.21-win64.exe",
        "https://mirrors.syringanetworks.net/videolan/vlc/3.0.21/win64/vlc-3.0.21-win64.exe"
    )
    
    $vlcPath = Join-Path $script:tempDir "VLCSetup.exe"
    
    foreach ($url in $vlcUrls) {
        Write-Log "Trying VLC download from: $url"
        if (Get-WebFile -Url $url -OutputPath $vlcPath -MaxRetries 2) {
            Start-Process -FilePath $vlcPath -ArgumentList "/L=1033 /S" -Wait -NoNewWindow
            Start-Sleep -Seconds 5
            if (Test-ApplicationInstalled -ApplicationName "VLC media player" -Publisher "VideoLAN") {
                return $true
            }
        }
    }
    
    Write-Log "All VLC download mirrors failed" -Level Error
    return $false
}


function Set-Win11TaskbarLayout {
    param(
        [switch]$ForDefaultUser
    )
    
    Write-Log "Configuring Windows 11 Taskbar layout..."
    
    if ($ForDefaultUser) {
        Write-Log "Configuring for new user profiles..."
        $defaultUserHive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
        if (Test-Path $defaultUserHive) {
            reg load "HKU\DefaultUser" $defaultUserHive | Out-Null
            $taskbandPath = "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
            $startPath = "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            $explorerPath = "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer"
        } else {
            Write-Log "Error: Default user hive not found" -Level Error
            return
        }
    } else {
        $taskbandPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        $startPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    }

    @($taskbandPath, $startPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -Force | Out-Null
        }
    }

    Set-ItemProperty -Path $startPath -Name "Start_Layout" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $startPath -Name "Start_ShowClassicMode" -Value 1 -Type DWord -Force

    $taskbandSettings = @{
        "FavoritesChanges" = 20
        "FavoritesVersion" = 3
        "FavoritesRemovedChanges" = 1
    }

    foreach ($setting in $taskbandSettings.GetEnumerator()) {
        Set-ItemProperty -Path $taskbandPath -Name $setting.Key -Value $setting.Value -Type DWord -Force
    }

    Set-ItemProperty -Path $taskbandPath -Name "LayoutXMLLastModified" -Value ([byte[]]@(0,0,0,0,0,0,0,0)) -Type Binary -Force

    $favoritesResolve = @(
        0xac,0x05,0x00,0x00,0x4c,0x00,0x00,0x00,0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,
        0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x81,0x00,0x80,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    )
    Set-ItemProperty -Path $taskbandPath -Name "FavoritesResolve" -Value ([byte[]]$favoritesResolve) -Type Binary -Force

    $auxPinsPath = Join-Path $taskbandPath "AuxiliaryPins"
    if (-not (Test-Path $auxPinsPath)) {
        New-Item -Path $auxPinsPath -Force | Out-Null
    }

    $auxPinSettings = @{
        "MailPin" = 1
        "TFLPin" = 1
        "CopilotPWAPin" = 1
    }

    foreach ($pin in $auxPinSettings.GetEnumerator()) {
        Set-ItemProperty -Path $auxPinsPath -Name $pin.Key -Value $pin.Value -Type DWord -Force
    }

    Set-ItemProperty -Path $explorerPath -Name "ShowStoreAppsOnTaskbar" -Value 0 -Type DWord -Force

    if ($ForDefaultUser) {
        [gc]::Collect()
        reg unload "HKU\DefaultUser" | Out-Null
        Write-Log "Default user configuration complete"
    } else {
        Write-Log "Current user configuration complete"
        try {
            $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
            if ($explorerProcesses) {
                Write-Log "Restarting Explorer to apply taskbar changes..."
                Stop-Process -Name "explorer" -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
                Start-Process "explorer.exe"
                Start-Sleep -Seconds 2
                
                $explorerRestarted = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
                if (-not $explorerRestarted) {
                    Write-Log "Explorer did not restart automatically, starting manually..." -Level Warning
                    Start-Process "explorer.exe"
                }
            } else {
                Write-Log "Explorer not running (likely system context), changes will apply at next user logon"
            }
        } catch {
            Write-Log "Could not restart Explorer (may be running as SYSTEM): $_" -Level Warning
            Write-Log "Taskbar changes will apply at next user logon"
        }
    }
}

function Set-Win10StartLayout {
    Write-Log "Configuring Windows 10 Start Menu and Taskbar layout..."
    $layoutXml = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6">
        <start:Group Name="Productivity">
          <start:DesktopApplicationTile Size="1x1" Column="1" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Excel.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="1" Row="1" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="0" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Word.lnk" />
          <start:Tile Size="1x1" Column="3" Row="0" AppUserModelID="MSTeams_8wekyb3d8bbwe!MSTeams" />
          <start:DesktopApplicationTile Size="1x1" Column="0" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="3" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Firefox.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="4" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Zoom\Zoom Workplace.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Outlook (classic).lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="4" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\OneDrive for Business.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="2" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" />
        </start:Group>
        <start:Group Name="Admin Tools">
          <start:DesktopApplicationTile Size="1x1" Column="2" Row="1" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk" />
          <start:Tile Size="1x1" Column="4" Row="1" AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
          <start:DesktopApplicationTile Size="1x1" Column="0" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\7-Zip\7-Zip File Manager.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="1" Row="1" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\Run.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="4" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="3" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="2" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="0" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="3" Row="1" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\System Tools\Task Manager.lnk" />
          <start:DesktopApplicationTile Size="1x1" Column="1" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
  <CustomTaskbarLayoutCollection>
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>	  
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Word.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Excel.lnk" />
        <taskbar:UWA AppUserModelID="MSTeams_8wekyb3d8bbwe!MSTeams" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
    
    $layoutPath = Join-Path $env:SystemDrive "Windows\StartLayout.xml"
    Set-Content -Path $layoutPath -Value $layoutXml -Force
    
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "StartLayoutFile" -Value $layoutPath -Type ExpandString -Force
    Set-ItemProperty -Path $regPath -Name "LockedStartLayout" -Value 1 -Type DWord -Force
    
    Write-Log "Windows 10 Start Menu and Taskbar layout configured successfully"
}

function Set-Win11StartLayout {
    Write-Log "Configuring Windows 11 Start Menu and Taskbar layout..."
    
    $registryContent = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Start]
"ConfigureStartPins"="{\"pinnedList\":[{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Word.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Excel.lnk\"},{\"packagedAppId\":\"Microsoft.OutlookForWindows_8wekyb3d8bbwe!Microsoft.OutlookforWindows\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\OneDrive for Business.lnk\"},{\"packagedAppId\":\"MSTeams_8wekyb3d8bbwe!MSTeams\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Zoom\\\\Zoom Workplace.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Microsoft Edge.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Firefox.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Google Chrome.lnk\"},{\"desktopAppLink\":\"%APPDATA%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\This PC.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Notepad++.lnk\"},{\"packagedAppId\":\"Microsoft.ScreenSketch_8wekyb3d8bbwe!App\"}]}"
"ConfigureStartPins_ProviderSet"=dword:00000001
"ConfigureStartPins_WinningProvider"="B5292708-1619-419B-9923-E5D9F3925E71"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start]
"ConfigureStartPins"="{\"pinnedList\":[{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Word.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Excel.lnk\"},{\"packagedAppId\":\"Microsoft.OutlookForWindows_8wekyb3d8bbwe!Microsoft.OutlookforWindows\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\OneDrive for Business.lnk\"},{\"packagedAppId\":\"MSTeams_8wekyb3d8bbwe!MSTeams\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Zoom\\\\Zoom Workplace.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Microsoft Edge.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Firefox.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Google Chrome.lnk\"},{\"desktopAppLink\":\"%APPDATA%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\This PC.lnk\"},{\"desktopAppLink\":\"%ALLUSERSPROFILE%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Notepad++.lnk\"},{\"packagedAppId\":\"Microsoft.ScreenSketch_8wekyb3d8bbwe!App\"}]}"
"ConfigureStartPins_LastWrite"=dword:00000001

"@

    $regPath = Join-Path $script:tempDir "Win11StartLayout.reg"
    Set-Content -Path $regPath -Value $registryContent -Force
    
    Write-Log "Importing Windows 11 Start Menu registry settings..."
    Start-Process "reg.exe" -ArgumentList "import `"$regPath`"" -Wait -NoNewWindow
    
    Set-Win11TaskbarLayout
    
    Write-Log "Windows 11 Start Menu and Taskbar layout configured successfully"
}

function Configure-StartLayout {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [System.Version]$osInfo.Version
    $buildNumber = $osVersion.Build
    
    if ($buildNumber -ge 22000) {
        Write-Log "Detected Windows 11 (Build: $buildNumber), applying Windows 11 Start Menu and Taskbar layout..."
        Set-Win11StartLayout
    } else {
        Write-Log "Detected Windows 10 (Build: $buildNumber), applying Windows 10 Start Menu and Taskbar layout..."
        Set-Win10StartLayout
    }
}

function Get-WindowsBuildNumber {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [System.Version]$osInfo.Version
    return $osVersion.Build
}

function Remove-WindowsBloatware {
    param(
        [switch]$ForAllUsers
    )
    
    Write-Log "Removing Windows bloatware..."
    $buildNumber = Get-WindowsBuildNumber
    
    if ($buildNumber -ge 22000) {
        Write-Log "Detected Windows 11, removing Windows 11 specific bloatware..."
        $bloatwareApps = @(
            "Microsoft.BingNews"
            "Microsoft.BingSearch"
            "Microsoft.GamingApp"
            "Microsoft.PowerAutomateDesktop"
            "Microsoft.OutlookForWindows"
            "MicrosoftCorporationII.QuickAssist"
            
            "Microsoft.549981C3F5F10"
            "Microsoft.BingWeather"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.People"
            "Microsoft.WindowsFeedbackHub"
            "Microsoft.WindowsMaps"
            "Microsoft.Xbox.TCUI"
            "Microsoft.XboxApp"
            "Microsoft.XboxGameOverlay"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.XboxIdentityProvider"
            "Microsoft.XboxSpeechToTextOverlay"
            "Microsoft.YourPhone"
            "Microsoft.ZuneMusic"
            "Microsoft.ZuneVideo"
            "microsoft.windowscommunicationsapps" # Mail and Calendar
            "Microsoft.MixedReality.Portal"
            "Microsoft.SkypeApp"
            "Microsoft.WindowsCamera"
            "Microsoft.WindowsSoundRecorder"
            "Microsoft.WindowsAlarms"
        )
    } else {
        Write-Log "Detected Windows 10, removing Windows 10 specific bloatware..."
        $bloatwareApps = @(
           
            "Microsoft.Microsoft3DViewer"
            "Microsoft.Office.OneNote"
            
 
            "Microsoft.549981C3F5F10"
            "Microsoft.BingWeather"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.People"
            "Microsoft.WindowsFeedbackHub"
            "Microsoft.WindowsMaps"
            "Microsoft.Xbox.TCUI"
            "Microsoft.XboxApp"
            "Microsoft.XboxGameOverlay"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.XboxIdentityProvider"
            "Microsoft.XboxSpeechToTextOverlay"
            "Microsoft.YourPhone"
            "Microsoft.ZuneMusic"
            "Microsoft.ZuneVideo"
            "microsoft.windowscommunicationsapps"
            "Microsoft.MixedReality.Portal"
            "Microsoft.SkypeApp"
            "Microsoft.WindowsCamera"
            "Microsoft.WindowsSoundRecorder"
            "Microsoft.WindowsAlarms"
        )
    }

 
    foreach ($app in $bloatwareApps) {
        try {
            Write-Log "Removing $app..."
            Get-AppxPackage -Name $app -AllUsers:$ForAllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            
            if ($ForAllUsers) {
             
                Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$app*" } | 
                ForEach-Object { 
                    Write-Log "Removing provisioned package $($_.PackageName)..."
                    Remove-AppxProvisionedPackage -PackageName $_.PackageName -Online -AllUsers -ErrorAction SilentlyContinue | Out-Null 
                }
            }
        }
        catch {
            Write-Log ("Error removing " + $app + ": " + $_.Exception.Message) -Level Error
        }
    }
   
    if ($ForAllUsers) {
        Write-Log "Removing personal OneDrive..."        
       
        Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | 
            Where-Object { $_.Path -notlike "*Microsoft OneDrive for Business*" -and $_.Path -notlike "*Microsoft Corporation\OneDrive for Business*" } | 
            Stop-Process -Force        

        $oneDrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        if (Test-Path $oneDrivePath) {
            Start-Process $oneDrivePath -ArgumentList "/uninstall" -Wait -NoNewWindow
        }        
   
        Remove-Item -Path "$env:ProgramFiles\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:ProgramFiles (x86)\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemDrive\Program Files\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Program Files (x86)\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        
        Write-Log "Removing OneDrive shortcuts..."
        $shortcutLocations = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
            [System.Environment]::GetFolderPath("Desktop"),
            "$env:PUBLIC\Desktop"
        )
        
        foreach ($location in $shortcutLocations) {
            Get-ChildItem -Path $location -Filter "OneDrive*.lnk" -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notlike "*for Business*" } | 
                ForEach-Object {
                    Write-Log "Removing shortcut: $($_.FullName)"
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                }
        }        
   
        Write-Log "Removing OneDrive from Quick Access..."
        $shell = New-Object -ComObject Shell.Application
        $quickAccess = $shell.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | 
            Where-Object { $_.Name -eq "OneDrive" -and $_.Name -notlike "*for Business*" }
        if ($quickAccess) {
            $quickAccess.InvokeVerb("removefromlist")
        }
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null        

        $personalOneDriveKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        if (Test-Path $personalOneDriveKey) {
            Remove-Item -Path $personalOneDriveKey -Force -Recurse
        }
        
        Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -Recurse -ErrorAction SilentlyContinue
        
        $businessOneDriveKey = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
        if (Test-Path $businessOneDriveKey) {
            Write-Log "Preserving OneDrive for Business settings..."
        }        

        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisablePersonalSync" -Type DWord -Value 1
        
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableBusinessSync" -Type DWord -Value 0
        
        Write-Log "Personal OneDrive removal completed"
    }
    if ($ForAllUsers) {
        Write-Log "Disabling consumer features..."
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "DisableSoftLanding" -Value 1 -Type DWord -Force
    }

    Write-Log "Bloatware removal complete"
}

function Show-InstalledUWPApps {
    param(
        [switch]$AllUsers
    )
    
    Write-Log "Listing installed UWP applications..."
    
    if ($AllUsers) {
        Write-Log "Provisioned packages (all users):"
        Get-AppxProvisionedPackage -Online | 
            Select-Object -Property DisplayName, PackageName |
            Sort-Object DisplayName |
            Format-Table -AutoSize
    }
    
    Write-Log "Installed packages (current user):"
    Get-AppxPackage -AllUsers:$AllUsers | 
        Select-Object -Property Name, PackageFullName |
        Sort-Object Name |
        Format-Table -AutoSize
}

Write-Log "========================================" 
Write-Log "Lab Computer Configuration Script Started"
Write-Log "========================================"

Write-Log "Performing pre-flight checks..."

if (-not (Test-NetworkConnectivity)) {
    Write-Log "Network connectivity check failed. Cannot proceed with installation." -Level Error
    Add-InstallationResult -Software "Pre-flight Check: Network" -Success $false -Message "No network connectivity"
    exit 1
}
Add-InstallationResult -Software "Pre-flight Check: Network" -Success $true -Message "Network connectivity confirmed"

if (-not (Test-DiskSpace -RequiredSpaceGB 20)) {
    Write-Log "Insufficient disk space. Cannot proceed with installation." -Level Error
    Add-InstallationResult -Software "Pre-flight Check: Disk Space" -Success $false -Message "Insufficient disk space"
    exit 1
}
Add-InstallationResult -Software "Pre-flight Check: Disk Space" -Success $true -Message "Sufficient disk space available"

$result = Set-PowerShellExecutionPolicy
Add-InstallationResult -Software "PowerShell Execution Policy" -Success $result -Message "Set to RemoteSigned"

$result = Set-TimeZoneEST
Add-InstallationResult -Software "Time Zone Configuration" -Success $result -Message "Set to Eastern Standard Time (New York)"

$result = Set-WindowsUpdateSettings
Add-InstallationResult -Software "Windows Update Configuration" -Success $result -Message "Auto download and notify"

$isDomainJoined = Test-DomainMembership
Add-InstallationResult -Software "Domain Membership Check" -Success $true -Message $(if ($isDomainJoined) { "Domain-joined" } else { "Workgroup" })

if (-not $isDomainJoined) {
    Write-Log "Computer is not domain-joined, creating local 'Client' user account..."
    $result = New-ClientLocalUser
    Add-InstallationResult -Software "Local User 'Client' Creation" -Success $result -Message $(if ($result) { "User created with password" } else { "User creation failed" })
} else {
    Write-Log "Computer is domain-joined, skipping local user creation"
    Add-InstallationResult -Software "Local User 'Client' Creation" -Success $true -Message "Skipped (domain-joined)"
}

$installationSuccess = $true
$totalSteps = 14
$currentStep = 1

Write-Log "Starting software installation..."

Write-Log "Installing Chrome..."
$result = Install-Chrome
Add-InstallationResult -Software "Google Chrome" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing Teams..."
$result = Install-Teams
Add-InstallationResult -Software "Microsoft Teams" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing Zoom..."
$result = Install-Zoom
Add-InstallationResult -Software "Zoom" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing Adobe Reader..."
$result = Install-AdobeReader
Add-InstallationResult -Software "Adobe Acrobat Reader DC" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing Java..."
$result = Install-Java
Add-InstallationResult -Software "Java Runtime Environment" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing Firefox..."
$result = Install-Firefox
Add-InstallationResult -Software "Mozilla Firefox" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing 7-Zip..."
$result = Install-7Zip
Add-InstallationResult -Software "7-Zip" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing Notepad++..."
$result = Install-NotepadPlusPlus
Add-InstallationResult -Software "Notepad++" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Installing VLC Media Player..."
$result = Install-VLC
Add-InstallationResult -Software "VLC Media Player" -Success $result -Message $(if ($result) { "Successfully installed" } else { "Installation failed" })
$installationSuccess = $installationSuccess -and $result
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Configuring Start Menu and Taskbar layout..."
Configure-StartLayout
Add-InstallationResult -Software "Start Menu & Taskbar Layout" -Success $true -Message "Layout configured"
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Log "Removing Windows bloatware..."
Remove-WindowsBloatware -ForAllUsers
Add-InstallationResult -Software "Bloatware Removal" -Success $true -Message "Bloatware removed"
Show-InstallProgress -Activity "Overall Installation Progress" -TotalSteps $totalSteps -CurrentStep $currentStep
$currentStep++

Write-Progress -Activity "Overall Installation Progress" -Completed

Write-Log "Installation and configuration process completed!"

Write-Log "Generating installation report..."
New-HTMLReport

# Display summary
Write-Log "========================================" 
Write-Log "INSTALLATION SUMMARY"
Write-Log "========================================"

$successCount = ($script:installationResults | Where-Object { $_.Success -eq $true }).Count
$failCount = ($script:installationResults | Where-Object { $_.Success -eq $false }).Count
$totalCount = $script:installationResults.Count

Write-Log "Total Items: $totalCount"
Write-Log "Successful: $successCount"
Write-Log "Failed: $failCount"

if ($failCount -gt 0) {
    Write-Log ""
    Write-Log "Failed installations:" -Level Error
    $script:installationResults | Where-Object { $_.Success -eq $false } | ForEach-Object {
        Write-Log "  - $($_.Software): $($_.Message)" -Level Error
    }
}

Write-Log ""
Write-Log "Log file: $logFile"
Write-Log "HTML Report: $htmlReportFile"

Write-Log "Cleaning up downloaded files..."
if (Test-Path $script:tempDir) {
    Remove-Item -Path $script:tempDir -Recurse -Force
    Write-Log "Temporary files cleaned up successfully"
}

$pendingReboot = $false
try {
    $cbsRebootPending = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
    $wuRebootPending = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
    
    if ($cbsRebootPending -or $wuRebootPending) {
        $pendingReboot = $true
    }
} catch {
    Write-Log "Error checking for pending reboot: $_" -Level Warning
}

Write-Log ""
Write-Log "========================================"
Write-Log "Script execution completed!"
Write-Log "========================================"

$needsLogoff = $false
$buildNumber = Get-WindowsBuildNumber

if ($buildNumber -ge 22000) {
    $needsLogoff = $true
    Write-Log "Windows 11 detected - user logoff required to apply Start Menu and Taskbar changes"
}

{{ ... }}
    Write-Log ""
    Write-Log "*** RESTART REQUIRED ***" -Level Warning
    Write-Log "Some installations require a system restart to complete." -Level Warning
    Write-Log "Initiating automatic restart in 60 seconds..."
    Write-Log ""
    
    Start-Sleep -Seconds 10
    shutdown /r /t 60 /c "Lab Computer Configuration: Restart required to complete installation. Save your work!"
    
} elseif ($needsLogoff) {
    Write-Log ""
    Write-Log "*** USER LOGOFF REQUIRED ***" -Level Warning
    Write-Log "Start Menu and Taskbar changes require user logoff to apply." -Level Warning
    Write-Log "Initiating automatic logoff in 60 seconds..."
    Write-Log ""
    
    Start-Sleep -Seconds 10
    
    try {
        shutdown /l /t 60 /c "Lab Computer Configuration: Logging off to apply configuration changes. Save your work!"
        Write-Log "Logoff scheduled in 60 seconds"
    } catch {
        Write-Log "Could not schedule automatic logoff: $_" -Level Warning
        Write-Log "Please log off manually to apply Start Menu and Taskbar changes"
    }
}

try {
    if ($needsLogoff -or $pendingReboot) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        if ($desktopPath) {
            Copy-Item $htmlReportFile "$desktopPath\InstallationReport.html" -Force -ErrorAction SilentlyContinue
            Write-Log "Installation report copied to Desktop for review after logon"
        }
    }
    Start-Process $htmlReportFile -ErrorAction SilentlyContinue
} catch {
    Write-Log "Could not open HTML report automatically. Please open it manually: $htmlReportFile"
}