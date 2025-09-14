# --- Language-independent nano11 Builder Script ---
# Version 3.2 - Final, complete script with universal language compatibility and English comments

# 1. Check and adjust Execution Policy (accepts 'yes')
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Your current PowerShell Execution Policy is 'Restricted', which prevents scripts from running."
    Write-Host "Do you want to change it to 'RemoteSigned'? (yes/no)"
    $response = Read-Host
    if ($response.ToLower() -eq 'yes') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
        Write-Host "Execution Policy has been changed."
    } else {
        Write-Host "The script cannot be run without changing the execution policy. Exiting..."
        exit
    }
}

# 2. Check for Admin rights and restart the script as admin if required
# NOTE: The method for checking the admin role is language-independent.
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
if (-not $myWindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting the script with administrator rights in a new window..."
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $newProcess.Arguments = "-File `"$($myInvocation.MyCommand.Definition)`""
    $newProcess.Verb = "runas"
    [System.Diagnostics.Process]::Start($newProcess)
    exit
}

# 3. Get the Administrators group in a language-independent way via its well-known SID
# This works on any Windows system, regardless of the configured language.
$adminGroupSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$adminGroup = $adminGroupSid.Translate([System.Security.Principal.NTAccount])

# --- Function to take ownership (language-independent) ---
# This function replaces all calls to takeown.exe and icacls.exe
function Set-ItemOwnershipAndAccess {
    param(
        [string]$Path,
        [switch]$Recurse
    )
    if (-not (Test-Path $Path)) {
        Write-Warning "Path not found: $Path"
        return
    }
    Write-Host "Taking ownership and setting permissions for: $Path"
    try {
        $acl = Get-Acl $Path
        $acl.SetOwner($adminGroup)
        if ($Recurse) {
            # Rule for folders: Full control, inherited by all subfolders and files.
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, [System.Security.AccessControl.FileSystemRights]::FullControl, "ContainerInherit, ObjectInherit", "None", "Allow")
        } else {
            # Rule for single files (no inheritance)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, [System.Security.AccessControl.FileSystemRights]::FullControl, "Allow")
        }
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
        Write-Host "  - Success."
    } catch {
        Write-Error "Error processing '$Path': $_"
    }
}

Start-Transcript -Path "$PSScriptRoot\nano11.log"
# User prompt (accepts y/n)
Write-Host "Welcome to the nano11 Builder!"
Write-Host "This script generates a heavily reduced Windows 11 image. It's not intended for regular use as it cannot be serviced (no updates, languages, etc.)."
Write-Host "Do you want to continue? (y/n)"
$input = Read-Host

if ($input.ToLower() -eq 'y') {
    Write-Host "Off we go..."
    Start-Sleep -Seconds 3
    Clear-Host

    $mainOSDrive = $env:SystemDrive
    $ScratchDisk = $env:SystemDrive
    New-Item -ItemType Directory -Force -Path "$mainOSDrive\nano11\sources"
    $DriveLetter = Read-Host "Please enter the drive letter of the Windows 11 installation media"
    $DriveLetter = $DriveLetter + ":"

    if (-not (Test-Path "$DriveLetter\sources\install.wim")) {
        if (Test-Path "$DriveLetter\sources\install.esd") {
            Write-Host "install.esd found, converting to install.wim..."
            & 'dism' /English /Get-WimInfo /WimFile:"$DriveLetter\sources\install.esd"
            $index = Read-Host "Please enter the image index"
            Write-Host 'Converting install.esd to install.wim. This may take a while...'
            & 'dism' /English /Export-Image /SourceImageFile:"$DriveLetter\sources\install.esd" /SourceIndex:$index /DestinationImageFile:"$mainOSDrive\nano11\sources\install.wim" /Compress:max /CheckIntegrity
        } else {
            Write-Host "No Windows installation files found on the specified drive. Exiting."
            exit
        }
    } else {
        Write-Host "install.wim found."
    }

    Write-Host "Copying Windows image..."
    Copy-Item -Path "$DriveLetter\*" -Destination "$mainOSDrive\nano11" -Recurse -Force > $null
    Remove-Item "$mainOSDrive\nano11\sources\install.esd" -ErrorAction SilentlyContinue

    Write-Host "Getting image information:"
    $wimFilePath = "$mainOSDrive\nano11\sources\install.wim"
    & 'dism' /English /Get-WimInfo /WimFile:$wimFilePath
    $index = Read-Host "Please enter the image index"
    Write-Host "Mounting Windows image. This may take a while."
    
    Set-ItemOwnershipAndAccess -Path $wimFilePath
    try { Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction Stop } catch {}

    New-Item -ItemType Directory -Force -Path "$mainOSDrive\scratchdir"
    & dism /English /Mount-Image /ImageFile:$wimFilePath /Index:$index /MountDir:"$mainOSDrive\scratchdir"

    # --- Taking ownership with the language-independent function ---
    $scratchDir = "$mainOSDrive\scratchdir"
    $foldersToOwn = @("$scratchDir\Windows\System32\DriverStore\FileRepository", "$scratchDir\Windows\Fonts", "$scratchDir\Windows\Web", "$scratchDir\Windows\Help", "$scratchDir\Windows\Cursors", "$scratchDir\Program Files (x86)\Microsoft", "$scratchDir\Program Files\WindowsApps", "$scratchDir\Windows\System32\Microsoft-Edge-Webview", "$scratchDir\Windows\System32\Recovery", "$scratchDir\Windows\WinSxS", "$scratchDir\Windows\assembly", "$scratchDir\ProgramData\Microsoft\Windows Defender", "$scratchDir\Windows\System32\InputMethod", "$scratchDir\Windows\Speech", "$scratchDir\Windows\Temp")
    $filesToOwn = @("$scratchDir\Windows\System32\OneDriveSetup.exe")
    
    foreach ($folder in $foldersToOwn) { Set-ItemOwnershipAndAccess -Path $folder -Recurse }
    foreach ($file in $filesToOwn) { Set-ItemOwnershipAndAccess -Path $file }

    $imageIntl = & dism /English /Get-Intl "/Image:$scratchDir"
    $languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }
    if ($languageLine) { $languageCode = $Matches[1]; Write-Host "Default system UI language code: $languageCode" } else { Write-Host "Default system UI language code not found." }
    $imageInfo = & 'dism' /English /Get-WimInfo "/wimFile:$wimFilePath" "/index:$index"
    $lines = $imageInfo -split '\r?\n'
    foreach ($line in $lines) { if ($line -like '*Architecture : *') { $architecture = $line -replace 'Architecture : ',''; if ($architecture -eq 'x64') { $architecture = 'amd64' }; Write-Host "Architecture: $architecture"; break } }
    if (-not $architecture) { Write-Host "Architecture information not found." }
    
    Write-Host "Removing provisioned AppX packages (bloatware)..."
    $packagesToRemove = Get-AppxProvisionedPackage -Path $scratchDir | Where-Object { $_.PackageName -like '*Zune*' -or $_.PackageName -like '*Bing*' -or $_.PackageName -like '*Clipchamp*' -or $_.PackageName -like '*Gaming*' -or $_.PackageName -like '*People*' -or $_.PackageName -like '*PowerAutomate*' -or $_.PackageName -like '*Teams*' -or $_.PackageName -like '*Todos*' -or $_.PackageName -like '*YourPhone*' -or $_.PackageName -like '*SoundRecorder*' -or $_.PackageName -like '*Solitaire*' -or $_.PackageName -like '*FeedbackHub*' -or $_.PackageName -like '*Maps*' -or $_.PackageName -like '*OfficeHub*' -or $_.PackageName -like '*Help*' -or $_.PackageName -like '*Family*' -or $_.PackageName -like '*Alarms*' -or $_.PackageName -like '*CommunicationsApps*' -or $_.PackageName -like '*Copilot*' -or $_.PackageName -like '*CompatibilityEnhancements*' -or $_.PackageName -like '*AV1VideoExtension*' -or $_.PackageName -like '*AVCEncoderVideoExtension*' -or $_.PackageName -like '*HEIFImageExtension*' -or $_.PackageName -like '*HEVCVideoExtension*' -or $_.PackageName -like '*MicrosoftStickyNotes*' -or $_.PackageName -like '*OutlookForWindows*' -or $_.PackageName -like '*RawImageExtension*' -or $_.PackageName -like '*SecHealthUI*' -or $_.PackageName -like '*VP9VideoExtensions*' -or $_.PackageName -like '*WebpImageExtension*' -or $_.PackageName -like '*DevHome*' -or $_.PackageName -like '*Photos*' -or $_.PackageName -like '*Camera*' -or $_.PackageName -like '*QuickAssist*' -or $_.PackageName -like '*CoreAI*' -or $_.PackageName -like '*PeopleExperienceHost*' -or $_.PackageName -like '*PinningConfirmationDialog*' -or $_.PackageName -like '*SecureAssessmentBrowser*' -or $_.PackageName -like '*Paint*' -or $_.PackageName -like '*Notepad*' }
    foreach ($package in $packagesToRemove) { write-host "Removing: $($package.DisplayName)"; Remove-AppxProvisionedPackage -Path $scratchDir -PackageName $package.PackageName }

    Write-Host "Attempting to remove leftover WindowsApps folders..."
    foreach ($package in $packagesToRemove) { $folderPath = Join-Path "$scratchDir\Program Files\WindowsApps" $package.PackageName; if (Test-Path $folderPath) { Write-Host "Deleting folder: $($package.PackageName)"; Remove-Item $folderPath -Recurse -Force -ErrorAction SilentlyContinue } }

    Write-Host "Removing of system apps complete! Now proceeding to removal of system packages..."
    Start-Sleep -Seconds 1
    Clear-Host

    $packagePatterns = @( "Microsoft-Windows-InternetExplorer-Optional-Package~", "Microsoft-Windows-MediaPlayer-Package~", "Microsoft-Windows-WordPad-FoD-Package~", "Microsoft-Windows-StepsRecorder-Package~", "Microsoft-Windows-MSPaint-FoD-Package~", "Microsoft-Windows-SnippingTool-FoD-Package~", "Microsoft-Windows-TabletPCMath-Package~", "Microsoft-Windows-Xps-Xps-Viewer-Opt-Package~", "Microsoft-Windows-PowerShell-ISE-FOD-Package~", "OpenSSH-Client-Package~", "Microsoft-Windows-LanguageFeatures-Handwriting-$languageCode-Package~", "Microsoft-Windows-LanguageFeatures-OCR-$languageCode-Package~", "Microsoft-Windows-LanguageFeatures-Speech-$languageCode-Package~", "Microsoft-Windows-LanguageFeatures-TextToSpeech-$languageCode-Package~", "*IME-ja-jp*", "*IME-ko-kr*", "*IME-zh-cn*", "*IME-zh-tw*", "Windows-Defender-Client-Package~", "Microsoft-Windows-Search-Engine-Client-Package~", "Microsoft-Windows-Kernel-LA57-FoD-Package~", "Microsoft-Windows-Hello-Face-Package~", "Microsoft-Windows-Hello-BioEnrollment-Package~", "Microsoft-Windows-BitLocker-DriveEncryption-FVE-Package~", "Microsoft-Windows-TPM-WMI-Provider-Package~", "Microsoft-Windows-Narrator-App-Package~", "Microsoft-Windows-Magnifier-App-Package~", "Microsoft-Windows-Printing-PMCPPC-FoD-Package~", "Microsoft-Windows-WebcamExperience-Package~", "Microsoft-Media-MPEG2-Decoder-Package~", "Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package~" )
    $allPackages = & dism /English /image:$scratchDir /Get-Packages /Format:Table
    $allPackages = $allPackages -split "`n" | Select-Object -Skip 1
    foreach ($packagePattern in $packagePatterns) {
        $packagesToRemove = $allPackages | Where-Object { $_ -like "$packagePattern*" }
        foreach ($package in $packagesToRemove) {
            $packageIdentity = ($package -split "\s+")[0]
            Write-Host "Removing $packageIdentity..."
            & dism /English /image:$scratchDir /Remove-Package /PackageName:$packageIdentity
        }
    }
    
    Write-Host "Removing pre-compiled .NET assemblies (Native Images)..."
    Remove-Item -Path "$scratchDir\Windows\assembly\NativeImages_*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Performing aggressive manual file deletions..."
    $winDir = "$scratchDir\Windows"
    
    Write-Host "Slimming the DriverStore... (removing non-essential driver classes)"
    $driverRepo = Join-Path -Path $winDir -ChildPath "System32\DriverStore\FileRepository"
    $patternsToRemove = @('prn*', 'scan*', 'mfd*', 'wscsmd.inf*', 'tapdrv*', 'rdpbus.inf*', 'tdibth.inf*')
    # FIX: Use a robust deletion method for protected driver folders.
    $emptyDirForDrivers = Join-Path -Path $scratchDir -ChildPath "empty_drivers_delete"
    New-Item -Path $emptyDirForDrivers -ItemType Directory -Force | Out-Null
    Get-ChildItem -Path $driverRepo -Directory | ForEach-Object { 
        $driverFolder = $_
        foreach ($pattern in $patternsToRemove) { 
            if ($driverFolder.Name -like $pattern) { 
                Write-Host "Force-removing non-essential driver package: $($driverFolder.Name)"
                Set-ItemOwnershipAndAccess -Path $driverFolder.FullName -Recurse
                & robocopy $emptyDirForDrivers $driverFolder.FullName /MIR /R:0 /W:0 | Out-Null
                Remove-Item -Path $driverFolder.FullName -Recurse -Force
                break 
            } 
        } 
    }
    Remove-Item -Path $emptyDirForDrivers -Recurse -Force

    $fontsPath = Join-Path -Path $winDir -ChildPath "Fonts"
    if (Test-Path $fontsPath) {
        Write-Host "Slimming the Fonts folder..."
        # FIX: Take ownership of each font file individually before attempting to delete it.
        $fontsToRemoveExclude = Get-ChildItem -Path $fontsPath -Exclude "segoe*.*", "tahoma*.*", "marlett.ttf", "8541oem.fon", "segui*.*", "consol*.*", "lucon*.*", "calibri*.*", "arial*.*", "times*.*", "cou*.*", "8*.*"
        $fontsToRemoveInclude = Get-ChildItem -Path $fontsPath -Include "mingli*", "msjh*", "msyh*", "malgun*", "meiryo*", "yugoth*", "segoeuihistoric.ttf"
        ($fontsToRemoveExclude + $fontsToRemoveInclude) | ForEach-Object {
            Write-Host "  - Removing font: $($_.Name)"
            Set-ItemOwnershipAndAccess -Path $_.FullName
            Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Speech\Engines\TTS") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scratchDir\ProgramData\Microsoft\Windows Defender\Definition Updates" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\CHS" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\CHT" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\JPN" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\KOR" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scratchDir\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Web") -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Help") -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Cursors") -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Removing Edge, WinRE, and OneDrive..."
    Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\Edge*" -Recurse -Force -ErrorAction SilentlyContinue
    
    # FIX: Robustly delete Edge WebView components from WinSxS to prevent "Access Denied" errors.
    if ($architecture -eq 'amd64') {
        $folderPaths = Get-ChildItem -Path "$scratchDir\Windows\WinSxS" -Filter "amd64_microsoft-edge-webview_31bf3856ad364e35*" -Directory
        if ($folderPaths) {
            $emptyDirForEdge = Join-Path -Path $scratchDir -ChildPath "empty_edge_delete"
            New-Item -Path $emptyDirForEdge -ItemType Directory -Force | Out-Null
            foreach ($folder in $folderPaths) {
                Write-Host "Force-deleting Edge WebView folder: $($folder.FullName)"
                Set-ItemOwnershipAndAccess -Path $folder.FullName -Recurse
                & robocopy $emptyDirForEdge $folder.FullName /MIR /R:0 /W:0 | Out-Null
                Remove-Item -Path $folder.FullName -Recurse -Force
            }
            Remove-Item -Path $emptyDirForEdge -Recurse -Force
        }
    }
    
    Remove-Item -Path "$scratchDir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$scratchDir\Windows\System32\Recovery\winre.wim" -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -Path "$scratchDir\Windows\System32\Recovery\winre.wim" -ItemType File -Force | Out-Null
    Remove-Item -Path "$scratchDir\Windows\System32\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue
    
    & 'dism' /English "/image:$scratchDir" /Cleanup-Image /StartComponentCleanup /ResetBase

    Write-Host "Taking ownership of the WinSxS folder. This might take a while..."
    Set-ItemOwnershipAndAccess -Path "$scratchDir\Windows\WinSxS" -Recurse
    Write-host "Complete!"
    
    $folderPath = Join-Path -Path $mainOSDrive -ChildPath "\scratchdir\Windows\WinSxS_edit"
    $sourceDirectory = "$mainOSDrive\scratchdir\Windows\WinSxS"
    $destinationDirectory = "$mainOSDrive\scratchdir\Windows\WinSxS_edit"
    New-Item -Path $folderPath -ItemType Directory
    
    $dirsToCopy = @()
    if ($architecture -eq "amd64") {
        $dirsToCopy = @("x86_microsoft.windows.common-controls_6595b64144ccf1df_*", "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*", "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*", "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*", "x86_microsoft-windows-s..ngstack-onecorebase_31bf3856ad364e35_*", "x86_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*", "x86_microsoft-windows-servicingstack_31bf3856ad364e35_*", "x86_microsoft-windows-servicingstack-inetsrv_*", "x86_microsoft-windows-servicingstack-onecore_*", "amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*", "amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*", "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*", "amd64_microsoft.windows.common-controls_6595b64144ccf1df_*", "amd64_microsoft.windows.gdiplus_6595b64144ccf1df_*", "amd64_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*", "amd64_microsoft.windows.isolationautomation_6595b64144ccf1df_*", "amd64_microsoft-windows-s..stack-inetsrv-extra_31bf3856ad364e35_*", "amd64_microsoft-windows-s..stack-msg.resources_31bf3856ad364e35_*", "amd64_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*", "amd64_microsoft-windows-servicingstack_31bf3856ad364e35_*", "amd64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*", "amd64_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*", "amd64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*", "Catalogs", "FileMaps", "Fusion", "InstallTemp", "Manifests", "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*", "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*", "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*")
    } elseif ($architecture -eq "arm64") {
        $dirsToCopy = @("arm64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*", "Catalogs", "FileMaps", "Fusion", "InstallTemp", "Manifests", "SettingsManifests", "Temp", "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*", "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*", "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*", "x86_microsoft.windows.common-controls_6595b64144ccf1df_*", "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*", "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*", "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*", "arm_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*", "arm_microsoft.windows.common-controls_6595b64144ccf1df_*", "arm_microsoft.windows.gdiplus_6595b64144ccf1df_*", "arm_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*", "arm_microsoft.windows.isolationautomation_6595b64144ccf1df_*", "arm64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*", "arm64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*", "arm64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*", "arm64_microsoft.windows.common-controls_6595b64144ccf1df_*", "arm64_microsoft.windows.gdiplus_6595b64144ccf1df_*", "arm64_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*", "arm64_microsoft.windows.isolationautomation_6595b64144ccf1df_*", "arm64_microsoft-windows-servicing-adm_31bf3856ad364e35_*", "arm64_microsoft-windows-servicingcommon_31bf3856ad364e35_*", "arm64_microsoft-windows-servicing-onecore-uapi_31bf3856ad364e35_*", "arm64_microsoft-windows-servicingstack_31bf3856ad364e35_*", "arm64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*", "arm64_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*")
    }
    foreach ($dir in $dirsToCopy) { $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory; foreach ($sourceDir in $sourceDirs) { $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name; Write-Host "Copying $($sourceDir.FullName) to $destDir"; Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force } }

    Write-Host "Deleting WinSxS. This may take a while..."
    # FIX: Use robocopy to reliably delete the protected WinSxS folder contents.
    # Remove-Item can fail with "Access Denied" due to TrustedInstaller permissions.
    $emptyDir = Join-Path -Path $scratchDir -ChildPath "empty_temp_for_delete"
    New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null
    & robocopy $emptyDir "$mainOSDrive\scratchdir\Windows\WinSxS" /MIR /R:0 /W:0 | Out-Null
    Remove-Item -Path "$mainOSDrive\scratchdir\Windows\WinSxS" -Recurse -Force
    Remove-Item -Path $emptyDir -Recurse -Force

    Rename-Item -Path "$mainOSDrive\scratchdir\Windows\WinSxS_edit" -NewName "$mainOSDrive\scratchdir\Windows\WinSxS"
    Write-Host "Complete!"

    reg load HKLM\zCOMPONENTS "$scratchDir\Windows\System32\config\COMPONENTS" | Out-Null
    reg load HKLM\zDEFAULT "$scratchDir\Windows\System32\config\default" | Out-Null
    reg load HKLM\zNTUSER "$scratchDir\Users\Default\ntuser.dat" | Out-Null
    reg load HKLM\zSOFTWARE "$scratchDir\Windows\System32\config\SOFTWARE" | Out-Null
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
    
    Write-Host "Bypassing system requirements (on the system image):"
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t REG_DWORD /d 1 /f | Out-Null
    
    Write-Host "Applying various tweaks..."
    Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$scratchDir\Windows\System32\Sysprep\autounattend.xml" -Force | Out-Null
    & 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'ShippedWithReserves' /t REG_DWORD /d 0 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' /v 'PreventDeviceEncryption' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' /v 'ChatIcon' /t REG_DWORD /d 3 /f | Out-Null
    & 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f | Out-Null
    & 'reg' 'delete' "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f | Out-Null
    
    # ... Add more registry tweaks as needed ...
    
    Write-Host "Unmounting Registry..."
    reg unload HKLM\zCOMPONENTS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null

    Write-Host "Loading registry hives to remove services..."
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
    $servicesToRemove = @('Spooler', 'PrintNotify', 'Fax', 'RemoteRegistry', 'diagsvc', 'WerSvc', 'PcaSvc', 'MapsBroker', 'WalletService', 'BthAvctpSvc', 'BluetoothUserService', 'wuauserv', 'UsoSvc', 'WaaSMedicSvc')
    foreach ($service in $servicesToRemove) { Write-Host "Removing service: $service"; & 'reg' 'delete' "HKLM\zSYSTEM\ControlSet001\Services\$service" /f | Out-Null }
    reg unload HKLM\zSYSTEM | Out-Null
    
    Write-Host "Cleaning up and unmounting install.wim..."
    & 'dism' /English "/image:$scratchDir" /Cleanup-Image /StartComponentCleanup /ResetBase
    & 'dism' /English /Unmount-Image "/mountdir:$scratchDir" /commit
    & 'dism' /English /Export-Image "/SourceImageFile:$wimFilePath" "/SourceIndex:$index" "/DestinationImageFile:$mainOSDrive\nano11\sources\install2.wim" /compress:max
    Remove-Item -Path $wimFilePath -Force
    Rename-Item -Path "$mainOSDrive\nano11\sources\install2.wim" -NewName "install.wim"

    Write-Host "Shrinking boot.wim..."
    $bootWimPath = "$mainOSDrive\nano11\sources\boot.wim"
    Set-ItemOwnershipAndAccess -Path $bootWimPath
    try { Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction Stop } catch {}
    
    $newBootWimPath = "$mainOSDrive\nano11\sources\boot_new.wim"
    & 'dism' /English /Export-Image "/SourceImageFile:$bootWimPath" /SourceIndex:2 "/DestinationImageFile:$newBootWimPath"
    & 'dism' /English /Mount-Image "/imagefile:$newBootWimPath" /index:1 "/mountdir:$scratchDir"
    
    reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
    Write-Host "Bypassing system requirements (on boot image):"
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t REG_DWORD /d 1 /f | Out-Null
    & 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t REG_DWORD /d 1 /f | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
    
    & 'dism' /English /Unmount-Image "/mountdir:$scratchDir" /commit
    
    $finalBootWimPath = "$mainOSDrive\nano11\sources\boot_final.wim"
    Remove-Item -Path $bootWimPath -Force
    & 'dism' /English /Export-Image "/SourceImageFile:$newBootWimPath" /SourceIndex:1 "/DestinationImageFile:$finalBootWimPath" /compress:max
    Remove-Item -Path $newBootWimPath -Force
    Rename-Item -Path $finalBootWimPath -NewName "boot.wim"

    Clear-Host
    Write-Host "Exporting final image to highly compressed ESD format..."
    & dism /English /Export-Image /SourceImageFile:"$mainOSdrive\nano11\sources\install.wim" /SourceIndex:1 /DestinationImageFile:"$mainOSdrive\nano11\sources\install.esd" /Compress:recovery
    Remove-Item "$mainOSdrive\nano11\sources\install.wim" -Force -ErrorAction SilentlyContinue

    Write-Host "Performing final cleanup of installation folder root..."
    $isoRoot = "$mainOSDrive\nano11"
    $keepList = @("boot", "efi", "sources", "bootmgr", "bootmgr.efi", "setup.exe", "autounattend.xml")
    Get-ChildItem -Path $isoRoot | Where-Object { $_.Name -notin $keepList } | ForEach-Object { Write-Host "Removing non-essential file/folder from ISO root: $($_.Name)"; Remove-Item -Path $_.FullName -Recurse -Force }

    Write-Host "Creating bootable ISO image..."
    $OSCDIMG = "$PSScriptRoot\oscdimg.exe"
    if (-not (Test-Path $OSCDIMG)) { $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"; Invoke-WebRequest -Uri $url -OutFile $OSCDIMG }
    & "$OSCDIMG" -m -o -u2 -udfver102 "-bootdata:2#p0,e,b$mainOSdrive\nano11\boot\etfsboot.com#pEF,e,b$mainOSdrive\nano11\efi\microsoft\boot\efisys.bin" "$mainOSdrive\nano11" "$PSScriptRoot\nano11.iso"

    Write-Host "Creation complete! Your ISO is named nano11.iso"
    Read-Host "Press Enter to clean up and exit."
    & 'dism' /English /Unmount-Image /MountDir:$scratchDir /discard -ErrorAction SilentlyContinue
    Remove-Item -Path "$mainOSdrive\nano11" -Recurse -Force
    Remove-Item -Path "$mainOSdrive\scratchdir" -Recurse -Force
    Stop-Transcript
    exit
}
else {
    Write-Host "You cancelled the process. The script will now exit."
    exit
}

