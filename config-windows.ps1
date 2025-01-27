﻿Write-Host @"

Script de configuración automática de Windows 10

"@

# Load functions from library
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/RicardoVargasLeslie/ConfigMyWin10/master/functions.ps1"))

# Check if is running as administrator
If (Test-RunningAsAdministrator) {

    # Packages installation
    Install-Packages

    # Change user profiles location to a secondary disk drive if it's possible
    # https://www.nextofwindows.com/how-to-change-user-profile-default-location-in-windows-7
    Change-ProfilesLocation

    # Uninstall onedrive
    Uninstall-OneDrive

    # Change computer name and workgroup
    Write-Output "Changing computer name to RIC"
    Rename-Computer -NewName "RIC" -ErrorAction SilentlyContinue
   

    # Set timezone
    Write-Output "Setting timezone to GMT Standard Time"
    tzutil /s "GMT Standard Time"

} Else {

    Write-Host -ForegroundColor Red "Must be run as" (Get-AdminUsername)

 }
