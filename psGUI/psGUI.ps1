Import-Module .\lib\pocModules -Prefix pm.

function helpMenu {
    Write-Host "###########################################################"
    Write-Host "## Quick and easy POC for GUIs with Visual Studio"
    Write-Host "##"
    Write-Host "## Run with right-click 'Run with PowerShell' || from shell"
    Write-Host "###########################################################"
}

## Say hi without a Class
pm.example

## Main -- Uncomment the below and -Credential to pass different credentials
#$ourCreds = Get-Credential
Start-Process powershell.exe ".\lib\gui\_poc.ps1"# -Credential $ourCreds
