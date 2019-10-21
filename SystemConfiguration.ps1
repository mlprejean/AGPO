### Variables
$TimeStamp = Get-Date
$ScriptDir = "C:\Temp\SystemConfiguration\"
$GPODir = $ScriptDir + "Extracted\SystemConfiguration\GPO_Backup"
$ZIPFileName = 'SystemConfiguration.ZIP'
# Create script Folder
New-Item -Path $ScriptDir -ItemType Directory -ErrorAction SilentlyContinue
# Create Folder for logging
$LogDir = $ScriptDir + "\Log\"
$LogFile = $LogDir +  "Script.log"
New-Item -Path $LogDir -ItemType Directory -ErrorAction SilentlyContinue

# Functions
Function LogWrite {
    Param ([string]$logstring)
    Add-content $Logfile -value $logstring 
}

# Starting script
$TimeStamp = Get-Date
LogWrite "$TimeStamp - Script started"

# Search for the latest ZIP File
$customScriptPath = 'C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.9\Downloads' 
$ZIPFile = Get-Childitem –Path $customScriptPath -Include $ZIPFileName -Recurse | Select-Object -Last 1
Copy-Item $ZIPFile $ScriptDir

### Proces the ZIP file
$ZIPSrc = $ScriptDir + $ZIPFileName
$ZIPDst = $ScriptDir + 'Extracted\'
New-Item -Path $ZIPDst -ItemType Directory -ErrorAction SilentlyContinue
$TimeStamp = Get-Date
LogWrite "$timeStamp - Zip file = $ZIPFile"
LogWrite "$TimeStamp - ZIP Source is:$ZIPSrc"
LogWrite "$TimeStamp - ZIP Destination is:$ZIPDst"
# Unzip the file 
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip {
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
Unzip "$ZIPSrc" "$ZIPDst"

### Get OS Version
$OSVersion = (gwmi win32_operatingsystem).caption

if ($OSVersion -eq "Microsoft Windows Server 2012 R2 Datacenter") {
    $TimeStamp = Get-Date
    Write-Host "$TimeStamp OS Version is Microsoft Windows Server 2012 R2 Datacenter"
    LogWrite "$TimeStamp OS Version is Microsoft Windows Server 2012 R2 Datacenter"

   
## Changing Reg Keys Below

    ### MSS Settings - Eventlog Features Overwite
    $TimeStamp = Get-Date
    LogWrite "$Features Overwrite Settings"
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $RegName = "FeatureSettingsOverride"
    $RegValue = "72"
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

     ### MSS Settings - Eventlog Features Overwite
    $TimeStamp = Get-Date
    LogWrite "$Features Overwrite Settings Mask"
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $RegName = "FeatureSettingsOverrideMask"
    $RegValue = "3"
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog iexplore
    $TimeStamp = Get-Date
    LogWrite "$iexplore"
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX"
    $RegName = "iexplore.exe"
    $RegValue = "1"
    #Reg Key does not yet exist
    New-Item -Path $RegPath -Force
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog iexplore
    $TimeStamp = Get-Date
    LogWrite "$iexplore"
    $RegPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX"
    $RegName = "iexplore.exe"
    $RegValue = "1"
    #Reg Key does not yet exist
    New-Item -Path $RegPath -Force
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog iexplore
    $TimeStamp = Get-Date
    LogWrite "$iexplore"
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
    $RegName = "iexplore.exe"
    $RegValue = "1"
    #Reg Key does not yet exist
    New-Item -Path $RegPath -Force
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog iexplore
    $TimeStamp = Get-Date
    LogWrite "$iexplore"
    $RegPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
    $RegName = "iexplore.exe"
    $RegValue = "1"
    #Reg Key does not yet exist
    New-Item -Path $RegPath -Force
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog Allow Encryption Oracle
    $TimeStamp = Get-Date
    LogWrite "$Allow Encryption Oracle"
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
    $RegName = "AllowEncryptionOracle"
    $RegValue = "1"
    #Reg Key does not yet exist
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP" -Name "Parameters" -Force
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog Allow Encryption Oracle
    $TimeStamp = Get-Date
    LogWrite "$Allow Encryption Oracle"
    $RegPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
    $RegName = "AllowEncryptionOracle"
    $RegValue = "1"
    #Reg Key does not yet exist
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP" -Name "Parameters" -Force
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force

    ### MSS Settings - Eventlog Defalut Secure Protocols
    $TimeStamp = Get-Date
    LogWrite "$Defalut Secure Protocols"
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
    $RegName = "DefaultSecureProtocols"
    $RegValue = "2560"
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force
    
    ### MSS Settings - Eventlog Defalut Secure Protocols
    $TimeStamp = Get-Date
    LogWrite "$Defalut Secure Protocols"
    $RegPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
    $RegName = "DefaultSecureProtocols"
    $RegValue = "2560"
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force
      
    ### MSS Settings - Eventlog Use Logon Credential
    $TimeStamp = Get-Date
    LogWrite "$Use Logon Credential"
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"
    $RegName = "UseLogonCredential"
    $RegValue = "0"
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType "DWord" -Force


    ### Restore GPO Backup with OS vulnerability fixes
    $TimeStamp = Get-Date
    LogWrite "$TimeStamp Started with GPO Restore"
    $LGPOCMD = $ZIPDst + "SystemConfiguration\LGPO\LGPO.exe" 
    $GPOPath = $GPODir + "\WS-2012R2"
    $ARG = "/g", $GPOPath
    Start-Process -FilePath $LGPOCMD -ArgumentList $ARG

}
elseif ($OSVersion -eq "Microsoft Windows Server 2016 Datacenter") {
    $TimeStamp = Get-Date
    Write-Host "$TimeStamp OS Version is Microsoft Windows Server 2016 Datacenter"
    LogWrite "$TimeStamp OS Version is Microsoft Windows Server 2016 Datacenter"

    ### Disable SMBv1
    $TimeStamp = Get-Date
    LogWrite "$TimeStamp Disable SMBv10"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    ### Disable Windows Search Service
    $TimeStamp = Get-Date
    LogWrite "$TimeStamp Disable Windows Search Service"
    $Service = Get-Service -Name 'WSearch'
    if ($Service.Status -eq 'Running') {
        $Service | Stop-Service -Force
        $Service | Set-Service -StartupType Disable
        LogWrite "$TimeStamp Disabled Windows Search Service and set StartupType Disable"
    }
    else {
        LogWrite "$TimeStamp Windows Search Service was not running"   
    }
  
    ### Enable Windows Error Reporting
    $TimeStamp = Get-Date
    LogWrite "$TimeStamp Enable Windows Error Reporting"
    $ErrorReport = Get-WindowsErrorReporting
    if ($ErrorReport -eq 'Enabled') {
        LogWrite "$TimeStamp Windows Error Reporting is already enabled"
    }
    else {
        Enable-WindowsErrorReporting
        LogWrite "$TimeStamp Windows Error Reporting will be enabled"   
    }
    ### Restore GPO Backup with OS vulnerability fixes
    $TimeStamp = Get-Date
    LogWrite "$TimeStamp Started with GPO Restore"
    $LGPOCMD = $ZIPDst + "SystemConfiguration\LGPO\LGPO.exe" 
    $GPOPath = $GPODir + "\WS-2016"
    $ARG = "/g", $GPOPath
    Start-Process -FilePath $LGPOCMD -ArgumentList $ARG
}
