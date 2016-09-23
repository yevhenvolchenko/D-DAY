
#Yevgen Volchenko
#eu9591

###########
#Hardening#
###########
function Set-Admins
     {
        param([Parameter(Mandatory=$true)] $password)
      
        $adsi = [adsi]"WinNT://$env:Computername"
        $evryadm = $adsi.Children | where {$_.Name -eq "evryadm"}
        if (!$evryadm)
        {
            $evryAdm = $adsi.create('User','evryadm')
            $bSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($password)
            $_password = [system.runtime.interopservices.marshal]::PtrToStringAuto($BSTR)
            $evryAdm.SetPassword(($_password))
            $evryAdm.SetInfo()
            $evryAdm.Description = "Evry service account, do not delete"
            $evryAdm.UserFlags.Value = $evryAdm.UserFlags.Value -bor 0x10000 #Set "Account never expires" flag
            $evryAdm.SetInfo()
            $adsi.Children | where {$_.Name -eq "Administrators"} | foreach {$_.psbase.Invoke(“Add”,$evryAdm.path)}
            Write-Host "Evryadm created successfully" -ForegroundColor Cyan
        }
        else
        {
             Write-Host "evryadm already exist" -ForegroundColor Red
        }



        $guest = $adsi.Children | where {$_.Name -eq "Guest"}
        $administrator = $adsi.Children | where {$_.Name -eq "Administrator"}

        if ($guest)
        {
           $guest.UserFlags.Value = $guest.UserFlags.Value -bor 0x2  #Set "Account is disabled" flag
           $guest.psbase.Rename("Visitor")
           $guest.SetInfo()
           Write-Host "Guest account Disabled" -ForegroundColor Cyan
        }
        else
        {
            Write-Host "Guest account is not present in the system" -ForegroundColor Red
        }

        if ($administrator)
        {
           $ass = Add-Type -AssemblyName System.Web
           $passadm = [System.Web.Security.Membership]::GeneratePassword(18,2)
           $passadm = ConvertTo-SecureString $passadm -AsPlainText -Force
           $_bSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($passadm)
           $_passadm = [system.runtime.interopservices.marshal]::PtrToStringAuto($_bSTR)
           $administrator.SetPassword(($_passadm))
           $administrator.SetInfo()
           $administrator.UserFlags.Value = $administrator.UserFlags.Value -bor 0x2  #Set "Account is disabled" flag
           $administrator.psbase.Rename("Chief")
           $administrator.SetInfo()
           Write-Host "Administrator account Disabled" -ForegroundColor Cyan
        }
        else
        {
            Write-Host "Administrator account is not present in the system" -ForegroundColor Red
        }

        #Read-Host -Prompt "Press any key to continue..."

    }

function Set-LocalSecurytipolicy
{
$SecTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = "Administrators"
SeRemoteInteractiveLogonRight = "Administrators","Remote Desktop Users"
"@

$SecTemplateFile = [System.IO.Path]::GetTempFileName()


Write-Host "Import new settings to Local Security Policy" -ForegroundColor DarkCyan
$SecTemplate | Set-Content -Path $SecTemplateFile -Encoding Unicode -Force

Push-Location (Split-Path $SecTemplateFile)

try {
    secedit.exe /configure /db "secedit.sdb" /cfg "$($SecTemplateFile)"
} finally {
    Pop-Location
}

Write-Host "LocalSecurytiPolicy set" -ForegroundColor Cyan 
}

function Install-Sysmon 
{
    param ([Parameter(Mandatory=$true)] [String]$path)
    
    
    $SysmonConfig = "Sysmon.exe" 
    $arg1 = "-accepteula"
    $arg2 = "-i sysmon_conf.xml"

    $scriptpath = Split-Path $path
    $scriptpath = $scriptpath + "\sysmon"
    Push-Location $scriptpath
    [Environment]::CurrentDirectory = $PWD
    try{
        start-process $SysmonConfig  -argumentlist $arg1,$arg2 -wait -Verb runAs
        Write-Host "Sysmon installed" -ForegroundColor Cyan
        }
    catch{
        Write-Host "Sysmon installaton failed" -ForegroundColor Red
 
    }
    finally{
        Pop-Location
        [Environment]::CurrentDirectory = $PWD  
        }

 }


function Set-NTLM 
{

    $ntlm = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication
    if ($ntlm) {
        $ntlm.UserAuthentication = 1
    }
    else
    {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -PropertyType DWord -Value 1
    }

 }


 function Set-Logsize{


 $logList = @(Get-EventLog -list)
 foreach ($logName in $logList)
 {
     if ($logName.logdisplayname -eq "System")
     {
         Select -ExpandProperty Maximumkilobytes
         if ($LogSize -lt 40384)
         {
             limit-eventLog -logname System -MaximumSize 40384KB
         }
     }
     elseif ($logName.logdisplayname -eq "Application")
     {
         Select -ExpandProperty Maximumkilobytes
         if ($LogSize -lt 40384)
         {
             limit-eventLog -logname Application -MaximumSize 40384KB
         }
     }
     elseif ($logName.logdisplayname -eq "Security")
     {
         Select -ExpandProperty Maximumkilobytes
         if ($LogSize -lt 40384)
         {
             limit-eventLog -logname Security -MaximumSize 40384KB
         }
     }
 }
}


function Delete-213.153.99Routes{

$regex = [regex] "\b213.153.99.\d{1,3}\b"
$ro = route print | findstr 213.153.99.
if ($ro){
        $regex.Matches($ro) | % {Start-Process -FilePath route -ArgumentList "DELETE", $_.value -Verb RunAs
                                 Write-Host $_.value" route deleted" -ForegroundColor Cyan}
    }
    else
    {
        Write-Host "No 213.153.99.xxx route found" -ForegroundColor Cyan
    }
}




If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"

$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments

break
}

$password = Read-Host -Prompt "Enter properly generated password for evryadm" -AsSecureString
Set-Admins $password
Set-LocalSecurytipolicy
Install-Sysmon $MyInvocation.MyCommand.Path
Set-NTLM
Set-Logsize
Delete-213.153.99Routes

# Synchronize system clocks for standalone (workgroup) hosts
if ((gwmi win32_computersystem).partofdomain -eq $false) {
    Start-Process -FilePath w32tm -ArgumentList /config , /syncfromflags:manual, /manualpeerlist:213.153.104.1 -Wait -Verb RunAs
    write-host -fore red "Ooops, workgroup!"
}



################################
##Old backup systems uninstall##
################################


Get-WmiObject -Class Win32_Service | where {$_.name -match "^TSM" -and $_.name -match "Acceptor$"} | % {$_.StopService()
                                                                                                        $_.Delete()} | Out-Null
Get-WmiObject -Class Win32_Service | where {$_.name -match "^TSM" -and $_.name -match "Scheduler$"} | % {$_.StopService()
                                                                                                         $_.delete()}  | Out-Null
Get-WmiObject -Class Win32_Service | where {$_.name -match "^TSM" -and $_.name -match "Agent$"} | % {$_.StopService()
                                                                                                     $_.delete()}  | Out-Null

################### ENTER PROGRAMS NAMES TO UNINSTALL THEM. NOTE, THAT YOU SHOULD FOLLOW REGULAR EXPRESSION SYNTAX####
$uninstallPrograms = “(Tivoli Storage Manager|Data Protector|NetWorker)"
######################################################################################################################


$uninstallProgramsObj = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
                                        Get-ItemProperty |
                                            Where-Object {($_.DisplayName -MATCH $uninstallPrograms )}


Foreach ($obj in $uninstallProgramsObj)
    {
    if ($obj.UninstallString  -match "MsiExec")
        {
        Write-Host "Uninstalling" $obj.displayname"..."  -ForegroundColor Cyan
        $obj.UninstallString  -match "([{}][0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}[}])" | Out-Null
              
        & cmd /c msiexec.exe /x ''$Matches[1].ToString()''  /norestart /q
        Write-Host "Uninstall complete"  -ForegroundColor Cyan
        }
    else
        {
        Write-Host "Uninstall via MSIEXEC not supported, please uninstall "$obj.displayname" manually"  -BackgroundColor Red
        }
    }  

 
##################################
###NetBackup 7.6.1 installation###
################################## 
 
 
    
$scriptpath = Split-Path $MyInvocation.MyCommand.Path
Switch ([intptr]::Size) {

    4 {$scriptpath = $scriptpath + "\Netbackup86"}

    8 {$scriptpath = $scriptpath + "\Netbackup64"}      

}

Push-Location $scriptpath
[Environment]::CurrentDirectory = $PWD
try{
    Start-Process silentclient_fqdn.cmd -Wait -NoNewWindow
    }
finally{
    Pop-Location
    [Environment]::CurrentDirectory = $PWD  
    }

                 
          


################################
#############VSSFIX#############
################################


#Erik Nordstrцm
#Eu9512



    #root path for uninstall strings
    $uninstallpath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\uninstall"
    #loop all items...
    $items = Get-childItem $uninstallpath
    foreach ($item in $items){$child = $item.PSChildName;

    $path = "$uninstallpath\$child"
    $Object = Get-ItemProperty $path -ErrorAction SilentlyContinue 

    #Uninstall VMware Tools VSS Provider if VMware
    if ((Get-WmiObject Win32_Computersystem).Manufacturer -eq "VMware, Inc.")
    {
        if ($Object.DisplayName -eq "VMware Tools")
            {
            Write-Host "Uninstalling VMware Tools VSS Provider if found" -ForegroundColor Cyan
            $UninstallGUID_VMware = $Object.PSchildName
            cmd /c MsiExec.exe /i $UninstallGUID_VMware remove=VSS /passive /norestart
            }
    }}


Start-Sleep 2
# Install Symantec VSS provider for vSphere if VMware   
    if ((Get-WmiObject Win32_Computersystem).Manufacturer -eq "VMware, Inc.")
    {
        If ((Test-Path -Path ${env:ProgramFiles}'\VERITAS\NetBackup\bin\goodies\SYMCVSSProviderx86.msi') -eq $true)
            {
            Write-Host "Installing Symantec VSS Provider for vSphere" -ForegroundColor Cyan
            & ${env:ProgramFiles}'\VERITAS\NetBackup\bin\goodies\SYMCVSSProviderx86.msi'
            }
    ElseIf ((Test-Path $env:ProgramFiles'\VERITAS\NetBackup\bin\goodies\SYMCVSSProviderx64.msi') -eq $true)
            {
            Write-Host "Installing Symantec VSS Provider" -ForegroundColor Cyan
            & $env:ProgramFiles'\VERITAS\NetBackup\bin\goodies\SYMCVSSProviderx64.msi'
            }
    Else
            {
            Write-Host "Netbackup Client not found! Symantec VSS Provider will not be installed." -ForegroundColor Red
            }
    }
Write-Host "Installing task completed." -ForegroundColor Magenta
Start-Sleep 2

Read-Host









