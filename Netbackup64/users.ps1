
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


 If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"

$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments

break
}

Set-Ntlm