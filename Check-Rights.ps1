$folder = "c:\temp\None"

$CP = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$UGM = @($CP.Identities.Groups | ?{$_.AccountDomainSid -ne $null})
$UGM = $UGM + $CP.Identities.User
if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$UGM = $UGM + ($CP.Identities.Groups | ?{$_.Value -eq "S-1-5-32-544"})}

$TPP = (Get-Acl $folder).Access

foreach ($P in $TPP.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]))
{
    foreach ($UP in $UGM){if($UP -eq $P){Write-Host "We got permissions here!";$TPP | ?{$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -match $P}}}
}

foreach($pu in (Get-LocalGroup Administrators | Get-LocalGroupMember).SID){if($pu -eq $CP.Identities.User -And !([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){Write-Host "You are an admin, but you are not elevated..."}}
