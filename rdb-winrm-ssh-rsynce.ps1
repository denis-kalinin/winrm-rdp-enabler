Write-Output "Set all network interfaces as private network to enable winrm"
try{
  Set-NetConnectionProfile -NetworkCategory Private
}catch{
# Get network connections for Windows 7
$networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
$connections = $networkListManager.GetNetworkConnections()
# Set network location to Private for all networks
  $connections | % {$_.GetNetwork().SetCategory(1)}
}
Write-Output "Enabling WinRM remoting"
#skip restricting winrm on public networks
Enable-PSRemoting -Force
try{
  Set-WSManQuickConfig -SkipNetworkProfileCheck -Force
}catch{
  #win7
  netsh advfirewall set allprofiles state off
}
Write-Host "Allow WinRM over plain HTTP (AllowUnencrypted)"
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value "true" -Force
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
Write-Host "WinRM over HTTP is enabled"
Restart-Service winrm
$Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
#$Computer = [adsi]("WinNT://" + $env:COMPUTERNAME)
#$Computer = [ADSI]"WinNT://localhost,Computer"
$localAdminName = "LocalAdmin"
$localAdminPassword = "Password01"
Write-Output ("Creating " + $localAdminName + " user")
$LocalAdmin = $Computer.Create("User", $localAdminName)
$LocalAdmin.setPassword($localAdminPassword)
$LocalAdmin.UserFlags = 64 + 65536
$LocalAdmin.setInfo()
$LocalAdmin.FullName = "Local Admin for Powershell"
$LocalAdmin.setInfo()
$LocalAdmin.Description = "Defined by Powershell"
$LocalAdmin.setInfo()
$admGroupSID = get-wmiobject win32_group -Filter "SID=\'S-1-5-32-544\'"
$admGroupName = $admGroupSID.Name
Write-Output ("Adding " + $localAdminName + " to group " + $admGroupName)
$groupExpression = "WinNT://$Env:COMPUTERNAME/"+$admGroupSID.Name+",Group"
$AdminGroup = [ADSI]$groupExpression
$AdminGroup.Add("WinNT://LocalAdmin,User")
$AdminGroup.SetInfo()
$userProfilePath = [Environment]::GetFolderPath("MyDocuments")
#$userProfilePath = $env:userprofile
Write-Output "Userprofile" $userProfilePath "for user" $env:USERNAME
#$usersDir = (get-item $userProfilePath ).parent.FullName
$usersDir = (get-item $userProfilePath ).parent.parent.FullName
Write-Output "Users directory is" $usersDir
$cred_user = ".\"+$localAdminName
$cred_password = ConvertTo-SecureString -String $localAdminPassword -AsPlainText -Force
$UCredential = New-Object -typename System.Management.Automation.PSCredential -argumentlist $cred_user, $cred_password
#Start-Process powershell.exe -Credential $Credential -Verb RunAs -ArgumentList ("-file $args")
#Run simple console command as LocalAdmin to create Windows user's profile
[void](Invoke-Command -ComputerName "." -Credential $UCredential -Authentication Negotiate -Script {
  $proc = New-Object System.Diagnostics.ProcessStartInfo
  $proc.FileName = "cmd.exe"
  $proc.RedirectStandardError = $true
  $proc.RedirectStandardOutput = $true
  $proc.UseShellExecute = $false
  $proc.Arguments = "/c echo hello"
  $pr = New-Object System.Diagnostics.Process
  $pr.StartInfo = $proc
  $pr.Start() | Out-Null
  $pr.WaitForExit()
  $stdout = $pr.StandardOutput.ReadToEnd()
  $stderr = $pr.StandardError.ReadToEnd()
  Write-Host "HELLO OUT: $stdout"
  Write-Host "HELLO ERROR: $stderr"
  Write-Host "HELLO exit code: " + $pr.ExitCode
})
Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path  "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -name "UserAuthentication" -Value 1
$RDP = Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -ErrorAction Stop
$result = $RDP.SetAllowTsConnections(1,1)
if($result.ReturnValue -eq 0) {
  Write-Host "Enabled RDP Successfully"
} else {
  Write-Host "Failed to enabled RDP"
}
try{
  #Enable-NetFirewallRule -DisplayGroup "Remote Desktop*"
  Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true
}catch{
  #Win7 #netsh advfirewall firewall set service type=remotedesktop mode=enable
  netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
}
$cygUrl = "https://cygwin.com/setup-x86.exe"
$tempDir = "C:\TEMP"
$downloadDir = $tempDir + "\Downloads"
New-Item $downloadDir -type directory
$cygSaveTo = $downloadDir+"\setup-x86.exe"
Write-Host "Downloading CYGWIN to" $cygSaveTo
(New-Object System.Net.WebClient).DownloadFile($cygUrl, $cygSaveTo)
Write-Host -ForegroundColor Green "Installing Cygwin with Rsync"
$CYG_PATH = "C:\cygwin"
$cyginfo = New-Object System.Diagnostics.ProcessStartInfo
$cyginfo.FileName = $cygSaveTo
$cyginfo.UseShellExecute = $false
$cyginfo.Arguments = "--quiet-mode --site ftp://ftp.funet.fi/pub/mirrors/cygwin.com/pub/cygwin/ --root $CYG_PATH --packages rsync,curl"
$cyg = New-Object System.Diagnostics.Process
$cyg.StartInfo = $cyginfo
$cyg.Start() | Out-Null
$cyg.WaitForExit()
if($cyg.ExitCode -eq 0){   
  #$OLD_USER_PATH=[Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::User)
  $OLD_MACHINE_PATH=[Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
  $CYG_PATH = $CYG_PATH+";"+$CYG_PATH+"\bin"
  #[Environment]::SetEnvironmentVariable("PATH", "${OLD_USER_PATH};${CYG_PATH}", "User")
  [Environment]::SetEnvironmentVariable("PATH", "${OLD_MACHINE_PATH};${CYG_PATH}", "Machine")
  Write-Output "rsync installed"
}
Write-Host "Searching authorized_keys in users profiles"
$table = Get-ChildItem $usersDir -recurse | Where-Object {$_.PSIsContainer -eq $true -and $_.Name -match ".ssh"}
foreach($file in $table){        
  Write-Host $file.FullName
  $keyFile = $file.FullName+"\authorized_keys"
  $authkey = Get-Item $keyFile
  Write-Host -ForegroundColor Green "Found" $authkey.FullName
  #$sshKeysCopy = [Environment]::GetFolderPath("UserProfile")+"\.ssh"
  $sshKeysCopy = $usersDir + "\" + $localAdminName + "\.ssh"
  ( New-Item $sshKeysCopy -type directory -force ) > $null
  $sshKeysCopy = $sshKeysCopy + "\authorized_keys"
  ( Copy-Item -Path $authkey.FullName -Destination $sshKeysCopy ) > $null
  break
}
$url = "http://www.mls-software.com/files/setupssh-7.2p2-1-v1.exe"  
$saveTo = $downloadDir + "\OpenSSH-Install.exe"
(New-Object System.Net.WebClient).DownloadFile($url, $saveTo)
$sshDir = "C:\Program Files\OpenSSH"
Write-Output "Installing OpenSSH service"
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $saveTo
#$pinfo.RedirectStandardError = $true
#$pinfo.RedirectStandardOutput = $true
$pinfo.UseShellExecute = $false
$pinfo.Arguments = "/S /password=Password01 /domain=0 /privsep=1 /serveronly=1"
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null
$p.WaitForExit()
#$stdout = $p.StandardOutput.ReadToEnd()
#$stderr = $p.StandardError.ReadToEnd()
#Write-Host "stdout: $stdout"
#Write-Host "stderr: $stderr"
Write-Output "exit code: " + $p.ExitCode
Write-Output "Installed from" $saveTo    
cd $sshDir
$regex = "(.*)(StrictModes|PubkeyAuthentication|AuthorizedKeysFile)\s+(.+)"    
(Get-Content etc/sshd_config) | % {
  $line = $_
  if($_ -match $regex){
    $line = $line -ireplace $regex, "`$2"            
    $line = $line -replace "StrictModes", "StrictModes no"
    $line = $line -replace "PubkeyAuthentication", "PubkeyAuthentication yes"
    $line = $line -replace "AuthorizedKeysFile", "AuthorizedKeysFile .ssh/authorized_keys"
  }
  $line
} | Set-Content etc/sshd_config
Write-Output "Changing password for opensshd service"
$service = Get-WMIObject -namespace "root\cimv2" -class Win32_Service -Filter "Name=\'opensshd\'"
$newAccount = ".\sshd_server"
$newPassword = $localAdminPassword
$service.Change($null,$null,$null,$null,$null,$null,$newAccount,$newPassword)
Restart-Service "opensshd"
Write-Output "User data script is over!"
