#ps1_sysnative
function Set-NetworksAsPrivate {
  <#
    .synopsis
      Set all network interfaces as private network to enable winrm
  #>
  try{
    Set-NetConnectionProfile -NetworkCategory Private
  }catch{
    # Get network connections for Windows 7
    $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $connections = $networkListManager.GetNetworkConnections()
    $connections | % {$_.GetNetwork().SetCategory(1)}
  }
}
function Enable-WinrmRemote {
  <#
    .synopsis
      Enables WinRM remoting
    .description
      Turns off network profile check for WinRM, for Windows 7 - turns off firewall
  #>
  Set-ExecutionPolicy RemoteSigned
  Enable-PSRemoting -Force
  try{
    Set-WSManQuickConfig -SkipNetworkProfileCheck -Force
  }catch{
    #win7
    netsh advfirewall set allprofiles state off
  }
}

function Enable-WinrmOverHttp {
  <#
    .synopsis
      Allow WinRM over plain HTTP (AllowUnencrypted)
  #>
  Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value "true" -Force
  Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
  Write-Host "WinRM over HTTP is enabled"
}

function Enable-RDP {
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
}

function New-LocalAdmin {
  param([string]$username, [string]$password)
  $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
  Write-Host "Creating $username user"
  $LocalAdmin = $Computer.Create("User", $username)
  $LocalAdmin.setPassword($password)
  $LocalAdmin.UserFlags = 64 + 65536
  $LocalAdmin.setInfo()
  $LocalAdmin.FullName = "Local Admin for Powershell"
  $LocalAdmin.setInfo()
  $LocalAdmin.Description = "Defined by Powershell"
  $LocalAdmin.setInfo()
  $admGroupSID = get-wmiobject win32_group -Filter "SID='S-1-5-32-544'"
  $admGroupName = $admGroupSID.Name
  Write-Host ("Adding $username  to group $admGroupName")
  $groupExpression = "WinNT://$Env:COMPUTERNAME/$admGroupName,Group"
  $AdminGroup = [ADSI]$groupExpression
  $AdminGroup.Add("WinNT://$username,User")
  $AdminGroup.SetInfo()
}

function Get-UsersDir {
  $userProfilePath = $env:USERPROFILE
  Write-Host "Userprofile $userProfilePathfor user $env:USERNAME"
  $usersDir = (get-item $userProfilePath ).parent.FullName
  Write-Host "Users directory is $usersDir"
  return $usersDir
}

function New-LocalAdminProfile {
  <#
    .synopsis
      Creates Local admin profile
    .description
      Invokes simple CMD command (echo) under the provided credentials
    .parameter username
      Username to create profile for.
    .parameter password
      Password of the user to create profile for.
  #>
  param([string]$username, [string]$password)
  $cred_user = ".\$username"
  $cred_password = ConvertTo-SecureString -String $password -AsPlainText -Force
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
}

function GrantLogonAsSerivce {
  <#
    .synopsis
      Grants logon as a service right to user
    .parameter username
      username that can logon as service
  #>
  param([string]$username)
  # Grant logon as a service right
  $tempPath = [System.IO.Path]::GetTempPath()
  $import = Join-Path -Path $tempPath -ChildPath "import.inf"
  if(Test-Path $import) { Remove-Item -Path $import -Force }
  $export = Join-Path -Path $tempPath -ChildPath "export.inf"
  if(Test-Path $export) { Remove-Item -Path $export -Force }
  $secedt = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
  if(Test-Path $secedt) { Remove-Item -Path $secedt -Force }
  try {
    Write-Host ("Granting SeServiceLogonRight to user account: {0}." -f $username)
    $sid = ((New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier])).Value
    secedit /export /cfg $export
    $sids = (Select-String $export -Pattern "SeServiceLogonRight").Line
    foreach ($line in @("[Unicode]", "Unicode=yes", "[System Access]", "[Event Audit]", "[Registry Values]", "[Version]", "signature=`"`$CHICAGO$`"", "Revision=1", "[Profile Description]", "Description=GrantLogOnAsAService security template", "[Privilege Rights]", "SeServiceLogonRight = *$sids,*$sid")){
      Add-Content $import $line
    }
    secedit /import /db $secedt /cfg $import
    secedit /configure /db $secedt
    gpupdate /force
    Remove-Item -Path $import -Force
    Remove-Item -Path $export -Force
    Remove-Item -Path $secedt -Force
  }
  catch {
    Write-Host ("Failed to grant SeServiceLogonRight to user account: {0}" -f $username)
    $error[0]
  }
}

function Install-SshKeys {
  <#
    .synopsis
      Puts cloud keys to the specified user profile, that will run SSH daemon.
    .parameter username
      username that runs SSH daemon
  #>
  param([string]$username)
  Write-Host "Searching authorized_keys in users profiles"
  $usersDir = Get-UsersDir
  $table = Get-ChildItem $usersDir -recurse | Where-Object {$_.PSIsContainer -eq $true -and $_.Name -match ".ssh"}
  foreach($file in $table){
    $sshdir = $file.FullName
    Write-Host $sshdir
    $keyFile = "$sshdir\authorized_keys"
    $authkey = Get-Item $keyFile
    Write-Host "Found" $authkey.FullName
    #$sshKeysCopy = [Environment]::GetFolderPath("UserProfile")+"\.ssh"
    $sshKeysCopy = "$usersDir\$username\.ssh"
    ( New-Item $sshKeysCopy -type directory -force ) > $null
    $sshKeysCopy = "$sshKeysCopy\authorized_keys"
    ( Copy-Item -Path $authkey.FullName -Destination $sshKeysCopy ) > $null
    break
  }
}

function DownloadFromHttp {
  <#
    .synopsis
      Downloads file from web server to the specified directory
    .parameter url
      URL of the file on web server
    .parameter dir
      Local directory to save file.
    .parameter filename
      Name of the file in local directory where to save download.
  #>
  param([string]$url, [string]$dir, [string]$filename)
  New-Item $dir -type directory -Force | Out-Null
  $saveTo = "$dir\$filename"
  Write-Host "Downloading $url into $saveTo"
  (New-Object System.Net.WebClient).DownloadFile($url, $saveTo) | Out-Null
  return $saveTo
}

function Install-Cygwin {
  Write-Host "Installing Cygwin for Rsync"
  $cygSaveTo = DownloadFromHttp -url "https://cygwin.com/setup-x86.exe" -dir "C:\TEMP\Downloads" -filename "setup-x86.exe"
  $cyginfo = New-Object System.Diagnostics.ProcessStartInfo
  $cyginfo.RedirectStandardError = $true
  $cyginfo.RedirectStandardOutput = $true
  $cyginfo.FileName = $cygSaveTo
  $cyginfo.UseShellExecute = $false
  $CYG_PATH = "C:\cygwin"
  $cyginfo.Arguments = "--quiet-mode --site ftp://ftp.funet.fi/pub/mirrors/cygwin.com/pub/cygwin/ --root $CYG_PATH --packages rsync,curl"
  $cyg = New-Object System.Diagnostics.Process
  $cyg.StartInfo = $cyginfo
  $cyg.Start() | Out-Null
  $cyg.WaitForExit()
  if($cyg.ExitCode -eq 0){
    #$$OLD_USER_PATH=[Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::User)
    $OLD_MACHINE_PATH=[Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
    $CYG_PATH = $CYG_PATH+";"+$CYG_PATH+"\bin"
    #[Environment]::SetEnvironmentVariable("PATH", "$${OLD_USER_PATH};$${CYG_PATH}", "User")
    [Environment]::SetEnvironmentVariable("PATH", "$OLD_MACHINE_PATH;$CYG_PATH", "Machine")
    Write-Host "rsync installed"
  }else {
    Write-Host "exit code: " $cyg.ExitCode
    Write-Host "ERROR: " $cyg.StandardError.ReadToEnd()
    Write-Host "OUTPUT: " $cyg.StandardOutput.ReadToEnd()
  }
}

function Install-Sshd {
  <#
    .synopsis
      Downloads and runs OpenSSH server for Windows
    .parameter password
      ./sshd_server account's password that will run OpenSSH service
  #>
  param([string]$password)
  $saveTo = DownloadFromHttp -url "http://www.mls-software.com/files/setupssh-7.2p2-1-v1.exe" -dir "C:\TEMP\Downloads" -filename "OpenSSH-Install.exe"
  $sshDir = "C:\Program Files\OpenSSH"
  Write-Host "Installing OpenSSH service"
  $pinfo = New-Object System.Diagnostics.ProcessStartInfo
  $pinfo.FileName = $saveTo
  #$pinfo.RedirectStandardError = $true
  #$pinfo.RedirectStandardOutput = $true
  $pinfo.UseShellExecute = $false
  $pinfo.Arguments = "/S /password=$password /domain=0 /privsep=1 /serveronly=1"
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $pinfo
  $p.Start() | Out-Null
  $p.WaitForExit()
  Write-Host "exit code: " + $p.ExitCode
  Write-Host "Installed from $saveTo"
  Set-Location $sshDir
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
  Write-Host "Removing DOMAIN or HOSTNAME from service account name"
  $service = Get-WMIObject -namespace "root\cimv2" -class Win32_Service -Filter "Name='opensshd'"
  $newAccount = ".\sshd_server"
  $service.Change($null,$null,$null,$null,$null,$null,$newAccount,$password)
  Restart-Service "opensshd"
}
Set-NetworksAsPrivate
Enable-WinrmRemote
Enable-WinrmOverHttp
Restart-Service winrm
Enable-RDP
$username = "${LocalAdminUsername}"
$password = "${LocalAdminPassword}"
New-LocalAdmin -username $username -password $password
New-LocalAdminProfile -username $username -password $password
GrantLogonAsSerivce -username $username
Install-SshKeys -username $username
#Install-Cygwin
#Install-Sshd -password $password
