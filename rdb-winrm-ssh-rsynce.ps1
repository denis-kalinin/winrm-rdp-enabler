#ps1_sysnative
function NetworksAsPrivate-Set {
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
function WinrmRemote-Enable {
  <#
    .synopsis
      Enables WinRM remoting
    .description
      Turns off network profile check for WinRM, for Windows 7 - turns off firewall
  #>
  Enable-PSRemoting -Force
  try{
    Set-WSManQuickConfig -SkipNetworkProfileCheck -Force
  }catch{
    #win7
    netsh advfirewall set allprofiles state off
  }
}

function WinrmOverHttp-Enable {
  <#
    .synopsis
      Allow WinRM over plain HTTP (AllowUnencrypted)
  #>
  Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value "true" -Force
  Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
  Write-Host "WinRM over HTTP is enabled"
}

function RDP-Enable {
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

function LocalAdmin-Create {
  param([string]$username, [string]$password)
  $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
  Write-Output ("Creating " + $username + " user")
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
  Write-Output ("Adding $username  to group $admGroupName")
  $groupExpression = "WinNT://$Env:COMPUTERNAME/$admGroupName,Group"
  $AdminGroup = [ADSI]$groupExpression
  $AdminGroup.Add("WinNT://$username,User")
  $AdminGroup.SetInfo()
}

function UsersDir-Get {
  $userProfilePath = [Environment]::GetFolderPath("MyDocuments")
  Write-Output "Userprofile $userProfilePathfor user $env:USERNAME"
  $usersDir = (get-item $userProfilePath ).parent.parent.FullName
  Write-Output "Users directory is $usersDir"
  return $userDir
}

function LocalAdminProfile-Create {
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

function SshKeys-Install {
  <#
    .synopsis
      Puts cloud keys to the specified user profile, that will run SSH daemon.
    .parameter username
      username that runs SSH daemon
  #>
  param([string]$username)
  Write-Host "Searching authorized_keys in users profiles"
  $usersDir = UsersDir-Get
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
  New-Item $dir -type directory
  $saveTo = "$dir\$filename"
  Write-Host "Downloading $url into $saveTo"
  (New-Object System.Net.WebClient).DownloadFile($url, $saveTo)
  return $saveTo
}

function Cygwin-Install {
  Write-Host "Installing Cygwin for Rsync"
  $cygSaveTo = DownloadFromHttp -url "https://cygwin.com/setup-x86.exe" -dir "C:\TEMP\Downloads" -filename "setup-x86.exe"
  $cyginfo = New-Object System.Diagnostics.ProcessStartInfo
  $cyginfo.FileName = $cygSaveTo
  $cyginfo.UseShellExecute = $false
  $CYG_PATH = "C:\cygwin"
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
}

function Sshd-Install {
  <#
    .synopsis
      Downloads and runs OpenSSH server for Windows
    .parameter password
      ./sshd_server account's password that will run OpenSSH service
  #>
  param([string]password)
  $saveTo = DownloadFromHttp -url "http://www.mls-software.com/files/setupssh-7.2p2-1-v1.exe" -dir "C:\TEMP\Downloads" -filename "OpenSSH-Install.exe"
  $sshDir = "C:\Program Files\OpenSSH"
  Write-Output "Installing OpenSSH service"
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
  Write-Output "exit code: " + $p.ExitCode
  Write-Output "Installed from $saveTo"
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
  Write-Output "Removing DOMAIN or HOSTNAME from service account name"
  $service = Get-WMIObject -namespace "root\cimv2" -class Win32_Service -Filter "Name='opensshd'"
  $newAccount = ".\sshd_server"
  $service.Change($null,$null,$null,$null,$null,$null,$newAccount,$password)
  Restart-Service "opensshd"
}
NetworskAsPrivate-Set
WinrmRemote-Enable
WinrmOverHttp-Enable
Restart-Service winrm
RDP-Enable
$username = "LocalAdmin"
$password = "Password01"
LocalAdmin-Create -username $username -password $password
LocalAdminProfile-Create -username $username -password $password
SshKeys-Install -username $username
#Cygwin-Install
#Sshd-Install -password $password
