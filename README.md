# winrm-rdp-enabler
Provision Window VM instance with powershell script that enables:
 - WinRM
 - RDP
 - SSH*
 - rsync*

 on OS up from Windows 7 SP1.

## why you may need this?
Let you want to launch a **VM** (_virtual machine_) in a cloud&mdash;AWS, Openstack, Auzre,
et cetera&mdash;with arbitrary image of Windows OS &ndash; how do you install
software on the VM, configure settings?

When you are going to spawn VM instance in a cloud you have an option to pass
**cloud-init** script in **Powershell** language (for Windows OS). This script will
run only once at the end of VM's creation. **Cloud-init** leads us to a couple of ways how to achive our
goals (install and configure software on VM):

1. _mega_-script that installs and configure all software you need &ndash; **BAD**
2. script that downloads and installs any of _CM (configuration management) tools_&mdash;SaltStack, Ansimble, Chef
&mdash;then just _pull/push_ appropriate configuration from you CM server &ndash; **NOT BAD**
3. enable WinRM (à la SSH for Windows) on VM &ndash; **GOOD** &ndash;
contemporary **IaC tools** (infrastucture as code), like CloudFormation, Terraform and Vagrant,
can execute VM's post-creation tasks: upload files to VM, execute sets of commands on VM, but
they need a communication tool&mdash;WinRM (_service supports execution of Powershell scripts remotely_).

## what does the script do?

1. sets VM's network interfaces as Private &ndash; Windows very restricts communications on Public interfaces
2. enables WinRM over HTTP
3. enables execution of **.ps1** files on VM
4. enables RDP &ndash; you may view VM's desktop now
5. creates local administrator (**LocalAdmin**, you can change this) &ndash; sometimes it is very hard to figure out 
automatically the password and correct name of build-in Administrator (may vary depending on localization), that is
why we need our own _admin_. Set your IaC tool to use this credentials.
6. *(optional)* install SSH and rsync&mdash;if you wish to opt-in uncomment last strings
    - copies your pki public key from the cloud to LocalAdmin's profile
    - installs CYGWIN with rsync package
    - installs and run OpenSSH





