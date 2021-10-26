### Exit command to prevent the whole script from accidently being run...
Write-Host "This script is not designed to be run end-to-end. Please run selected parts of the script in ISE using the 'Run Selection' fuction" -ForegroundColor Yellow
exit

### Interact install steps
### ----------------------
### Install SQL Express (Optional if no database server)
### Install SMSS (optional, but recommended)
### Install .NET FWK 4.7.2
### Install Blue Prism
### Install Prereqs
###    .NET FWK 4.7.2 (if not done already)
###    3.1.11 Windows Hosting
###    3.1.11 Windows Desktop Runtime
###    VCRedist
###    IIS
###    Erlang
###    RabbitMQ
###        Install management plugin
###        Create new RabbitMQ User
###    Create Certificates
### Install Hub
### Install Interact 
### Do Windows Authentication if required
###     Certificate keys
###     Windows Services
###     Application Pools
###     Folder Permissions
### Reboot
### Test portal
### Install plugins


### Decipher install steps
### ----------------------
### Install SQL Express (Optional if no database server)
### Install SMSS (optional, but recommended)
### Install .NET FWK 4.7.2
### Install Blue Prism
### Import Decipher Licence into BP DB
### Copy Decipher Dll to BP installation directory
### Install Prereqs
###    .NET FWK 4.7.2 (if not done already)
###    IIS
###    Erlang
###    RabbitMQ
###        Install management plugin
###        Create new RabbitMQ User
### Install Licence Service
### Install Decipher Server
### Install Decipher Web Client
### Install Decipher Automated Client
### Install Decipher Server Plugin
### Activate Decipher Website, disable Default website
### Do Windows Authentication (Services required)
###     Windows Services
###     Application Pool
### Set ReprtingDB data sync
### Add Decipher SQL location to Web.config
### Enable machine learning training (optional)
### Reboot
### Test portal### Test Decipher

###### List of files to be downloaded from Blue Prism Portal, the cannot be downloaded through Powershell ######
###### !!! Note correct as of Oct '21 but very likely to change in the future !!! ######

### Blue Prism V7.0
### https://portal.blueprism.com/system/files/2021-05/BluePrism7.0_x64_0.msi

### Interact 4.1.1 files to be copied to C:\temp
### From  here:
### https://portal.blueprism.com/node/72551
###    https://portal.blueprism.com/system/files/2021-10/BluePrismHub-4.4.1.msi
###    https://portal.blueprism.com/system/files/2021-10/BluePrismInteract-4.4.1.msi
###    https://portal.blueprism.com/system/files/2021-09/Interact-API-Service-v1.5.zip


### Decipher 1.2 files to be copied to C:\temp
### From  here:
### https://portal.blueprism.com/node/72274
###    https://portal.blueprism.com/system/files/2021-05/BluePrism.Decipher.VBO_.Interop_0.zip
###    https://portal.blueprism.com/system/files/2021-05/BPA%20Object%20-%20Decipher.zip
###    https://portal.blueprism.com/system/files/2021-05/Decipher%20v1.0.zip
###    https://portal.blueprism.com/system/files/2021-05/Decipher%20Licensing%20Service.msi
###    https://portal.blueprism.com/system/files/2021-05/Decipher%20Server%201.221.03230.msi
###    https://portal.blueprism.com/system/files/2021-05/Decipher%20Web%20Client%201.221.05130.msi
###    https://portal.blueprism.com/system/files/2021-05/Decipher%20Automated%20Clients%201.220.12070.msi
###    https://portal.blueprism.com/system/files/2021-05/Decipher%20Server%20Plugin.msi
###    https://portal.blueprism.com/system/files/2021-05/Invoice.zip


######## Start of Download section ########

### Download .NET FWK 4.7.2
wget https://go.microsoft.com/fwlink/?LinkID=863265 -outfile C:\temp\ndp472-kb4054530-x86-x64-allos-enu.exe

### Download 3.1.11 Windows Hosting (Interact only)
wget https://download.visualstudio.microsoft.com/download/pr/d8b046b7-c812-4200-905d-d2e0242be9d5/53d5698d79013be0232152ae1b43c86b/dotnet-hosting-3.1.11-win.exe -outfile C:\temp\dotnet-hosting-3.1.11-win.exe

### Download 3.1.11 Desktop Runtime (Interact only)
wget https://download.visualstudio.microsoft.com/download/pr/3f1cc4f7-0c1a-48ca-9551-a8447fa55892/ed9809822448f55b649858920afb35cb/windowsdesktop-runtime-3.1.11-win-x64.exe -outfile C:\temp\windowsdesktop-runtime-3.1.11-win-x64.exe

### Download VCRedist (Interact only)
wget https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe -outfile C:\temp\vcredist_x64.exe

### Download SQL 2019 Express Installer (If required)
wget https://go.microsoft.com/fwlink/?linkid=866658 -outfile C:\temp\SQL2019-SSEI-Expr.exe

### Download SQL 2019 Express Silent install ini file (If required)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
wget https://raw.githubusercontent.com/BPMikeLawrence/ScriptedInstall/main/2019SQLExpressConfigurationFile.ini -outfile C:\temp\2019SQLExpressConfigurationFile.ini

### Download SMSS (If required)
wget https://aka.ms/ssmsfullsetup -outfile C:\temp\SSMS-Setup-ENU.exe

### Download Erlang
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
wget https://github.com/erlang/otp/releases/download/OTP-23.3/otp_win64_23.3.exe -outfile C:\temp\otp_win64_23.3.exe

### Download RabbitMQ
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
wget https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.8.17/rabbitmq-server-3.8.17.exe -outfile C:\temp\rabbitmq-server-3.8.17.exe

### Download Chrome
wget https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B9B042D81-4049-E06D-2587-CC2F8DC642F9%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe -outfile C:\temp\ChromeStandaloneSetup64.exe

######## End of Download section ########


######## Start of Install commands section ########

### Install .NET Fwk 4.7.2
Start-process "C:\temp\ndp472-kb4054530-x86-x64-allos-enu.exe" "/Passive -wait" -Wait:$true -Passthru

### (Interact only)
### Install 3.1.11 Windows Hosting
Start-process "C:\temp\dotnet-hosting-3.1.11-win.exe" "/Passive -wait" -Wait:$true -Passthru

### (Interact only)
### Install 3.1.11 Widows Desktop Runtime
Start-process "C:\temp\windowsdesktop-runtime-3.1.11-win-x64.exe" "/Passive -wait" -Wait:$true -Passthru

### (Interact only)
### Install VCRedistributables
Start-process "C:\temp\vcredist_x64.exe" "/Passive -wait" -Wait:$true -Passthru

### Install IIS
Install-WindowsFeature -Name Web-Mgmt-Console, Web-Net-Ext, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content -computerName localhost -Restart

### Download SQL install files (If required)
Start-process “C:\temp\SQL2019-SSEI-Expr.exe" "/ACTION=Download MEDIAPATH=C:\temp /MEDIATYPE=Core /QUIET" -Wait:$true -Passthru

### Extract SQL files (If required)
Start-process "C:\temp\SQLEXPR_x64_ENU.exe" "/q /x:C:\temp\sqlinstallfiles" -Wait:$true -Passthru

### Replace password placeholder in SQL ini file (If required)
(Get-Content -path C:\temp\2019SQLExpressConfigurationFile.ini -Raw) -replace 'SQLPASSWORDPLACEHOLDER','Password123!' | Set-Content -Path C:\temp\2019SQLExpressConfigurationFile.ini

### Start SQL install (If required)
Start-process "C:\temp\sqlinstallfiles\Setup.exe" "/ConfigurationFile=C:\temp\2019SQLExpressConfigurationFile.ini" -Wait:$true -Passthru

### Start SMSS install (If required)
Start-process "C:\temp\SSMS-Setup-ENU.exe" "/Passive -wait" -Wait:$true -Passthru

### Install Chrome
Start-process "C:\temp\ChromeStandaloneSetup64.exe" "/silent /install" -Wait:$true -Passthru

### Add RabbitMQ Environment variables for a sensible RMQ AppDB directory
[System.Environment]::SetEnvironmentVariable('RABBITMQ_BASE','C:\RabbitMQ',[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('RABBITMQ_LOGS','C:\RabbitMQ\RMQ.log',[System.EnvironmentVariableTarget]::Machine)

### Install Erlang - Into the default "C:\Program Files\erl-23.3" folder
Start-Process "C:\temp\otp_win64_23.3.exe" "/S" -Wait:$true -Passthru

### Install RabbitMQ - Into the default "C:\Program Files\RabbitMQ Server" folder
### Then enable the management console. Open the RMQ command line - rabbitmq-plugins enable rabbitmq_management
### Then create a new user - go to http://localhost:15672
$proc = Start-Process "C:\temp\rabbitmq-server-3.8.17.exe" "/S" -Wait:$false -Passthru
Wait-Process -Id $proc.Id

### (Interact only)
### Create self-signed certificates. Note not ideal for Production environments!!!
### Substitute XXXXXXXX for your machine host name, and change the hostnames and Certificate friendly name to suit
New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName XXXXXXXX,
authentication.local,
hub.local,
email.local,
audit.local,
file.local,
signalr.local,
notification.local,
license.local,
interact.local,
iada.local,
interactremoteapi.local -FriendlyName "HubAndInteractCert" -NotAfter (Get-Date).AddYears(10)

### (Interact only)
### Copy the certificate to the Trusted Root store. Ensure the friendly name matches the previous certificate creation command
$filehash = (Get-Childitem cert:\LocalMachine\My | Where-Object { $_.friendlyname -like "HubAndInteractCert" }).Thumbprint
Export-Certificate -Cert (Get-Item Cert:\LocalMachine\My\$filehash) -FilePath C:\temp\mycert.cert
Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath C:\temp\mycert.cert


######## End of Install commands section ########

######## Start of configuration commands section ########


### Handy code to do Interact Application Pool identity and Services Log on as changes - Change credentials to suit

$User = "YourDomain\YourAccount"
$Password = "YourPassword"

$User = ".\InstallUser"
$Password = "Password123!"
$InteractServices = "Blue Prism - Audit Service Listener", "Blue Prism - Log Service", "Blue Prism - Submit Form Manager"
Import-Module WebAdministration
$pools = Get-ChildItem IIS:\AppPools | where { $_.name -Like  "Blue Prism - *"}
foreach ($pool in $pools)
	{
	$pool.processmodel.identityType = 3
	$pool.processmodel.username = $User
	$pool.processmodel.password = $Password
    Restart-WebAppPool -Name $pool.name
    Start-WebAppPool -Name $pool.name
	$pool | Set-Item
	}
foreach ($service in $InteractServices)
    {
    echo $service
    $ServiceC = Get-WmiObject Win32_Service -Filter "Name='$service'"
    $ServiceC.Change($null,$null,$null,$null,$null,$null,$User,$Password,$null,$null,$null)
    Restart-Service -name $service
    }


### Handy code to do Decipher Application Pool identity and Services Log on as changes - Change credentials to suit
$User = ".\InstallUser"
$Password = "Password123!"
$DecipherServices = "DecipherAutoClientManager", "BluePrism.Decipher.LicensingService", "DecipherService", "DecipherWebSDKService"
Import-Module WebAdministration
$pools = Get-ChildItem IIS:\AppPools | where { $_.name -Like  "Decipher*"}
foreach ($pool in $pools)
	{
	$pool.processmodel.identityType = 3
	$pool.processmodel.username = $User
	$pool.processmodel.password = $Password
	$pool | Set-Item
    Restart-WebAppPool -Name $pool.name
    Start-WebAppPool -Name $pool.name
	}
foreach ($service in $DecipherServices)
    {
    echo $service
    $ServiceC = Get-WmiObject Win32_Service -Filter "Name='$service'"
    $ServiceC.Change($null,$null,$null,$null,$null,$null,$User,$Password,$null,$null,$null)
    Restart-Service -name $service
    }


### (Decipher only)
### Commands to enable Reporting DB sync and ML 
(Get-Content -path 'C:\Program Files (x86)\Blue Prism\Decipher Server\SsiServer.exe.config' -Raw) -replace '<add key="SyncOldDataToReportingDatabase" value="false" />','<add key="SyncOldDataToReportingDatabase" value="true" />' | Set-Content -Path 'C:\Program Files (x86)\Blue Prism\Decipher Server\SsiServer.exe.config'
(Get-Content -path 'C:\Program Files (x86)\Blue Prism\Decipher Automated Clients\SsiDataCaptureClient.exe.config' -Raw) -replace '<add key="EnableModelTrainingML" value="false" />','<add key="EnableModelTrainingML" value="true" />' | Set-Content -Path 'C:\Program Files (x86)\Blue Prism\Decipher Automated Clients\SsiDataCaptureClient.exe.config'

######## End of configuration commands section ########