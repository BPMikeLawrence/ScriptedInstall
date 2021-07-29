########################################################################################################
# Scripted Install 
#
# Mike Lawrence, Blue Prism Professional Services EMEA
# (mike.lawrence@blueprism.com)
#
# Only attempt with:
#    Decipher 1.2+
#    Interact 4.3+
#    Internet Access
#    Server OS 2016+    
#
# My first PowerShell script that's more than two lines. OO languages have always been my nemesis. 
# Please be kind ;-)
#
# Newest version is always available here:
# https://raw.githubusercontent.com/BPMikeLawrence/ScriptedInstall/main/ScriptedInstall.ps1
# 
# v 0.1 - Alpha Version!
# v 0.2 - Based on customer experience, changed hub\interact msi names, corrected file check, tested temp directory with spaces, made interact services restart cos i forgot to do that, downloaded files are now checked for post-download
# v 0.3 - Now all global variables are written to a file first, so that the script can be very easily restarted. Updated Decipher 1.2 and Interact 4.3 source file refs now they're out. 
# v 0.4 - Option to use an alternative RabbitMQ Data Directory has been added.
# v 0.41 - Asks if you want to deletes the ini file after running.
# v 0.42 - Logfile is no longer hardcoded. 
# v 0.43 - Updated to use RMQ 3.8.17
#
# To do: 

$DecipherVersion = "1.2"
$InteractVersion = "4.3"
$BluePrismVersion = "6.10.1"

$DecipherServices = "DecipherAutoClientManager", "BluePrism.Decipher.LicensingService", "DecipherService", "DecipherWebSDKService"
$InteractServices = "Blue Prism - Audit Service Listener", "Blue Prism - Log Service", "Blue Prism - Submit Form Manager"

$NetFWKFile = "NDP472-KB4054531-Web.exe"
$NetFWKUrl = "https://download.microsoft.com/download/0/5/C/05C1EC0E-D5EE-463B-BFE3-9311376A6809/NDP472-KB4054531-Web.exe"

$DotNetHostingFile = "dotnet-hosting-3.1.3-win.exe"
$DotNetHostingUrl = "https://download.visualstudio.microsoft.com/download/pr/ff658e5a-c017-4a63-9ffe-e53865963848/15875eef1f0b8e25974846e4a4518135/dotnet-hosting-3.1.3-win.exe"

$WindowsDesktopRuntimeFile = "windowsdesktop-runtime-3.1.3-win-x64.exe"
$WindowsDesktopRuntimeURL = "https://download.visualstudio.microsoft.com/download/pr/5954c748-86a1-4823-9e7d-d35f6039317a/169e82cbf6fdeb678c5558c5d0a83834/windowsdesktop-runtime-3.1.3-win-x64.exe"

$VCRedistFile = "vcredist_x64.exe"
$VCRedistUrl = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"

$SQLExpressFile = "SQL2019-SSEI-Expr.exe"
$SQLExpressUrl = "https://go.microsoft.com/fwlink/?linkid=866658"
$SQLInstallMarker = "Browser for SQL Server 2019"

$SQLConfigFileFile = "2019SQLExpressConfigurationFile.ini"
$SQLConfigFileUrl = "https://raw.githubusercontent.com/BPMikeLawrence/ScriptedInstall/main/2019SQLExpressConfigurationFile.ini"

$SSMSFile = "SSMS-Setup-ENU.exe"
$SSMSUrl = "https://aka.ms/ssmsfullsetup"
$SSMSInstallMarker = "Microsoft SQL Server Management Studio - 18.9.1"

$ChromeFile = "ChromeStandaloneSetup64.exe"
$ChromeUrl = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B9B042D81-4049-E06D-2587-CC2F8DC642F9%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe"
$ChromeInstallMarker = "Google Chrome"

$ErlangFile = "otp_win64_23.3.exe"
$ErlangUrl = "https://github.com/erlang/otp/releases/download/OTP-23.3/otp_win64_23.3.exe"
$ErlangInstallMarker = "Erlang OTP 23.3"

$RMQFile = "rabbitmq-server-3.8.17.exe"
$RMQurl = "https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.8.17/rabbitmq-server-3.8.17.exe"
$RMQInstallMarker = "RabbitMQ Server 3.8.17"

$ErlangHome = "C:\Program Files\erl-23.3"
$RMQsbin = "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.8.16\sbin"

$HubInstallFile = "BluePrismHub-4.3.msi"
$HubInstallMarker = "Blue Prism Hub"

$InteractInstallFile = "BluePrismInteract-4.3.msi"
$InteractInstallMarker = "Blue Prism Interact"

$InteractPermsFolders = "C:\Program Files (x86)\Blue Prism"

$bpccerts = "BluePrismCloud_Data_Protection", "BluePrismCloud_IMS_JWT"

$InteractFilesarray = $HubInstallFile, $InteractInstallFile

$DecipherServerInstallFile = "Decipher Server 1.221.03230.msi"
$DecipherServerInstallMarker = "Decipher Server"

$DecipherServerPluginFile = "Decipher Server Plugin.msi"
$DecipherServerPluginMarker = "Decipher Server Plugin"

$DecipherLicensingServiceInstallFile = "Decipher Licensing Service.msi"
$DecipherLicensingServiceInstallMarker = "Decipher Licensing Service"

$DecipherWebClientInstallFile = "Decipher Web Client 1.221.05130.msi"
$DecipherWebClientInstallMarker = "Decipher Web Client"

$DecipherAutomantedClientInstallFile = "Decipher Automated Clients 1.220.12070.msi"
$DecipherAutomantedClientInstallMarker = "Decipher Automated Clients"

$DecipherFilesarray = $DecipherServerInstallFile, $DecipherServerPluginFile, $DecipherLicensingServiceInstallFile, $DecipherWebClientInstallFile, $DecipherAutomantedClientInstallFile

$DecipherPermsFolders = "C:\Program Files (x86)\Blue Prism", "C:\Windows\System32\config\systemprofile\AppData\Local\Decipher", "C:\Windows\System32\config\systemprofile\AppData\Local\Blue Prism", "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism"

$HubWebsites = $env:computername, "authentication.hostname","hub.hostname","email.hostname","audit.hostname","file.hostname","signalr.hostname","notification.hostname","license.hostname"
$InteractWebsites = $env:computername, "authentication.hostname","hub.hostname","email.hostname","audit.hostname","file.hostname","signalr.hostname","notification.hostname","license.hostname","interact.hostname","iada.hostname","interactremoteapi.hostname"

$RestartScriptUrl = "https://raw.githubusercontent.com/BPMikeLawrence/ScriptedInstall/main/RestartInteract.ps1"
$RestartScriptFile = "RestartInteract.ps1"

$Global:QRMQCustomDir = $Global:WAUser = $Global:WAPword = $Global:WAPwordPlain = $Global:QSysadminCurrentUser = $Global:QChromeInstall = $Global:QPQ = $Global:InstalledList = $Global:SQLDownloadDir = $Global:DownloadDir = $Global:SQLPasswordPlain = $Global:QRMQCreds = $Global:RMQUSer = $Global:RMQPword = $Global:RMQPwordPlain = $Global:QCertFriendlyName = $Global:QHostSuffix = $null

### FUNCTIONS ###

Function WriteandLog ($string, $colour)
    {
    $timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    #echo $timestamp 
    #echo $string
    Add-content $Logfile -value "$timestamp $string"
    Write-Host $string -ForegroundColor $colour
    }

function StartupQuestions
    {
    if (Test-Path -Path $DownloadDir)
        {
        Write-Host "Please ensure your Blue Prism installation files are present in $DownloadDir" -ForegroundColor Yellow
        } 
        else 
        {
        WriteandLog "Path does not exist, script unable to continue" Red
        exit
        }
        
    #$Global:QPQ = ProductQuestion "Are you installing Interact (I), Decipher (D) or Blue Prism V7 (B)?"
    $QPQ = ProductQuestion "Are you installing Interact (I), Decipher (D) (Blue Prism V7 coming soon)?"
    Set-Content -Path $inifile -Value "QPQ=$QPQ"
      
# Check Interact install files exist, before we start    
    if ($QPQ -eq "I")
        {
        foreach ($InstallFile in $InteractFilesarray)
        	{
            if (-not (Test-Path -Path "$DownloadDir\$InstallFile" -PathType Leaf))
                {
                WriteandLog "Unable to find install file, $InstallFile. Please download and place in $DownloadDir before retrying" Red
                exit
	            } 
            }
        }

# Check Decipher install files exist, before we start       
    if ($QPQ -eq "D")
        {
        foreach ($InstallFile in $DecipherFilesarray)
        	{
            if (-not (Test-Path -Path "$DownloadDir\$InstallFile" -PathType Leaf))
                {
                WriteandLog "Unable to find install file, $InstallFile. Please download and place in $DownloadDir before retrying" Red
                exit
	            } 
            }
        }

    $QIISInstall = InputQuestion "Do you want IIS Installing?" "Y"
    Add-Content -Path $inifile -Value "QIISInstall=$QIISInstall"

    $QSQLInstall = InputQuestion "Do you want SQL Express Installing?" "Y"
    Add-Content -Path $inifile -Value "QSQLInstall=$QSQLInstall"
    if ($QSQLInstall -eq "Y")
        {
        DefineSQLCreds
        $QSysadminCurrentUser = InputQuestion "Do you want to add the current logged on user as a DB sysadmin?" "Y"
        Add-Content -Path $inifile -Value "QSysadminCurrentUser=$QSysadminCurrentUser"    
        }
    
    $QSSMSInstall = InputQuestion "Do you want SQL Server Management Studio Installing?" "Y"
    Add-Content -Path $inifile -Value "QSSMSInstall=$QSSMSInstall"
    
    $QChromeInstall = InputQuestion "Do you want Chrome Installing?" "Y"
    Add-Content -Path $inifile -Value "QChromeInstall=$QChromeInstall"
    
    $QRMQInstall = InputQuestion "Do you want RabbitMQ Installing?" "Y"
    Add-Content -Path $inifile -Value "QRMQInstall=$QRMQInstall"

    if ($QRMQInstall -eq "Y")
        {
        $QRMQCreds = InputQuestion "Do you want to use the standard guest\guest RMQ account? (Or use custom credentials?)" "Y"
        Add-Content -Path $inifile -Value "QRMQCreds=$QRMQCreds"
        if ($QRMQCreds -ne "Y")
            {
            DefineRMQCreds
            }
        $QRMQCustomDir = InputQuestion "Do you want to use the standard Data Directory $env:APPDATA\RabbitMQ? (Or define your own directory?)" "Y"
        Add-Content -Path $inifile -Value "QRMQCustomDir=$QRMQCustomDir"
        if ($QRMQCustomDir -ne "Y")
            {
            DefineRMQDataDir
            }
        }
    
    $QWA = InputQuestion "Do you want use Windows Authentication? (The alternative being everything running under the local system account)" "Y"
    Add-Content -Path $inifile -Value "QWA=$QWA"
    if ($QWA -eq "Y")
        {
        Write-Host "Before continuing, ensure that this logged on user has syaadmin access to your database!!!" -ForegroundColor Red
		DefineWACreds
        }


    if ($QPQ -ne "D")
        {
        $QRMQCerts = InputQuestion "Create a Self-Signed Certificate?" "Y"
        Add-Content -Path $inifile -Value "QRMQCerts=$QRMQCerts"
        if ($QRMQCerts -eq "Y")
            {
            $QHostSuffix = InputQuestion "Choose a suffix for your web sites \ applications " ".local"
            Add-Content -Path $inifile -Value "QHostSuffix=$QHostSuffix"
            $QCertFriendlyName = InputQuestion "Choose a Friendly Name for you Certificate" "MyBPCertificate"
            Add-Content -Path $inifile -Value "QCertFriendlyName=$QCertFriendlyName"
            }
        }
    }

function DefineRMQDataDir
    {
    $RMQCustomDir = Read-Host "Enter RabbitMQ custom Data Directory path (in the standard windows format E.g. C:\Applications\RabbitMQ)"
    Add-Content -Path $inifile -Value "RMQCustomDir=$RMQCustomDir"
    }

function DefineWACreds
    {
    $WAUser = Read-Host "Enter WA Account (in the format DOMAIN\USER (prefix .\ for a local account))"
    Add-Content -Path $inifile -Value "WAUser=$WAUser"
    $WAPword = Read-Host -AsSecureString "Enter WA Password"
    Add-Content -Path $inifile -Value "WAPword=$WAPword"
    $WAPwordPlain =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($WAPword))
    Add-Content -Path $inifile -Value "WAPwordPlain=$WAPwordPlain"
    $ShowPW = InputQuestion "Do you want to see your password to check it?" "N"
    if ($ShowPW -eq "Y")
        {
        WriteandLog "Your WA password is : $WAPwordPlain" Gray
        }
    }


function DefineRMQCreds
    {
    $RMQUser = Read-Host "Enter RabbitMQ custom Username"
    Add-Content -Path $inifile -Value "RMQUser=$RMQUser"
    $RMQPword = Read-Host -AsSecureString "Enter RabbitMQ custom Password"
    Add-Content -Path $inifile -Value "RMQPword=$RMQPword"
    $RMQPwordPlain =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($RMQPword))
    Add-Content -Path $inifile -Value "RMQPwordPlain=$RMQPwordPlain"
    $ShowPW = InputQuestion "Do you want to see your password to check it?" "N"
    if ($ShowPW -eq "Y")
        {
        WriteandLog "Your RMQ password is : $RMQPwordPlain" Gray
        }
    }


function DefineSQLCreds
    {
    $SQLPassword = Read-Host -AsSecureString "Enter SQL sa account custom Password"
    #Add-Content -Path $inifile -Value "SQLPassword=$SQLPassword"
    $SQLPasswordPlain =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SQLPassword))
    Add-Content -Path $inifile -Value "SQLPasswordPlain=$SQLPasswordPlain"
    $ShowPW = InputQuestion "Do you want to see your password to check it?" "N"
    if ($ShowPW -eq "Y")
        {
        WriteandLog "Your SQL password is : $SQLPasswordPlain" Gray
        }
    #Add-Content -Path $inifile -Value "SQLPassword=$SQLPassword"
    }
    

function ProductQuestion($question)
    {
    $answer = Read-Host $question
     while("I","D","B" -notcontains $answer)
        {
        $answer = Read-Host "Please answer Interact (I), Decipher (D) or Blue Prism V7 (B)"
        }
    return $answer
    }


function InputQuestion ($question, $DefaultAnswer)
    {
    $answer = Read-Host "$question -$DefaultAnswer-"
    if ([string]::IsNullOrWhiteSpace($answer))
        {
        $answer = $DefaultAnswer
        }
#    while("Y","N" -notcontains $answer)        
#        {
#        $answer = Read-Host "Please answer all questions Yes (Y) or No (N). Hitting enter defaults to Y"
#        }
    return $answer
    }


function CheckInstalled ($Software)
    {
    $Global:InstallCheck = $null
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > $Global:InstalledList
    $Global:InstallCheck  = Select-String -Path $Global:InstalledList -Pattern $Software
    if ($InstallCheck -ne $null)
        {
        WriteandLog "$Software is already installed" Green
        }
        else
        {
        WriteandLog "$Software is not installed" Yellow
        }
    }


function CheckAndDownload($file, $url, $CheckDownloadDir)
    {
    if (-not (Test-Path -Path "$CheckDownloadDir\$file" -PathType Leaf))
        {
        WriteandLog "Downloading $file" White
        wget $url -outfile $CheckDownloadDir\$file
        if (-not (Test-Path -Path "$CheckDownloadDir\$file" -PathType Leaf))
            {
            WriteandLog "Unable to download $file. Do you have access to the Internet?" Red
            exit
            }
        }
        else
        {
        WriteandLog "$file already present in $CheckDownloadDir" Gray
        }
    }


function InstallChrome
    {
    WriteandLog "Starting Chrome install" Green
    CheckInstalled $ChromeInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        $dl = CheckAndDownload $ChromeFile $ChromeUrl $Global:DownloadDir
        Start-process "$Global:DownloadDir\$Chromefile" "/silent /install" -Wait:$true -Passthru
        }
    }


function InstallIIS
    {
    WriteandLog "Starting IIS install" Green
    WriteandLog "Note! This may take some time. If the windows modules installer worker is still running, let it be" Yellow
    Install-WindowsFeature -Name Web-Mgmt-Console, Web-Net-Ext, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content -computerName localhost -Restart
    }


function InstallSQL
    {
    WriteandLog "Starting SQL install" Green
    CheckInstalled $SQLInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        $dl = CheckAndDownload $SQLExpressFile $SQLExpressUrl $Global:DownloadDir
        Set-Location $Global:DownloadDir
        Start-process "$Global:DownloadDir\$SQLExpressFile" "/ACTION=Download MEDIAPATH=$Global:DownloadDir /MEDIATYPE=Core /QUIET" -Wait:$true -Passthru
        Start-process "$Global:DownloadDir\SQLEXPR_x64_ENU.exe" "/q /x:$Global:SQLDownloadDir" -Wait:$true -Passthru
        Set-Location $Global:SQLDownloadDir
    
        WriteandLog "Pulling slient install configfile from GitHub" Magenta
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $dl = CheckAndDownload $SQLConfigFileFile $SQLConfigFileUrl $Global:SQLDownloadDir
        (Get-Content -path $Global:SQLDownloadDir\$SQLConfigFileFile -Raw) -replace 'SQLPASSWORDPLACEHOLDER',$Global:SQLPasswordPlain | Set-Content -Path $Global:SQLDownloadDir\$SQLConfigFileFile
        
        WriteandLog "Silently Installing SQL" Magenta
        Start-process "Setup.exe" "/ConfigurationFile=$SQLConfigFileFile" -Wait:$true -Passthru
        }

    if ($Global:QSysadminCurrentUser -eq "Y")
        {
        SysadminCurrentUser
        }
    }

function SysadminCurrentUser
    {
    WriteandLog "Adding logged on user to sysadmin" Green
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
    $srv = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:computername\SQLEXPRESS"
    
    $currentuser = whoami
    
    $srv.ConnectionContext.LoginSecure=$false;
    $srv.ConnectionContext.set_Login("sa");
    $srv.ConnectionContext.set_Password("$Global:SQLPasswordPlain") 
        
    $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $srv, "$currentuser"
    $login.LoginType = "WindowsUser"
    $login.Create()
    $login.AddToRole("sysadmin")
    
    WriteandLog "Adding NT AUTHORITY\SYSTEM to sysadmin" Green
    $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $srv, "NT AUTHORITY\SYSTEM"
    $login.LoginType = "WindowsUser"
    $login.AddToRole("sysadmin")
    }



function InstallSMSS
    {
    WriteandLog "Starting SMSS install" Green
    CheckInstalled $SSMSInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        $dl = CheckAndDownload $SSMSFile $SSMSUrl $Global:DownloadDir
        Set-Location $Global:DownloadDir
        Start-process "$Global:DownloadDir\$SSMSFile" "/Passive -wait" -Wait:$true -Passthru
        }
    }


function InstallNetFWK472
    {
    WriteandLog "Starting .Net FWK 4.7.2. install" Green
    WriteandLog "NOTE!!!! THIS MAY CAUSE A NECCESSARY REBOOT!!!" Red
    WriteandLog "Please allow the reboot to happen then restart the script" Yellow

    $dl = CheckAndDownload $NetFWKFile $NetFWKUrl $Global:DownloadDir
    Set-Location $Global:DownloadDir
    Start-process "$Global:DownloadDir\$NetFWKFile" "/Passive -wait" -Wait:$true -Passthru
    }


function InstallHubInteractPreReqs
    {
    WriteandLog "Starting .Net Hosting install" Green
    $dl = CheckAndDownload $DotNetHostingFile $DotNetHostingUrl $Global:DownloadDir
    Start-process "$Global:DownloadDir\$DotNetHostingFile" "/Passive -wait" -Wait:$true -Passthru

    WriteandLog "Starting Windows Desktop Runtime install" Green
    $dl = CheckAndDownload $WindowsDesktopRuntimeFile $WindowsDesktopRuntimeUrl $Global:DownloadDir
    Start-process "$Global:DownloadDir\$WindowsDesktopRuntimeFile" "/Passive -wait" -Wait:$true -Passthru
    
    WriteandLog "Starting VC Redist install" Green
    $dl = CheckAndDownload $VCRedistFile $VCRedistUrl $Global:DownloadDir
    Start-process "$Global:DownloadDir\$VCRedistFile" "/Passive -wait" -Wait:$true -Passthru
    }


function InstallErlang
    {
    WriteandLog "Starting Erlang install" Green
    CheckInstalled $ErlangInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $dl = CheckAndDownload $ErlangFile $ErlangUrl $Global:DownloadDir
        WriteandLog "Installing Erlang" Green
        Start-Process "$Global:DownloadDir\$ErlangFile" "/S" -Wait:$true -Passthru
        }
    }


function InstallRMQ
    {
    WriteandLog "Starting RMQ install" Green
    CheckInstalled $RMQInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $dl = CheckAndDownload $RMQFile $RMQUrl $Global:DownloadDir
        WriteandLog "Installing RabbitMQ" Green
        $proc = Start-Process "$Global:DownloadDir\$RMQFile" "/S" -Wait:$false -Passthru
        Wait-Process -Id $proc.Id
        }
    }


function RMQConfig ($ErlangHome, $RMQsbin, $RMQCustomDir, $RMQCustomUser, $RMQCustomPword)
    {

    if ($RMQCustomDir -like '*:\*') 
        {
        WriteandLog "RMQ config and database directory will be changed to $RMQCustomDir" Green
        }
        else
        {
        $RMQCustomUser = $RMQCustomDir
        $RMQCustomPword = $RMQCustomUser
        $RMQCustomDir = $null
        }

    WriteandLog "Configuring RabbitMQ" Green
    set-location Env:
    New-Item -Path Env:\ERLANG_HOME -Value $ErlangHome
    ###get-childitem
    set-location $RMQsbin

    if ($RMQCustomDir -ne $null)
        {
        WriteandLog "Changing RMQ data directory to $RMQCustomDir" Green
        echo $env:RABBITMQ_BASE
        echo $env:ERLANG_HOME
        New-Item -Path Env:\RABBITMQ_BASE -Value $RMQCustomDir
        .\rabbitmq-service.bat remove
        Stop-Process -Name "epmd" -Force
        $RMQDataDir = "$env:APPDATA\RabbitMQ"
        WriteandLog "Deleting current RMQ data directory, $RMQDataDir" Green
        Remove-Item $RMQDataDir -Recurse
        WriteandLog "Reinstalling RMQ service with new data directory" Green
        .\rabbitmq-service.bat install
        .\rabbitmq-service.bat start
        .\rabbitmq-plugins enable rabbitmq_management
        .\rabbitmqctl stop_app
        .\rabbitmqctl start_app
        Start-Sleep -s 5
        }
        else
        {
        .\rabbitmq-plugins enable rabbitmq_management
        .\rabbitmqctl stop_app
        .\rabbitmqctl start_app
        }

    if ($RMQCustomPword -ne $null)
        {
        WriteandLog "Adding and configuring new user, $RMQCustomUser" Green
        .\rabbitmqctl add_user $RMQCustomUser $RMQCustomPword
        .\rabbitmqctl set_user_tags $RMQCustomUser administrator
        .\rabbitmqctl set_permissions -p / $RMQCustomUser ".*" ".*" ".*"
        }
    }


function CreateCerts ($Websites, $CertFriendlyName, $suffix)
    {
    WriteandLog "Creating Self-Signed Certificate" Green
    $dnsnames = $Websites.Replace(".hostname",$suffix)

    WriteandLog "Creating certificate in Peronsal Store with command:" Green
    WriteandLog "New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $dnsnames -FriendlyName $CertFriendlyName -NotAfter (Get-Date).AddYears(10)" Green
    $Cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $dnsnames -FriendlyName $CertFriendlyName -NotAfter (Get-Date).AddYears(10)
           
    WriteandLog "Moving $CertFriendlyName Cert to Trusted Root" Green

    $filehash = (Get-Childitem cert:\LocalMachine\My | Where-Object { $_.friendlyname -like $CertFriendlyName }).Thumbprint
    ###WriteandLog $filehash
    Export-Certificate -Cert (Get-Item Cert:\LocalMachine\My\$filehash) -FilePath $Global:DownloadDir\mycert.cert
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath $Global:DownloadDir\mycert.cert
    (Get-ChildItem -Path Cert:\LocalMachine\Root\$filehash).FriendlyName = $CertFriendlyName
    }

function InstallBluePrism
    {
    Start-Process "msiexec /i "C:\temp\BluePrism6.10.1_x64.msi" /QB- ALLUSERS=1" -Wait:$true -Passthru
    }


function WaitUntilServices($SearchString, $Status)
    {
    # Get all services where DisplayName matches $searchString and loop through each of them.
    foreach($Service in (Get-Service -DisplayName $SearchString))
        {
        # Wait for the service to reach the $status or a maximum of 30 seconds
        $Service.WaitForStatus($Status, '00:00:30')
        }
    }

function Add-ServiceLogonRight([string] $Username) 
    {
    #Blatant copy-paste of someone else's code. Although whoever wrote this was a legend...
    $tmp = New-TemporaryFile
    secedit /export /cfg "$tmp.inf" | Out-Null
    (gc -Encoding ascii "$tmp.inf") -replace '^SeServiceLogonRight .+', "`$0,$Username" | sc -Encoding ascii "$tmp.inf"
    secedit /import /cfg "$tmp.inf" /db "$tmp.sdb" | Out-Null
    secedit /configure /db "$tmp.sdb" /cfg "$tmp.inf" | Out-Null
    rm $tmp* -ea 0
    }


function CreateShortcut ($SourceFileLocation, $ShortcutName, $ShortcutArguments)
    {
    $CurentUserDesktop = [Environment]::GetFolderPath("Desktop")
    if ($ShortcutName -like "*Logs*")
        {
        if(!(test-path $CurentUserDesktop\Logs))
            {
            New-Item -ItemType Directory -Force -Path $CurentUserDesktop\Logs
            }
        $ShortcutLocation = "$CurentUserDesktop\Logs\$ShortcutName"
        }
        else
        {
        $ShortcutLocation = "$CurentUserDesktop\$ShortcutName"
        }
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation)
    $Shortcut.TargetPath = $SourceFileLocation
    if ($ShortcutArguments)
        {
        $Shortcut.Arguments = $ShortcutArguments
        }
    #Save the Shortcut to the TargetPath
    $Shortcut.Save()
    $ShortcutArguments = $null
    }


function InteractShortcuts
    {
    WriteandLog "Creating Interact Shortcuts" Yellow

    #CreateShortcut $SourceFileLocation $ShortcutName $ShortcutArguments 
    CreateShortcut "$env:SystemRoot\System32\inetsrv\InetMgr.exe" "IIS Manager.lnk"
    CreateShortcut "$env:SystemRoot\System32\services.msc" "Services.lnk"
    CreateShortcut "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" "Interact.lnk" "https://authentication$Global:QHostSuffix"

    CreateShortcut "C:\Program Files (x86)\Blue Prism\Audit Service\Logs_Audit" "Audit Service Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Audit Service Listener\Logs_AuditQueueListener" "Audit Service Listener Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Authentication Server\Logs_AuthenticationServer" "Authentication Server Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Email Service\Logs_EmailQueueListener" "Email Service Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\File Service\Logs_FileStorageApi" "File Service Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Hub\Logs_Hub" "Hub Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\IADA\Logs_WindowsIada" "IADA Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Interact\Logs_Interact" "Interact Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Interact Remote API\Logs_InteractRemoteApi" "Interact Remote API Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\License Manager\Logs_LicenseManager" "License Manager Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Log Service\Logs_LogsGatherer" "Log Service Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Notification Center\Logs_NotificationCenter" "Notification Center Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\SignalR\Logs_Inbox" "SignalR Logs.lnk"
    CreateShortcut "C:\Program Files (x86)\Blue Prism\Submit Form Manager\Logs_SubmitFormManager" "Submit From Manager Logs.lnk"
    }

function DecipherShortcuts
    {
    WriteandLog "Creating Decipher Shortcuts" Yellow

    #CreateShortcut $SourceFileLocation $ShortcutName $ShortcutArguments 
    CreateShortcut "$env:SystemRoot\System32\inetsrv\InetMgr.exe" "IIS Manager.lnk"
    CreateShortcut "$env:SystemRoot\System32\services.msc" "Services.lnk"
    CreateShortcut "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" "Decipher.lnk" "http://localhost:80"

    CreateShortcut "C:\Windows\System32\config\systemprofile\AppData\Local\Decipher\ApplicationServer\Logs" "Decipher Server Logs.lnk"
    CreateShortcut "C:\Windows\System32\config\systemprofile\AppData\Local\Blue Prism\AutoClientManager\Logs" "Automated Client Logs.lnk"
    CreateShortcut "C:\Windows\System32\config\systemprofile\AppData\Local\Blue Prism\Decipher Licensing Service" "Licensing Service Logs.lnk"
    CreateShortcut "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism\DecipherWebServer\Logs" "Web Server Logs.lnk"
    CreateShortcut "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism\ClassificationClient\Logs" "Classification Logs.lnk"
    CreateShortcut "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism\DataCaptureClient\Logs" "Data Capture Logs.lnk"
    CreateShortcut "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism\ExportClient\Logs" "Export Client Logs.lnk"
    CreateShortcut "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism\ImageProcessingClient\Logs" "ImageProcessing Logs.lnk"
    CreateShortcut "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Blue Prism\OcrClient\Logs" "OCR Logs.lnk"
    }


function InteractWindowsAuthChanges ($WAUser, $WAPassword)
    {
    WriteandLog "Configuring Interact for Windows Authentication" Yellow

    $pattern = '[\.\\/]'
    $WAUSerX = $WAUser -replace $pattern, ''

    WriteandLog "Enable ServiceLogonRight for $WAUserX" Yellow
    Add-ServiceLogonRight $WAUserX

    WriteandLog "Setting Service Log On As accounts to $WAUser" Yellow
    foreach ($service in $InteractServices)
    	{
        echo $service
        $ServiceC = Get-WmiObject Win32_Service -Filter "Name='$service'"
        $ServiceC.Change($null,$null,$null,$null,$null,$null,$WAUser,$WAPassword,$null,$null,$null)
    	}

    WriteandLog "Setting Application Pool Identity to $WAUser" Yellow
    Import-Module WebAdministration
    $pools = Get-ChildItem IIS:\AppPools | where { $_.name -Like  "Blue Prism - *"}
    foreach ($pool in $pools)
    	{
    	$pool.processmodel.identityType = 3
    	$pool.processmodel.username = $WAUser
    	$pool.processmodel.password = $WAPassword
	    $pool | Set-Item
	    }

    WriteandLog "Setting Folder Permissions to Full Control for $WAUserX" Yellow

    foreach ($folder in $InteractPermsFolders)
        {
        WriteandLog "Setting Folder $folder" Yellow
        #echo $folder
        $acl = Get-Acl $folder
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($WAUserX,"FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        #echo $AccessRule
        $acl.SetAccessRule($AccessRule)
        $acl | Set-Acl "$folder"
        }

    WriteandLog "Setting Private Keys to Full on BPC Certifcates for $WAUserX" Yellow

    foreach ($bpccert in $bpccerts)
        {
        $filehash = (Get-Childitem cert:\LocalMachine\My | Where-Object { $_.friendlyname -like $bpccert }).Thumbprint
        $CertObj= Get-ChildItem Cert:\LocalMachine\my\$filehash
        $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($CertObj)
        $fileName = $rsaCert.key.UniqueName
        $path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$fileName"
        $permissions = Get-Acl -Path $path
        $rule = new-object security.accesscontrol.filesystemaccessrule $WAUserX, "Full", allow
        $permissions.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $permissions
        }
        
    InteractPostInstallRestart
    #restart app pools
    }

function DecipherWindowsAuthChanges ($WAUser, $WAPassword)
    {
    WriteandLog "Configuring Decipher for Windows Authentication" Yellow

    $pattern = '[\.\\/]'
    $WAUSerX = $WAUser -replace $pattern, ''

    WriteandLog "Enable ServiceLogonRight for $WAUserX" Yellow
    Add-ServiceLogonRight $WAUserX

    WriteandLog "Setting Service Log On As accounts to $WAUser" Yellow
    foreach ($service in $DecipherServices)
    	{
        echo $service
        $ServiceC = Get-WmiObject Win32_Service -Filter "Name='$service'"
        $ServiceC.Change($null,$null,$null,$null,$null,$null,$WAUser,$WAPassword,$null,$null,$null)
    	}
     
    WriteandLog "Setting Application Pool Identity to $WAUser" Yellow
    Import-Module WebAdministration
    $pools = Get-ChildItem IIS:\AppPools | where { $_.name -Like  "Decipher*"}
    foreach ($pool in $pools)
    	{
    	$pool.processmodel.identityType = 3
    	$pool.processmodel.username = $WAUser
    	$pool.processmodel.password = $WAPassword
	    $pool | Set-Item
	    }

    DecipherPostInstallRestart
    
    WriteandLog "Setting Folder Permissions to Full Control for $WAUserX" Yellow
      
    foreach ($folder in $DecipherPermsFolders)
        {
        WriteandLog "Setting Folder $folder" Yellow
        #echo $folder
        $acl = Get-Acl $folder
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($WAUserX,"FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        #echo $AccessRule
        $acl.SetAccessRule($AccessRule)
        $acl | Set-Acl "$folder"
        }
    }


function InteractPostInstallRestart
    {
    WriteandLog "Stopping all Services" Yellow
    foreach ($service in $InteractServices)
    	{
        echo $service
        Stop-Service -Name $service 
    	}

    WriteandLog "Stopping all Application Pools" Yellow
    $pools = Get-ChildItem IIS:\AppPools | where { $_.name -Like  "Blue Prism - *"}
    foreach ($pool in $pools)
        {
        echo $pool.name
        Stop-WebAppPool -Name $pool.name
	    }

    WriteandLog "Restarting IIS" Yellow
    & {iisreset}

    WriteandLog "Starting all Services" Yellow
    foreach ($service in $InteractServices)
    	{
        echo $service
        Start-Service -Name $service 
    	}

    }


function DecipherPostInstallRestart
    {
    if((get-process "BluePrism.Decipher.LicensingService" -ea SilentlyContinue) -eq $Null)
        { 
        WriteandLog "Licensing Service is not running" Yellow
        }
        else
        { 
        WriteandLog "Killing Licensing Service" Yellow
        Stop-Process -Name "BluePrism.Decipher.LicensingService" -Force
        }
        
    WriteandLog "Stopping all Services" Yellow

    foreach ($service in $DecipherServices)
    	{
        echo $service
        Stop-Service -Name $service 
    	}

    WriteandLog "Stopping the Default Web Site" Yellow
    Stop-IISSite "Default Web Site" -Confirm:$false

    WriteandLog "Setting Default Web Site binding to port 81" Yellow
    Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -PropertyName "Port" -Value "81"

    WriteandLog "Starting the Decipher Web Site" Yellow
    Start-IISSite "Decipher"
    
    WriteandLog "Restarting Service Lic -> Server -> Web -> Auto" Yellow

    Start-Service -Name "Decipher Licensing Service"
    WaitUntilServices "Decipher Licensing Service" "Running"
    
    Start-Service -Name "Decipher Server"
    WaitUntilServices "Decipher Server" "Running"

    Start-Service -Name "Decipher Web SDK Service"
    WaitUntilServices "Decipher Web SDK Service" "Running"

    Start-Service -Name "Decipher Automated Client Manager"
    WaitUntilServices "Decipher Automated Client Manager" "Running"
    }


### END OF FUNCTIONS ###

Write-Host "`nPlease answer the following questions. Default answers (just hot Enter) are shown in like this -Y-`n`n" -ForegroundColor Magenta

$DownloadDir = InputQuestion "Please specify a source files directory" "C:\temp"

$Logfile = "$DownloadDir\ScriptedInstall.log"

WriteandLog "S T A R T I N G   N E W   I N S T A L L" White
WriteandLog "=======================================" White

$Global:inifile = "$DownloadDir\ScriptedInstall.ini"

if (-not (Test-Path -Path "$Global:inifile" -PathType Leaf))
    {
    StartupQuestions
    }
    else
    {
    $UsePrevious = InputQuestion "$Global:inifile is present, and has the configuration from the last run. Do you want to use it?" "Y"
    if ($UsePrevious -match "n")
        {
        StartupQuestions
        }
    }

Add-Content -Path $inifile -Value "DownloadDir=$DownloadDir"

$IniContent = Get-Content $Global:inifile

    foreach ($line in $IniContent)
        {
    #    echo $line
        $var = $line.Split('=')
        New-Variable -Name $var[0] -Value $var[1] -Force -Scope Global
        #Echo "setting $var[0] to $var[1]"
        }

$Global:SQLDownloadDir = "$Global:DownloadDir\SQLEXPR_2019"
$Global:InstalledList = "$Global:DownloadDir\InstalledSoftware.txt"

if ($QPQ -match "I")
    {
    WriteandLog "Interact $InteractVersion will be installed" Yellow
    }

if ($QPQ -match "D")
    {
    WriteandLog "Decipher Version $DecipherVersion will be installed" Yellow
    }

if ($QPQ -match "B")
    {
    WriteandLog "BPV7 will be installed" Yellow
    WriteandLog "Apologies - BPV7 install not yet implemented" Yellow
    exit
    }
    
if ($QIISInstall -match "y")
    {
    WriteandLog "IIS will be installed" Yellow
    }
    
if ($QSQLInstall -match "y")
    {
    WriteandLog "SQL Express will be installed" Yellow
    }

if ($QSysadminCurrentUser -match "y")
    {
    WriteandLog "Current User will be added as SQL Express sysadmin" Yellow
    }

if ($QSSMSInstall -match "y")
    {
    WriteandLog "SSMS will be installed" Yellow
    }

if ($Global:QChromeInstall -match "y")
    {
    WriteandLog "Chrome will be installed" Yellow
    }
    
if ($Global:QRMQInstall -eq "Y")
    {
    WriteandLog "RabbitMQ will be installed" Yellow
    }

if ($Global:QRMQCreds -match "n")
    {
    WriteandLog "Custom RMQ user, $Global:RMQUser will be created" Yellow
    }

if ($Global:QRMQCustomDir -match "n")
    {
    WriteandLog "Custom RMQ Data Directory, $Global:RMQCustomDir will be used" Yellow
    }

if ($Global:QRMQCerts -match "y")
    {
    WriteandLog "Certificate will be created using suffix $Global:QHostSuffix and Friendly Name $Global:QCertFriendlyName" Yellow
    }

if ($Global:QWA -match "y")
    {
    WriteandLog "Windows Authentication will be configured for $Global:WAUser" Yellow
    WriteandLog "PLEASE ENSURE $Global:WAUser HAS SYSADMIN ACCESS TO YOUR DATABASES" Red
    }

WriteandLog "File Download Directory will be: $Global:DownloadDir" Yellow

Write-Host "Is everything correct, and are you ready to proceed?" -NoNewline
Write-Host " [Y]" -ForegroundColor Green -NoNewline
Write-Host "\" -NoNewline
Write-Host "[N]" -ForegroundColor Red

$input = Read-Host
while("Y","N" -notcontains $input)       
    {
    $input = Read-Host "Please answer Yes (Y) or No (N)."
    }
if ($input -ne "Y")
    {
    exit
    }


# Decipher Install procedure

if ($QPQ -match "D")
    {
    WriteandLog "Starting Decipher $DecipherVersion install" Green
    WriteandLog "=========================" Green
    InstallNetFWK472
    if ($Global:QIISInstall -match "y")
        {
        InstallIIS
        }
    if ($QSQLInstall -match "y")
        {
        InstallSQL
        }
    if ($QSSMSInstall -match "y")
        {
        InstallSMSS
        }
    if ($Global:QRMQInstall -match "y")
        {
        InstallErlang
        InstallRMQ
        RMQConfig $ErlangHome $RMQsbin $Global:RMQCustomDir $Global:RMQUser $Global:RMQPwordPlain
        }
    if ($Global:QChromeInstall -match "y")
        {
        InstallChrome
        }
    
    Write-Host "All prerequisites should be complete are you ready to install Decipher $DecipherVersion?" -NoNewline -ForegroundColor Green
    Write-Host " [Y]" -ForegroundColor Green -NoNewline
    Write-Host "\" -NoNewline
    Write-Host "[N]" -ForegroundColor Red
    
    $input = Read-Host
    while("Y","N" -notcontains $input)       
        {
        $input = Read-Host "Please answer Yes (Y) or No (N)."
        }
    if ($input -ne "Y")
        {
        exit
        }
        
    WriteandLog "Starting the Decipher Licensing Service Installation..." Green
    CheckInstalled $DecipherLicensingServiceInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$DecipherLicensingServiceInstallFile" -Wait
        }
    
    WriteandLog "Starting the Decipher Server installation..." Green
    CheckInstalled $DecipherServerInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$DecipherServerInstallFile" -Wait
        }

    WriteandLog "Starting the Decipher Web Client installation..." Green
    CheckInstalled $DecipherWebClientInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$DecipherWebClientInstallFile" -Wait
        }

    WriteandLog "Starting the Decipher Automated Client installation..." Green
    CheckInstalled $DecipherAutomantedClientInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$DecipherAutomantedClientInstallFile" -Wait
        }

    WriteandLog "Starting the Decipher Server Plugin installation..." Green
    CheckInstalled $DecipherServerPluginMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$DecipherServerPluginFile" -Wait
        }

    if ($Global:QWA -match "y")
        {
        $ReadytoWA = InputQuestion "Is Windows Authentication ready to be configured? ($Global:WAUser should have db_owner access to the newly created database)" "Y"
        if ($ReadytoWA -match "y")
            {
            DecipherWindowsAuthChanges $Global:WAUser $Global:WAPwordPlain    
            }
            else
            {
            WriteandLog "Ensure $Global:WAUser has been configured prior to re-runnng the script" Red
            exit
            }
        }
    
    DecipherShortcuts
    
    WriteandLog "Decipher Installation completed!!!" Green
       
    CheckInstalled $ChromeInstallMarker
    if ($Global:InstallCheck -ne $null)
        {
        Start-process "C:\Program Files\Google\Chrome\Application\chrome.exe" "http://localhost:80"
        }
    }

    
# Interact Install procedure    

if ($QPQ -match "I")
    {
    WriteandLog "Starting Interact $InteractVersion install" Green
    WriteandLog "=========================" Green
    InstallNetFWK472
    if ($Global:QIISInstall -match "y")
        {
        InstallIIS
        }
    InstallHubInteractPreReqs
    if ($QSQLInstall -match "y")
        {
        InstallSQL
        }
    if ($QSSMSInstall -match "y")
        {
        InstallSMSS
        }
    if ($Global:QRMQInstall -match "y")
        {
        InstallErlang
        InstallRMQ
        RMQConfig $ErlangHome $RMQsbin $Global:RMQCustomDir $Global:RMQUser $Global:RMQPwordPlain
        }
    if ($Global:QRMQCerts -match "y")
        {
        CreateCerts $InteractWebsites $Global:QCertFriendlyName $Global:QHostSuffix
        }
    
    if ($Global:QChromeInstall -match "y")
        {
        InstallChrome
        }

    WriteandLog "Starting the Hub installation..." Green
    CheckInstalled $HubInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$HubInstallFile" -Wait
        }

    
    WriteandLog "Starting the Interact installation..." Green
    CheckInstalled $InteractInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        Start-process "$Global:DownloadDir\$InteractInstallFile" -Wait
        }


    if ($Global:QWA -match "y")
        {
        $ReadytoWA = InputQuestion "Is Windows Authentication ready to be configured? ($Global:WAUser should have db_owner access to the newly created databases)" "Y"
        if ($ReadytoWA -match "y")
            {
            InteractWindowsAuthChanges $Global:WAUser $Global:WAPwordPlain    
            }
            else
            {
            WriteandLog "Ensure $Global:WAUser has been configured prior to re-runnng the script" Red
            exit
            }
        }
    
    InteractShortcuts

    $CurentUserDesktop = [Environment]::GetFolderPath("Desktop")
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    wget $RestartScriptUrl -outfile $CurentUserDesktop\$RestartScriptFile
    
    WriteandLog "Interact Installation completed!!!" Green
    
    CheckInstalled $ChromeInstallMarker
    if ($Global:InstallCheck -ne $null)
        {
        Start-process "C:\Program Files\Google\Chrome\Application\chrome.exe" "https://authentication$Global:QHostSuffix"
        }
            
    }

set-location $DownloadDir


if ((Test-Path -Path "$Global:inifile" -PathType Leaf))
    {
    $IniFileCleanup = InputQuestion "If everything installed as expected, then shall we delete your ini file now? (it may contain passwords)" "Y"
    if ($IniFileCleanup -match "y")
        {
        Remove-Item $Global:inifile
        }
    }
    