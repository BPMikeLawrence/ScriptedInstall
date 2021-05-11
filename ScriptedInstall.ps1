#Write-Host "Please answer all questions Yes (Y) or No (N). Hitting enter defaults to Y"


#Get-WindowsFeature -Name Web-Server
#Get-WindowsFeature -Name XPS-Viewer
#$checkfeature = Get-WindowsFeature -Name Web-Server
#$checkfeature = Get-WindowsFeature -Name XPS-Viewer

#$checkfeature = Invoke-Command -ScriptBlock{Get-WindowsFeature Web-Server,XPS-Viewer}




$DownloadDir = "C:\temp"
$SQLDownloadDir = "$DownloadDir\SQLEXPR_2019"
$InstalledList = "$DownloadDir\InstalledSoftware.txt"

$NetFWKFile = "NDP472-KB4054531-Web.exe"
$NetFWKUrl = "https://download.microsoft.com/download/0/5/C/05C1EC0E-D5EE-463B-BFE3-9311376A6809/NDP472-KB4054531-Web.exe"

$SQLExpressFile = "SQL2019-SSEI-Expr.exe"
$SQLExpressUrl = "https://go.microsoft.com/fwlink/?linkid=866658"
$SQLInstallMarker = "Browser for SQL Server 2019"

$SSMSFile = "SSMS-Setup-ENU.exe"
$SSMSUrl = "https://aka.ms/ssmsfullsetup"
$SSMSInstallMarker = "Microsoft SQL Server Management Studio - 18.9.1"

$ChromeFile = "ChromeStandaloneSetup64.exe"
$ChromeUrl = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B9B042D81-4049-E06D-2587-CC2F8DC642F9%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe"
$ChromeInstallMarker = "Google Chrome"

$ErlangFile = "otp_win64_23.0.1.exe"
$ErlangUrl = "https://github.com/erlang/otp/releases/download/OTP-23.0.1/otp_win64_23.0.1.exe"
$ErlangInstallMarker = "Erlang OTP 23.0.1"

$RMQFile = "rabbitmq-server-3.8.5.exe"
$RMQurl = "https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.8.5/rabbitmq-server-3.8.5.exe"
$RMQInstallMarker = "RabbitMQ Server 3.8.5"

$ErlangHome = "C:\Program Files\erl-23.0.1"
$RMQsbin = "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.8.5\sbin"

$InteractWebsites = $env:computername, "ims.hostname","Hub.hostname","email.hostname","audit.hostname","file.hostname","signalr.hostname","notification.hostname","license.hostname","interact.hostname","iada.hostname","interactremoteapi.hostname"

### FUNCTIONS ###

function StartupQuestions
    {
    Write-Host "Y\N questions default to Y if left unanswered"
    $QPQ = ProductQuestion "Are you installing Interact (I), Decipher (D) or Blue Prism V7 (B)?"
    $QIISInstall = InputQuestion "Do you want IIS Installing?" "Y"
    $QSQLInstall = InputQuestion "Do you want SQL Express Installing?" "Y"
    $QSSMSInstall = InputQuestion "Do you want SQL Server Management Studio Installing?" "Y"
    $QChromeInstall = InputQuestion "Do you want Chrome Installing?" "Y"
    $QRMQCreds = InputQuestion "Use standard guest\guest RMQ account? (Or use custom credentials?)" "Y"
    if ($QRMQCreds -ne "Y")
        {
        DefineRMQCreds
        }
    if ($QPQ -ne "D")
        {
        $QRMQCerts = InputQuestion "Create Self-Signed Certificate?" "Y"
        }
    if ($QRMQCerts = "Y")
        {
        $Global:QHostSuffix = InputQuestion "Choose a suffix for your web sites \ applications " ".local"
        }

    $DownloadDir = InputQuestion "Download dir?" "C:\temp"
    }


function DefineRMQCreds
    {
    #$RMQCredCustom = True
    $Global:RMQUser = Read-Host "Enter RabbitMQ custom Username"
    $RMQPword = Read-Host -AsSecureString "Enter RabbitMQ custom Password"
    
    #$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Global:RMQPword)
    #$Global:RMQPword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)


    $Global:RMQPwordPlain =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($RMQPword))
    Write-Host "Your password is : $Global:RMQPwordPlain" -ForegroundColor Yellow

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


function CheckAndDownload($file, $url, $DownloadDir)
    {
    if (-not (Test-Path -Path "$DownloadDir\$file" -PathType Leaf))
        {
        Write-Host "Downloading $file"
        wget $url -outfile $DownloadDir\$file
        }
        else
        {
        Write-Host "$file already present in $DownloadDir"
        }
    }


function InstallChrome
    {
    $dl = CheckAndDownload $ChromeFile $ChromeUrl $DownloadDir
    Start-process "$DownloadDir\$Chromefile" "/silent /install" -Wait:$true -Passthru
    }


function InstallIIS
    {
    write-host "Installing IIS"
    Write-Host "Note! This may take some time. If the windows modules installer worker is still running, let it be" -ForegroundColor Yellow
    Install-WindowsFeature -Name Web-Mgmt-Console, Web-Net-Ext, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content -computerName localhost -Restart
    #! write out 
    }


function InstallSQL
    {
    CheckInstalled $SQLInstallMarker
    $dl = CheckAndDownload $SQLExpressFile $SQLExpressUrl $DownloadDir
    Set-Location $DownloadDir
    Start-process "$DownloadDir\$SQLExpressFile" "/ACTION=Download MEDIAPATH=$DownloadDir /MEDIATYPE=Core /QUIET" -Wait:$true -Passthru
    Start-process "$DownloadDir\SQLEXPR_x64_ENU.exe" "/q /x:$SQLDownloadDir" -Wait:$true -Passthru
    #!FIGURE OUT A WAY TO GET THIS CONFIG FILE DONE#
    Set-Location $SQLDownloadDir
    Start-process "Setup.exe" "/ConfigurationFile=ConfigurationFile.ini" -Wait:$true -Passthru
    }


function InstallSMSS
    {
    CheckInstalled $SSMSInstallMarker
    $dl = CheckAndDownload $SSMSFile $SSMSUrl $DownloadDir
    Set-Location $DownloadDir
    Start-process "$DownloadDir\$SSMSFile" "/Passive -wait" -Wait:$true -Passthru
    }


function InstallNetFWK472
    {
    $dl = CheckAndDownload $NetFWKFile $NetFWKUrl $DownloadDir
    Set-Location $DownloadDir
    try 
        {
        #$result = Start-process "$DownloadDir\NDP472-KB4054531-Web.exe" "/Passive -wait" -Wait:$true -Passthru
        }
    catch 
        {
        write-host "something went wrong"
        }
    write-host $?
    write-host $LASTEXITCODE
    }



function InstallErlang
    {
    CheckInstalled $ErlangInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $dl = CheckAndDownload $ErlangFile $ErlangUrl $DownloadDir
        write-host "Installing Erlang"
        Start-Process "$DownloadDir\$ErlangFile" "/S" -Wait:$true -Passthru
        }
    }

function InstallRMQ
    {
    CheckInstalled $RMQInstallMarker
    if ($Global:InstallCheck -eq $null)
        {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $dl = CheckAndDownload $RMQFile $RMQUrl $DownloadDir
        write-host "Installing RabbitMQ"
        Start-Process "$DownloadDir\$RMQFile" "/S" -Wait:$true -Passthru
        }
    }


function CheckInstalled ($Software)
    {
    $Global:InstallCheck = $null
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > $InstalledList
    $Global:InstallCheck  = Select-String -Path $InstalledList -Pattern $Software
### write-host "IC CI - $InstallCheck"
    if ($InstallCheck -ne $null)
        {
        write-host "$Software is Installed" -ForegroundColor Green
        }
        else
        {
        write-host "$Software is not Installed" -ForegroundColor Yellow
        }
    }
    

function RMQConfig ($ErlangHome, $RMQsbin, $RMQCustomUser, $RMQCustomPword)
    {
    set-location Env:
    New-Item -Path Env:\ERLANG_HOME -Value $ErlangHome
    ###get-childitem
    set-location $RMQsbin
    .\rabbitmq-plugins enable rabbitmq_management
    if ($Global:RMQUser -ne $null)
        {
        ###write-host "user $Global:RMQUser pword $Global:RMQPwordPlain"
        .\rabbitmqctl add_user $Global:RMQUser $Global:RMQPwordPlain
        .\rabbitmqctl set_user_tags $Global:RMQUser administrator
        .\rabbitmqctl set_permissions -p / $Global:RMQUser ".*" ".*" ".*"
        }
    }

function CreateCerts ($Websites, $CertFriendlyName)
    {
    #$dnsnames = $Websites
    #$dnsnames = $dnsnames.Replace(".hostname",".local")

    $dnsnames = $Websites.Replace(".hostname",".local")

    write-host "New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $dnsnames -FriendlyName $CertFriendlyName -NotAfter (Get-Date).AddYears(10)"

    $Cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $dnsnames -FriendlyName $CertFriendlyName -NotAfter (Get-Date).AddYears(10)

       
    #$filehash = (Get-Childitem cert:\LocalMachine\My | Where-Object { $_.subject -like '*ML-V7*' }).Thumbprint
    #Export-Certificate -Cert (Get-Item Cert:\LocalMachine\My\$filehash) -FilePath c:\temp\mycert.cert
    #Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath c:\temp\mycert.cert
    #(Get-ChildItem -Path Cert:\LocalMachine\Root\$filehash).FriendlyName = 'Hub-InteractSSCertificate-Root'
    
    }

### END OF FUNCTIONS ###


$Global:QHostSuffix = ".local"

#StartupQuestions
CreateCerts $InteractWebsites TestCert


exit




#Invoke-WebRequest --user "BPMikeLawrence" --password "Pil0t025!" https://portal.blueprism.com/system/files/2021-03/BluePrism6.10.1_x64.msi" -outfile "$DownloadDir\BluePrism6.10.1_x64.msi
#$Credentials = Get-Credential
#Invoke-WebRequest -Uri "https://www.contoso.com" -OutFile "C:\path\file" -Credential $Credentials


#wget --user='BPMikeLawrence' --ask-password https://portal.blueprism.com/system/files/2021-03/BluePrism6.10.1_x64.msi -outfile "$DownloadDir\BluePrism6.10.1_x64.msi


#This 403's
#$uri  = 'https://portal.blueprism.com/system/files/2021-03/BluePrism6.10.1_x64.msi'
#$user = 'BPMikeLawrence'
#$pass = 'Pil0t025!' | ConvertTo-SecureString -AsPlainText -Force
#$cred = New-Object Management.Automation.PSCredential ($user, $pass)
#Invoke-WebRequest -Uri $uri -Credential $cred



#$Uri = "https://portal.blueprism.com/system/files/2021-03/BluePrism6.10.1_x64.msi"
#$Username = "BPMikeLawrence"
#$Password = "Pil0t025!"
#$Headers = @{ Authorization = "Basic {0}" -f [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $Username,$Password))) }
#curl -Uri $Uri -Headers $Headers




#RMQConfig $ErlangHome $RMQsbin $Global:RMQUser $Global:RMQPword

#InstallErlang
#InstallRMQ

#DefineRMQCreds


#Decipher
#InstallNetFWK472
#2 installIIS
#3 InstallSQL
#4 InstallSMSS
#5 install BP
#6 install licences 
#7 copy dll over for Decipher.
#8 lic man
#kinda works: $result = msiexec.exe /i "C:\temp\Decipher Licensing Service.msi" /QN /L*V "C:\Temp\msilog.log" RMQ_PORT=5672
#. kill lic service. start lic service, start server post install.
#! BluePrism.Decipher.LicensingService procname
#! decipher switch default websites around, stop default, start decipher.

 
















if ($QPQ -match "I")
    {
    Write-Host "Interact will be installed"
    }

if ($QPQ -match "D")
    {
    Write-Host "Decipher will be installed"
    }

if ($QPQ -match "B")
    {
    Write-Host "BPV7 will be installed"
    }


if ($QSQLInstall -match "y")
    {
    Write-Host "SQL Express will be installed"
    }

if ($QSSMSInstall -match "y")
    {
    Write-Host "SSMS will be installed"
    }

if ($QChromeInstall -match "y")
    {
    Write-Host "Chrome will be installed"
    }



Write-Host "File Download Directory will be: $DownloadDir"

$ReadyToGo = InputQuestion "Is everything correct, and are you ready to proceed?" "Y"
if ($ReadyToGo -notcontains "Y")
    {
    exit
    }


