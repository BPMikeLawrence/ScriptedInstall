Import-Module WebAdministration
$InteractServices = "Blue Prism - Audit Service Listener", "Blue Prism - Log Service", "Blue Prism - Submit Form Manager"


Write-Host "Stopping all Application Pools"
$pools = Get-ChildItem IIS:\AppPools | where { $_.name -Like  "Blue Prism - *"}
foreach ($pool in $pools)
	{
	echo $pool.name
	Stop-WebAppPool -Name $pool.name
	}

Write-Host "Restarting IIS"
    & {iisreset}

Write-Host "Restarting all Services"
foreach ($service in $InteractServices)
	{
	echo $service
	Start-Service -Name $service 
	}