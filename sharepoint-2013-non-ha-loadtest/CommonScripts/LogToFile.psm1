function CreateLogFile
{
	param(
		[String]$logFolderName = "CustomScriptExtensionLogs",
		[String]$logFileName = "CustomScriptExtension.log"
	)
	# Create log file
	$logFolderPath = Join-Path $env:SystemDrive $logFolderName
	if(-not(Test-Path $logFolderPath))
	{
		New-Item $logFolderPath -ItemType directory	
	}
	$logFilePath = Join-Path $logFolderPath $logFileName
	if(-not(Test-Path $logFilePath))
	{
		New-Item $logFilePath -ItemType file	
	}
}

function LogToFile
{
   param (
		[parameter(Mandatory = $true)]
		[String]$Message,
		[String]$LogFilePath = "$env:SystemDrive\CustomScriptExtensionLogs\CustomScriptExtension.log"
   )
   $timestamp = Get-Date -Format s
   $logLine = "[$($timestamp)] $($Message)"
   Add-Content $LogFilePath -value $logLine
}
Export-ModuleMember -Function CreateLogFile
Export-ModuleMember -Function LogToFile
