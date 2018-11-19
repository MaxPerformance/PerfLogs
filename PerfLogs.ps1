#// PerfLogs.ps1 v 1.0
#// Written by Claus Søgaard (cso@maxperformance.dk)
#// 
#//  ChangeLogs
#//  25-08-2010: Perflogs.ps1 v 0.1 Release date
#//  31-08-2010: v 0.1:  		Added functionality - Choose between different servertypes - SystemOvervies, IIS, BizTalk, ActiveDirectory. 
#//  08-11-2010: v 0.2:  		Code cleanup and changed how the date and time is parsed.
#//  15-12-2010: v 0.3:  		Added functionality - It is now possible to enter a start date and time when to start the performance counters. 
#//  23-12-2010: v 0.4:  		Edit - Gets the XML files in path $scriptPath and adds this to the menu.
#//                      		Code Cleanup
#//  29-12-2010  v 0.5:	 		Added functionality for multi domain use
#//                      		Encryptet password for all environments.
#//                      		Changed how number of processors were found.
#//  03-01-2011  v 0.6:	 		Due to different locale in server images, sometimes the scheduler would switch day and month when logman created
#//                      		the Data Collection.  This is fixed where the management server is controlling the scheduler via task scheduler.
#//  10-01-2011  v 0.7   		Added support for SQL server.
#//  16-08-2011  v 0.7.1		BUGFIX: logman query is gives a different result when query 2003 and 2008 servers remotely. Implemented PSEXEC to 
#// 												do the query local on the server wich returns file information on 2003 server.
#//  09-09-2011  v 0.8	 		Possible to select another account to run the context in from the GUI
#//  15-03-2012  v 0.81			Added functionality to automatic calculate the sample interval.
#//  06-08-2012  v 0.90			Added support for running old performance logfiles
#//  03-10-2012  v 1.00			Using PS-Sessions when enabled on remote server
#//													Job will be written to a queue to be processed by PAL (using PalQueueWatcher.PS1 to monitor the queue)
#//													Enables PS-Remoting on remote server is its not allready enabled. This is only on windows 2008 and newer servers.
#//  
#//  TODO
#//  - Help/about Tab
#//
#//	 - KNOWN BUGS:
#//  
#//
#//
#//  IMPORTANT: 
#//  1: When a new release of PAL.PS1 is released, then mark out the line where OpenHtmlReport is being called.  This is almost at the bottom of the script.
#//     Otherwise lots of iexplorer.exe processes will be spawned and never shut down.
#//  2: PSExec.exe (Sysinternals) must be located in the same directory as this script. 
#//  3: set HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa disabledomaincreds = 0 on the server running PAL.
#//  
#///////////////////////////////////////////////////////////////////////////////////////////////////////////////  


Import-Module .\PowershellZip.dll
#region CONSTANTS
$domain=get-item env:userdomain | %{$_.value}
$ScriptPath="C:\Mandatory\PAL"

$config = Import-Clixml -Path "$ScriptPath\perflogs.xml"

$user= $config.user
$OutputPath = $config.OutputPath
$OldLogPath = $config.OldLogPath
$pwdStr = $config.pwdStr
$pwd = $pwdStr | convertTo-securestring -Key (1..16)
$global:cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user ,$pwd
$global:PALQueueFilePath = $config.PALQueueFilePath
$samples = $config.samples
$erroractionpreference = "SilentlyContinue"
#$DebugPreference = "Continue"

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

if (!(test-path $ScriptPath\temp))
{
  New-Item $ScriptPath\temp -ItemType directory
}

#ENDregion CONSTANTS




########################################################################################################
#
# 											FUNCTIONS
#
########################################################################################################

#region Enable-RemotePSRemoting
Function Enable-RemotePSRemoting
{
	<#
	.SYNOPSIS
	 
	Enables PowerShell Remoting on a remote computer. Requires that the machine
	responds to WMI requests, and that its operating system is Windows Vista or
	later.
	 
	.EXAMPLE
	 
	Enable-RemotePsRemoting <Computer>
	 
	#>
	 
	param(
	    ## The computer on which to enable remoting
	    $Computername

	)
	 
	Set-StrictMode -Version Latest
	$VerbosePreference = "SilentlyContinue"
	 
	$script = @"
`$log = Join-Path `$env:TEMP Enable-RemotePsRemoting.output.txt
Remove-Item -Force `$log -ErrorAction SilentlyContinue
Start-Transcript -Path `$log 
## Create a task that will run with full network privileges.
## In this task, we call Enable-PsRemoting
schtasks /CREATE /TN 'Enable Remoting' /SC WEEKLY /RL HIGHEST /TR "powershell -noprofile -command Enable-PsRemoting -Force" /F |
Out-String
schtasks /RUN /TN 'Enable Remoting' | Out-String
## Wait for the remoting changes to come into effect
for(`$count = 1; `$count -le 10; `$count++){
`$output = Invoke-Command localhost { 1 } -ErrorAction SilentlyContinue
if(`$output -eq 1) { break; }
"Attempt `$count : Not ready yet."
Sleep 5
} 
## Delete the temporary task
schtasks /DELETE /TN 'Enable Remoting' /F | Out-String
Stop-Transcript 
"@

	$commandBytes = [System.Text.Encoding]::Unicode.GetBytes($script)
	$encoded = [Convert]::ToBase64String($commandBytes)
	 
	Write-Verbose "Configuring $computername"
	$command = "powershell -NoProfile -EncodedCommand $encoded"
	#$null = Invoke-WmiMethod -Computer $computername -Credential $credential Win32_Process Create -Args $command
	$null = Invoke-WmiMethod -Computer $computername Win32_Process Create -Args $command
	 
	Write-Verbose "Testing connection"
	Invoke-Command $computername {Get-WmiObject Win32_ComputerSystem } 
}
 #endregion Enable-RemotePSRemoting
 
#region WriteSplashScreen
Function WriteSplashScreen
{
$splash = @"
`n`n
	Perflogs by Claus Søgaard 2012. `n`n 
	
	Check following path for report shortly after collection is done:
			$OutputPath
			`n`n
			
"@

	$splash

}
#endregion WriteSplashScreen

#region isSQL
########################################################################################################
# Function:    isSQL
#
# Parameters:  $computer
#                                         
# Return:      
#
# Purpose:     Modifies / creates the Data Collector input file.
#              
# Changes History: 
#                  
#
########################################################################################################
Function isSQL ($computer, $CounterType)
{
  Write-Debug "Function isSQL ($computer, $CounterType"
  if(Test-Path SQLCollection.txt)
  {
    Remove-Item SQLCollection.txt
  }
  $reg=[Microsoft.win32.registrykey]::OpenRemoteBaseKey("LocalMachine",$computer)
  $regKey=$reg.OpenSubKey("Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")
  $instances=$regkey.getvaluenames()
  #$instances="DB01","DB02","DB03"  #For testing purposes
  if($instances -ne $null)
  {
    foreach($instance in $instances)
    { 
  	  $Counters = @("\MSSQL`$$instance`:Access Methods\Forwarded Records/sec",
      "\MSSQL`$$instance`:Access Methods\FreeSpace Scans/sec",
			"\MSSQL`$$instance`:Access Methods\Full Scans/sec",
			"\MSSQL`$$instance`:Access Methods\Index Searches/sec",
			"\MSSQL`$$instance`:Access Methods\Page Splits/sec",
			"\MSSQL`$$instance`:Access Methods\Scan Point Revalidations/sec",
			"\MSSQL`$$instance`:Access Methods\Workfiles Created/sec",
			"\MSSQL`$$instance`:Access Methods\Worktables Created/sec",
			"\MSSQL`$$instance`:Buffer Manager\Buffer cache hit ratio",
			"\MSSQL`$$instance`:Buffer Manager\Checkpoint pages/sec",
			"\MSSQL`$$instance`:Buffer Manager\Free pages",
			"\MSSQL`$$instance`:Buffer Manager\Lazy writes/sec",
			"\MSSQL`$$instance`:Buffer Manager\Page life expectancy",
			"\MSSQL`$$instance`:Buffer Manager\Page lookups/sec",
			"\MSSQL`$$instance`:Buffer Manager\Page reads/sec",
			"\MSSQL`$$instance`:Buffer Manager\Page writes/sec",
			"\MSSQL`$$instance`:General Statistics\Logins/sec",
			"\MSSQL`$$instance`:General Statistics\Logouts/sec",
			"\MSSQL`$$instance`:General Statistics\User Connections",
			"\MSSQL`$$instance`:Latches\Latch Waits/sec",
			"\MSSQL`$$instance`:Latches\Total Latch Wait Time (ms)",
			"\MSSQL`$$instance`:Locks(*)\Lock Requests/sec",
			"\MSSQL`$$instance`:Locks(*)\Lock Timeouts/sec",
			"\MSSQL`$$instance`:Locks(*)\Lock Wait Time (ms)",
			"\MSSQL`$$instance`:Locks(*)\Lock Waits/sec",
			"\MSSQL`$$instance`:Locks(*)\Number of Deadlocks/sec",
			"\MSSQL`$$instance`:Memory Manager\Memory Grants Pending",
			"\MSSQL`$$instance`:Memory Manager\Target Server Memory(KB)",
			"\MSSQL`$$instance`:Memory Manager\Total Server Memory (KB)",
			"\MSSQL`$$instance`:SQL Statistics\Batch Requests/sec",
			"\MSSQL`$$instance`:SQL Statistics\SQL Compilations/sec",
			"\MSSQL`$$instance`:SQL Statistics\SQL Re-Compilations/sec")
      foreach ($counter in $Counters)
		  {
		    Add-Content sqlCollection.txt -Value $Counter
		  }
    } 
  }
  Get-Content $CounterType".txt" | Add-Content SQLCollection.txt
}
#endregion isSQL

#region is64bit
Function is64bit($computer)
{
	$CPUAdrSpace=(Get-WmiObject win32_processor -computer $computer | select-object AddressWidth -unique).AddressWidth
  if($CPUAdrSpace -eq "64")
  {
   return $true
  } 
  ELSE
  {
    return $false
  }
}
#endregion is64bit

#region GetNumberOfProcessors
function GetNumberOfProcessors 
{
    param ($server)
    $processors = get-wmiobject -computername $server win32_processor

    if (@($processors)[0].NumberOfCores)
    {
        $cores = @($processors).count * @($processors)[0].NumberOfCores
    }
    else
    {
        $cores = @($processors).count
    }
    Return $cores
} 

#endregion GetNumberOfProcessors

#region GetTotalAmountOfRam
Function GetTotalAmountOfRam ($computer)
{
	$RamAry=Get-WmiObject CIM_PhysicalMemory -computer $computer | select-object Capacity
  foreach($RamBlock in $RamAry)
  { 
    $TotalRam += $ramblock.Capacity
  }
	return ($totalRam/1GB)
}
#endregion GetTotalAmountOfRam

#region Test-PsRemoting 
function Test-PsRemoting 
{ 
    param( 
        [Parameter(Mandatory = $true)] 
        $computername 
    ) 
    try 
    { 
        $errorActionPreference = "Stop" 
        $result = Invoke-Command -ComputerName $computername { 1 } 
    } 
    catch 
    { 
        Write-Verbose $_ 
        return $false 
    } 

    if($result -ne 1) 
    { 
        Write-Verbose "Remoting to $computerName returned an unexpected result." 
        return $false 
    } 
    $true    
} 
#endregion Test-PsRemoting 

#region ConnectPSRemoting

Function ConnectPSRemoting($computer)
{
	$session = New-PSSession $computer
	return $session
}

#endregion ConnectPSRemoting

#region PSEXEC
Function PSEXEC($computer,$strCommand)
{
	#$result = start-process -filepath C:\Mandatory\PsExec.exe -ArgumentList "\\$computer cmd /c $strCommand" -Wait

	$cmd = "C:\Mandatory\PsExec.exe \\$computer cmd /c $strCommand"
	$result = Invoke-Expression -command $cmd
	return $result
}

#endregion PSEXEC

#region GetNextBLGLOGNumber
Function GetNextBLGLOGNumber($computer)
{
	
	$query = "LOGMAN QUERY $CounterType"+"_"+$Computer
	if($global:isRemotingEnabled)
	{
		$blglog = Invoke-Command -Session $session -ScriptBlock {param($qu);invoke-expression -command $qu} -ArgumentList $query
	}
	ELSE
	{
		$blglog = PSEXEC $computer $query
	}
		
	if ($blglog.length -eq 3) #No collection found
  {
    $blglog=$logname+"_000001.blg"
		Write-Debug "LOGMAN returned no results. Starting new collection"
		return $blglog
  }
  else
  {
		$OutputString = $blglog | select-string ".blg"
		if($OutputString -ne $null)
		{
			$OutputString = $OutputString.tostring()
			$blgSplit=$OutputString.split(" ")
			$blgpath=$blgSplit[$blgSplit.length-1]
			$blgpathSplit=$blgpath.split("\")
			$blglog=$blgPathSplit[$blgpathSplit.length-1]
		}
		ELSE
		{
		  $blglog=$logname+"_000000.blg"
		}
    # Since the counter is not created at this time, we have to increment the counter number manually here. But only on windows 2008+ systems since 2003 shows the next counterlog filename.
		if((get-WmiObject win32_operatingsystem -computername $computer).version.substring(0,1) -eq "6")
		{
    	$blglog = $blglog.replace(($blglog.substring($blglog.length-5,1)+"."),([int]($blglog.substring($blglog.length-5,1))+1).tostring()+".")
		}
  }
	return $blglog
}
#endregion GetNextBLGLOGNumber

#region Create-CMDFile
########################################################################################################
# Function:    Create-CMDFile
#
# Parameters:  $computer, $logname, $CounterType
#                                         
# Return:      
#
# Purpose:     Creates the CMD file that will be run by Task Scheduler
#              
# Changes History: 
#                  
#
########################################################################################################
Function Create-CMDFile($computer, $logname, $CounterType)
{ 
  Write-Debug "Function Create-CMDFile($computer, $logname, $CounterType) "
  $is64bit = is64bit $computer
	$Processors = GetNumberOfProcessors $computer
	$totalGb = GetTotalAmountOfRam $computer
	$blglog = GetNextBLGLOGNumber $computer 
	
  # This CMD File will be started by Task Scheduler
  "SCHTASKS /DELETE /TN $Logname /F" | Out-File "$scriptPath\Temp\$CounterType-$computer.cmd" -append -Encoding Default
  "cd $scriptPath" | Out-File "$scriptPath\Temp\startpal-$CounterType-$computer.ps1" -Encoding Default
  '"' + "cd $ScriptPath;.{.\PAL.ps1 -Log '\\$computer\c$\Perflogs\$blglog' -ThresholdFile '$scriptPath\$CounterType.xml' -Interval 'AUTO' -IsOutputHtml $True -HtmlOutputFileName '[LogFileName]_PAL_ANALYSIS_[DateTimeStamp].htm' -IsOutputXml $False -AllCounterStats $True -OutputDir $OutputDir -NumberOfProcessors $Processors -ThreeGBSwitch $False -SixtyFourBit $is64bit -TotalMemory $totalGb}" + '"' + " | Out-File '$global:PALQueueFilePath\QueueIn.txt' -append -Encoding Default" | Out-File "$scriptPath\Temp\startpal-$CounterType-$computer.ps1" -append -Encoding Default
	'"' + "cd $ScriptPath;.{.\PAL.ps1 -Log '\\$computer\c$\Perflogs\$blglog' -ThresholdFile '$scriptPath\$CounterType.xml' -Interval 'AUTO' -IsOutputHtml $True -HtmlOutputFileName '[LogFileName]_PAL_ANALYSIS_[DateTimeStamp].htm' -IsOutputXml $False -AllCounterStats $True -OutputDir $OutputDir -NumberOfProcessors $Processors -ThreeGBSwitch $False -SixtyFourBit $is64bit -TotalMemory $totalGb}" + '"' + " | Out-File '$global:PALQueueFilePath\PalLog.txt' -append -Encoding Default" | Out-File "$scriptPath\Temp\startpal-$CounterType-$computer.ps1" -append -Encoding Default
  if($global:BuildReport -eq $true)
	{

	}
  # This file is starting Data Collection on remote server
  "logman start -name $logname -s $computer" | Out-File "$scriptPath\Temp\StartDataCollection_$CounterType-$computer.cmd" -Encoding Default

  # This file will stop Data Collection on remote server and start up PAL for analysis.
  "logman stop -name $logname -s $computer" | Out-File "$scriptPath\Temp\StopDataCollection_$CounterType-$computer.cmd" -Encoding Default
  "powershell $scriptPath\Temp\startpal-$CounterType-$computer.ps1" | Out-File "$scriptPath\Temp\StopDataCollection_$CounterType-$computer.cmd" -append -Encoding Default
  "SCHTASKS /DELETE /TN StartDataCollection_$logname /F"  | Out-File "$scriptPath\Temp\StopDataCollection_$CounterType-$computer.cmd" -append -Encoding Default
  "SCHTASKS /DELETE /TN StopDataCollection_$logname /F" | Out-File "$scriptPath\Temp\StopDataCollection_$CounterType-$computer.cmd" -append -Encoding Default
}

#endregion Create-CMDFile

#region Remove-OldCMDFiles
########################################################################################################
# Function:    Remove-OldCMDFiles
#
# Parameters:  None
#                                         
# Return:      Void
#
# Purpose:     Remove old CMD Files previously used.
#			   NOT YET ACTIVE
#              
# Changes History: 
#                  
#
########################################################################################################
Function Remove-OldCMDFiles($computer)
{
  Write-Debug "Function Remove-OldCMDFiles"
	Get-ChildItem \\$computer\c$\PerfLogs | where {$_.extension -eq ".blg"} | remove-item
	
}
#endregion Remove-OldCMDFiles

#region DeletePerfLogs
########################################################################################################
# Function:    DeletePerfLogs
#
# Parameters:  $computer
#                                         
# Return:      Void
#
# Purpose:     Deletes old Data Collctor sets on remote server
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function DeletePerfLogs($computer)
{
  Write-Debug "Function DeletePerfLogs($computer)"
  $moreLogs=$true
  $RemoteLogs= logman query -s $computer
  Write-Debug $RemoteLogs
  $log = $remoteLogs[($remoteLogs.length)-3]
  
  while($morelogs)
  {
    if($remotelogs.length -gt 5)
    { 
      $log
      $LogName = $log.substring(0,40)
      write-host "sletter loggen: $Logname"
      logman delete $logname -s $computer
      $RemoteLogs= logman query -s $computer
      $log = $remoteLogs[($remoteLogs.length)-3]
    }
    else 
    {
      Write-host -foregroundcolor green "No performance logs found on this computer!"
      $moreLogs=$false
    }
  }
}

#endregion DeletePerfLogs

#region DeletePerfFiles
########################################################################################################
# Function:    DeletePerfFiles
#
# Parameters:  $computer
#                                         
# Return:      Void
#
# Purpose:     Deletes old performance logs stores on remote server under c:\perflogs
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function DeletePerfFiles($computer)
{
  Write-Debug "Function DeletePerFiles($computer)"
  get-childitem -path "\\$computer\c$\perflogs" | Remove-Item 
}
#endregion DeletePerfFiles

#region TrimCurrentTime
########################################################################################################
# Function:    TrimCurrentTime
#
# Parameters:  $date
#                                         
# Return:      Date where "-" is replaced with "/" due to Logman input format
#
# Purpose:     
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function TrimCurrentTime($date)
{
   Write-Debug "Function TrimCurrentTime($date)"
  return $date.toString().replace("-","/")
}

#endregion TrimCurrentTime

#region AddTime
########################################################################################################
# Function:    AddTime
#
# Parameters:  $date,$dage,$timer,$minutter
#                                         
# Return:      $date
#
# Purpose:     Add days, hours or minutes to $date
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function AddTime($date,$dage,$timer,$minutter)
{
   Write-Debug "Function AddTime($date,$dage,$timer,$minutter)"
  $minutesToAdd=0
  $date=$date.adddays($dage)
  $date=$date.addhours($timer)
  $date=$date.addminutes($minutter+$minutesToAdd)
  return $date
}
#endregion AddTime

#region LogExist
########################################################################################################
# Function:    LogExist
#
# Parameters:  $logname, $computer
#                                         
# Return:      $True is a log exists on a server
#              $false if it does not exists on server
#
# Purpose:     Determine wether a data collection set exists on a server
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function LogExist($logname, $computer)
{
  Write-Debug "LogExist($logname, $computer)"
  $LogQuery = Logman query -s $computer
  $currentLog = $LogQuery | Select-String -Pattern $logname
  if ($currentLog -ne $null)
  {
    Write-Debug "LogExist = True"
	return $true
  }
  else
  {
    Write-Debug "LogExist = False"
	return $false
  }
}
#endregion LogExist

#region IsLogRunning
########################################################################################################
# Function:    IsLogRunning
#
# Parameters:  $logname, $computer
#                                         
# Return:      $True is a log is running 
#              $False is a log is not running
#
# Purpose:     Determine is a data collection set is running or not.
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function IsLogRunning($logname, $computer)
{
  Write-Debug "IsLogRunning($logname, $computer)"
  $LogQuery = Logman query -s $computer
  $currentLog = $LogQuery | Select-String -Pattern $logname
  $strIsStarted=$currentlog | Select-String -Pattern "Running"
  if ($strIsstarted -ne $null)
  {
    Write-Debug "isLogRunning = True"
	return $true
  }
  else
  {
    Write-Debug "isLogRunning = False"
	return $false
  }
}
#endregion IsLogRunning

#region CreatePerfLog
########################################################################################################
# Function:    CreatePerfLog
#
# Parameters:  $computer, $interval, $logname, $logpath, $CounterType
#                                         
# Return:      void
#
# Purpose:     Create a data collection set on a remote server
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function CreatePerfLog($computer, $interval, $logname, $logpath, $CounterType)
{
  Write-Debug "CreatePerfLog($computer, $interval, $logname, $logpath, $CounterType)"
  Write-Host "Creating $CounterType Collection."
  #DeletePerfFiles $computer
  $StartTime = TrimCurrentTime $startDateTime
  $EndTime = TrimCurrentTime $endDateTime
  $cmd="logman create counter $logname -s $computer -o $logpath -f bin -v nnnnnn -cf $scriptPath\$CounterType.txt -si $interval"
  write-debug $cmd
  TRY
  {
    $result=Invoke-Expression $cmd
  }
  CATCH
  {
    Write-Error "$result - Not able to create performance counters on $computer"
	#Exit #Exit script.
  }
}
#endregion CreatePerfLog

#region UpdatePerfLog
########################################################################################################
# Function:    UpdatePerfLog
#
# Parameters:  $computer, $interval, $logname, $logpath, $CounterType
#                                         
# Return:      void
#
# Purpose:     Update a data collection set on a remote server
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function UpdatePerfLog($computer, $interval, $logname, $logpath, $CounterType)
{
  Write-Debug "UpdatePerfLog($computer, $interval, $logname, $logpath, $CounterType)"
  Write-Host "Updating $CounterType Collection."
  #DeletePerfFiles $computer
  $StartTime = TrimCurrentTime $startDateTime
  $EndTime = TrimCurrentTime $endDateTime
  $cmd="logman update counter $logname -s $computer -o $logpath -f bin -v nnnnnn -cf $scriptPath\$CounterType.txt -si $interval"
  write-debug $cmd
  $result=Invoke-Expression $cmd
  if ($result[1] -eq "Error:")
  {
    Write-Host -ForegroundColor Red "$result - Not able to create performance counters on $computer"
	 	Exit #Exit script.
  }
}
#endregion UpdatePerfLog

#region CreateSceduledTask
########################################################################################################
# Function:    CreateSceduledTask
#
# Parameters:  $computer, $logname, $CounterType, $StartLogDateTime, $StopLogDateTime
#                                         
# Return:      void
#
# Purpose:     Create a scheduled task that will start and stop a data collection set on a remote server
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function CreateSceduledTask($computer, $logname, $CounterType, $StartLogDateTime, $StopLogDateTime)
{
  Write-Debug "CreateSceduledTask($computer, $logname, $CounterType, $StartLogDateTime, $StopLogDateTime)"
  $TaskExists = schtasks | Select-String $logname
  if ($TaskExists -ne $null)
  {
    Delete-ScheduledTask $logname
  }
  Write-host "CREATING SCHEDULED TASK"
  $StartLogDateTime = $StartLogDateTime.AddMinutes(1)
  $StartLogDateTime = TrimCurrentTime $StartLogDateTime
  Write-Debug $StartLogDateTime
  Write-Debug "$computer, $logname, $CounterType, $runDate"
  $StartLogDateTime = $StartLogDateTime.split(" ")
  $StartLogTimeUntrimmed=$StartLogDateTime[1].split(":")
  $StartLogTime=""+$StartLogTimeUntrimmed[0]+":"+$StartLogTimeUntrimmed[1]
  $StartLogDate=$StartLogDateTime[0]
  
  $StopLogDateTime = $StopLogDateTime.AddMinutes(1)
  $StopLogDateTime = TrimCurrentTime $StopLogDateTime
  Write-Debug $StopLogDateTime
  Write-Debug "$computer, $logname, $CounterType, $runDate"
  $StopLogDateTime = $StopLogDateTime.split(" ")
  $StopLogTimeUntrimmed=$StopLogDateTime[1].split(":")
  $StopLogTime=""+$StopLogTimeUntrimmed[0]+":"+$StopLogTimeUntrimmed[1]
  $StopLogDate=$StopLogDateTime[0]
  
  $TaskRunPath = "$scriptPath\Temp\"+$CounterType+"-"+$computer+".cmd"
  $TaskStartDataCollectRunPath="$scriptPath\Temp\StartDataCollection_"+$CounterType+"-"+$computer+".cmd"
  $TaskStopDataCollectRunPath="$scriptPath\Temp\StopDataCollection_"+$CounterType+"-"+$computer+".cmd"
  IF($Domain -eq "Unknown")
  {
    $StartTaskCmd= "SCHTASKS /CREATE /SC ONCE /TN StartDataCollection_$logname /TR $TaskStartDataCollectRunPath /ST $StartLogTime /SD $StartLogDate"
    $StopTaskCmd= "SCHTASKS /CREATE /SC ONCE /TN StopDataCollection_$logname /TR $TaskStopDataCollectRunPath /ST $StopLogTime /SD $StopLogDate"
  }
  ELSE 
  {
		$StartTaskCmd = "SCHTASKS /CREATE /RU " + '"' + $cred.GetNetworkCredential().Domain+"\"+$cred.GetNetworkCredential().UserName + '"' +" /RP " + '"' + $cred.GetNetworkCredential().Password + '"' +" /SC ONCE /TN StartDataCollection_$logname /TR $TaskStartDataCollectRunPath /ST $StartLogTime /SD $StartLogDate"
    $StopTaskCmd = "SCHTASKS /CREATE /RU " + '"' + $cred.GetNetworkCredential().Domain+"\"+$cred.GetNetworkCredential().UserName + '"' +" /RP " + '"' + $cred.GetNetworkCredential().Password + '"' +" /SC ONCE /TN StopDataCollection_$logname /TR $TaskStopDataCollectRunPath /ST $StopLogTime /SD $StopLogDate"
  }
  Write-Debug $StartTaskCmd
  Invoke-Expression $StartTaskCmd
  Write-Debug $StopTaskCmd
  Invoke-Expression $StopTaskCmd

}
#endregion CreateSceduledTask

#region UpdateAndStartExistingLog
########################################################################################################
# Function:    
#
# Parameters:  
#                                         
# Return:      
#
# Purpose:     
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function UpdateAndStartExistingLog($computer, $interval, $logname, $startDateTime, $endDateTime)
{
  Write-Debug "UpdateAndStartExistingLog($computer, $interval, $logname, $startDateTime, $endDateTime)"
  $startDateTime = TrimCurrentTime $startDateTime
  $EndDateTime = TrimCurrentTime $endDateTime
  $cmd="logman update $logname -s $computer -si $interval -b $startDateTime -e $endDatetime"
  Write-debug $cmd
  Invoke-Expression $cmd > $null
}
#endregion UpdateAndStartExistingLog

#region GetEndDate
########################################################################################################
# Function:    GetEndDate
#
# Parameters:  
#                                         
# Return:      
#
# Purpose:     
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function GetEndDate ($endDate,[int]$dage, [int]$timer, [int]$minutter)
{
  $endDate=$endDate.adddays($dage)
  $endDate=$endDate.addhours($timer)
  $endDate=$endDate.addminutes($minutter)
  return $endDate
}
#endregion GetEndDate

#region CheckServer
########################################################################################################
# Function:    CheckServer
#
# Parameters:  $computer
#                                         
# Return:      Boolean
#
# Purpose:     Check if the server is a valid server
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function CheckServer($computer)
{
 	[Boolean]$valid=$true
	if(!(Test-Connection -ComputerName $computer -Count 1 -Quiet))
	{
			$valid = $false
	}
	
	return $valid
}
#endregion CheckServer

#region CalculateInterval
########################################################################################################
# Function:    Calculate Interval
#
# Parameters:  
#                                         
# Return:      Integer
#
# Purpose:     Calculate a reasonable interval based on the duration for of trace
#              
# Changes History: 
#                  
#
########################################################################################################
Function CalculateInterval ([int]$idays,[int]$ihours,[int]$iminutes)
{
	[int](($idays*86400 + $ihours*3600 + $iminutes*60)/$samples)
}

#endregion CalculateInterval

#region Main

########################################################################################################
# Function:    Main
#
# Parameters:  $computers, $interval, $CounterType, $StartDateTime, $EndDateTime 
#                                         
# Return:      void
#
# Purpose:     Running the program
#			   
#              
# Changes History: 
#                  
#
########################################################################################################
Function Main($computers, $interval, $CounterType, $StartDateTime, $EndDateTime)
{
  Write-Debug "Main($computers, $interval, $CounterType, $StartDateTime, $EndDateTime)"
	
  $computers=$computers.split(";, ")
  
  foreach($computer in $computers)
  {
		#remove spaces
		$computer = $computer.trim()  
	  if(CheckServer $computer)
		{
			[boolean]$global:isRemotingEnabled = Test-PSRemoting $computer
			if($isRemotingEnabled -eq $false)
			{
				Enable-RemotePSRemoting $computer
			}
			$global:session = ConnectPSRemoting $computer
			if($global:session -ne $null)
			{ 
			  $global:isRemotingEnabled = $true
				Write-Host "Successfully established link to $computer"
			}
			Else
			{
				$global:isRemotingEnabled = $false
				Write-Host -ForegroundColor Yellow "Unable to establish link to $computer - Defaulting to PSEXEC."
			}
			#Create c:\perflogs on remote computer if not exists.
			if(!(Test-Path \\$computer\c$\PerfLogs))
		  {
		    New-Item \\$computer\c$\PerfLogs -ItemType Directory
		  }
			#remove old performance log files on remote computer
			#DeletePerfFiles $computer
			
			#Creating directory in output location if not exists
	    $OutputDir=$OutputPath+$computer
	    if (!(Test-Path $outputdir))
	    {
	      New-Item $outputdir -ItemType directory
	    }
			
			#This function will create counters for the individual SQL instances
			if ($CounterType -eq "SQL_2005_2008")
			{
			  isSQL $computer $CounterType
			  $CounterType = "SQLCollection"
			}

			$logname=$CounterType+"_"+$computer
	    $Logpath="c:\perflogs\$logname.blg"

			if (!(logExist $LogName $computer))
	    { 
	      CreatePerfLog $computer $interval $logname $logpath $CounterType $StartDateTime $EndDateTime
				if($global:buildReport -eq $true)
				{
					CreateSceduledTask $computer $logname $CounterType $StartDateTime $EndDateTime  
				}
				ELSE
				{
					$zipFile = "$ScriptPath\temp\"+$computer +"_"+ $CounterType+".zip" 
					Get-ChildItem "$ScriptPath\temp" | where{$_.name -match $computer} | Export-Zip $zipFile -entryroot "$ScriptPath\temp"
					Write-Host "$zipFile has been created for export"
				}
			  start-sleep 2
			  Create-CMDFile $computer $logname $CounterType
	    }
	    else
		  {
		  	if(IsLogRunning $LogName $computer)
		  	{
		    	Write-Host "$logname is already running on $computer."
					EXIT
		  	}
			  ELSE
				{
					UpdatePerfLog $computer $interval $logname $logpath $CounterType $StartDateTime $EndDateTime
					if($global:buildReport -eq $true)
					{
						CreateSceduledTask $computer $logname $CounterType $StartDateTime $EndDateTime  
					}
					ELSE
					{
						$zipFile = "$ScriptPath\temp\"+$computer +"_"+ $CounterType+".zip" 
						Get-ChildItem "$ScriptPath\temp" | where{$_.name -match $computer} | Export-Zip $zipFile -entryroot "$ScriptPath\temp"
						Write-Host "$zipFile has been created for export"
					}
			  	start-sleep 2
			  	Create-CMDFile $computer $logname $CounterType
				}
	    }
		}
		Else
		{
			Write-Host -ForegroundColor RED "$computer does not exist"
		}
		Remove-PSSession $global:session
		Clear-Variable $global:isRemotingEnabled
        $objForm.Close()
  }
    break
}

#endregion Main

#region GUI

########################################################################################################
# Function:    GUI
#
# Parameters:  -
#                                         
# Return:      -
#
# Purpose:     Draws a GUI that user must fill out in order to make the performance measurement of one 
#              or more servers
#			   
#              
# Change History: 
#              17-01-2011/CSO: Looping script until Cancle button or ESC is pressed.
#                              Check on values in "End Log After"
#                  
#
########################################################################################################
Function GUI
{
  $objForm = New-Object System.Windows.Forms.Form 
  $objForm.Text = "Establish Performance Logs "
  $objForm.Size = New-Object System.Drawing.Size(620,450) 
  $objForm.StartPosition = "CenterScreen"
  $objForm.KeyPreview = $True
  $objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
    {$user=$objTextBox.Text}})
  $objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
    {$objForm.Close();Exit}})

# Building tabs
	$tab = New-Object System.Windows.Forms.Tabcontrol
	$tab.location = New-Object System.Drawing.Point(1,1)
	$tab.size = New-Object System.Drawing.Size(600,400)
	$tab.selectIndex = 0
	$tab.TabIndex=0
	$objForm.Controls.Add($tab)
	
	$tabNewLog = New-Object System.Windows.Forms.Tabpage
	$tabNewLog.Text = "New log"
	$tabNewLog.size = New-Object System.Drawing.Size(590,360)
	$tabNewLog.TabIndex = 0
	$tab.Controls.Add($tabNewLog)

	$tabOldLog = New-Object System.Windows.Forms.Tabpage
	$tabOldLog.Text = "Existing log"
	$tabOldLog.size = New-Object System.Drawing.Size(590,360)
	$tabOldLog.TabIndex = 0
	$tab.Controls.Add($tabOldLog)
	
	
	$tabSettings = New-Object System.Windows.Forms.Tabpage
	$tabSettings.Text = "Settings"
	$tabSettings.size = New-Object System.Drawing.Size(590,360)
	$tabSettings.TabIndex = 0
	$tab.Controls.Add($tabSettings)
	
	#region NewLog
	# Building NewLog Tab
  $OKButton = New-Object System.Windows.Forms.Button
  $OKButton.Location = New-Object System.Drawing.Size(75,320)
  $OKButton.Size = New-Object System.Drawing.Size(75,23)
  $OKButton.Text = "Create"
  $OKButton.Add_Click({
    $global:computers = $objTextBoxServer.Text
    $global:dage = $objTextBoxDage.Text
    $global:Timer = $objTextBoxTimer.Text
    $global:Minutter = $objTextBoxMin.Text
    $global:Interval = $objTextBoxInterval.text
    $global:CounterType = $objDropDownPerformanceType.Text 
    $global:startDateTime = $StartTime.text
	$global:BuildReport = $objCheckboxBuildReport.Checked
  $objForm.Close()})
  $tabNewLog.Controls.Add($OKButton)
	
  $CancelButton = New-Object System.Windows.Forms.Button
  $CancelButton.Location = New-Object System.Drawing.Size(150,320)
  $CancelButton.Size = New-Object System.Drawing.Size(75,23)
  $CancelButton.Text = "Cancel"
  $CancelButton.Add_Click({$global:ExitScript=$true;$objForm.Close();exit})
  $tabNewLog.Controls.Add($CancelButton)

  ##
  $objLabelServer = New-Object System.Windows.Forms.Label
  $objLabelServer.Location = New-Object System.Drawing.Size(10,20) 
  $objLabelServer.Size = New-Object System.Drawing.Size(75,20) 
  $objLabelServer.Text = "Server:"
  $tabNewLog.Controls.Add($objLabelServer) 

  $objTextBoxServer = New-Object System.Windows.Forms.TextBox 
  $objTextBoxServer.Location = New-Object System.Drawing.Size(100,20) 
  $objTextBoxServer.Size = New-Object System.Drawing.Size(100,20) 
  $objTextBoxServer.text=""
  $tabNewLog.Controls.Add($objTextBoxServer) 
	
	
 # Start Time
  $objLabelStartTime = New-Object System.Windows.Forms.Label
  $objLabelStartTime.Location = New-Object System.Drawing.Size(10,100) 
  $objLabelStartTime.Size = New-Object System.Drawing.Size(80,20) 
  $objLabelStartTime.Text = "Start Time:"
  $tabNewLog.Controls.Add($objLabelStartTime) 

 
  $StartTime = New-Object System.Windows.Forms.Textbox
  $StartTime.Location = New-Object System.Drawing.Size(100,100)
  $StartTime.Size = New-Object System.Drawing.Size(150,20)
  $StartTime.text = TrimCurrentTime (Get-Date)
  $tabNewLog.Controls.Add($StartTime)  

# Stop log efter
  $objLabelStopLog = New-Object System.Windows.Forms.Label
  $objLabelStopLog.Location = New-Object System.Drawing.Size(10,145) 
  $objLabelStopLog.Size = New-Object System.Drawing.Size(80,20) 
  $objLabelStopLog.Text = "Stop Log efter:"
  $tabNewLog.Controls.Add($objLabelStopLog) 

  $objLabelDage = New-Object System.Windows.Forms.Label
  $objLabelDage.Location = New-Object System.Drawing.Size(100,145) 
  $objLabelDage.Size = New-Object System.Drawing.Size(40,20) 
  $objLabelDage.Text = "Days:"
  $tabNewLog.Controls.Add($objLabelDage) 

  $objLabelTimer = New-Object System.Windows.Forms.Label
  $objLabelTimer.Location = New-Object System.Drawing.Size(140,145) 
  $objLabelTimer.Size = New-Object System.Drawing.Size(40,20) 
  $objLabelTimer.Text = "Hours:"
  $tabNewLog.Controls.Add($objLabelTimer) 

  $objLabelMin = New-Object System.Windows.Forms.Label
  $objLabelMin.Location = New-Object System.Drawing.Size(180,145) 
  $objLabelMin.Size = New-Object System.Drawing.Size(40,20) 
  $objLabelMin.Text = "Min:"
  $tabNewLog.Controls.Add($objLabelMin) 

  $objTextBoxDage = New-Object System.Windows.Forms.TextBox 
  $objTextBoxDage.Location = New-Object System.Drawing.Size(100,165) 
  $objTextBoxDage.Size = New-Object System.Drawing.Size(30,20) 
  $objTextBoxDage.text="0"
	$objTextboxDage.Add_LostFocus({
		$objTextBoxInterval.text=(CalculateInterval $objTextBoxDage.text $objTextBoxTimer.text $objTextBoxMin.text)
	})
    $tabNewLog.Controls.Add($objTextBoxDage) 

    $objTextBoxTimer = New-Object System.Windows.Forms.TextBox 
    $objTextBoxTimer.Location = New-Object System.Drawing.Size(140,165) 
    $objTextBoxTimer.Size = New-Object System.Drawing.Size(30,20) 
    $objTextBoxTimer.text="0"
	$objTextboxTimer.Add_LostFocus({
		$objTextBoxInterval.text=(CalculateInterval $objTextBoxDage.text $objTextBoxTimer.text $objTextBoxMin.text)
	})
    $tabNewLog.Controls.Add($objTextBoxTimer) 

    $objTextBoxMin = New-Object System.Windows.Forms.TextBox 
    $objTextBoxMin.Location = New-Object System.Drawing.Size(180,165) 
    $objTextBoxMin.Size = New-Object System.Drawing.Size(30,20) 
$objTextBoxMin.text="0"
	$objTextboxMin.Add_LostFocus({
		$objTextBoxInterval.text=(CalculateInterval $objTextBoxDage.text $objTextBoxTimer.text $objTextBoxMin.text)
	})
    $tabNewLog.Controls.Add($objTextBoxMin) 

	

    # Interval
    $objLabelInterval = New-Object System.Windows.Forms.Label
    $objLabelInterval.Location = New-Object System.Drawing.Size(10,200) 
    $objLabelInterval.Size = New-Object System.Drawing.Size(80,20) 
    $objLabelInterval.Text = "Interval:"
    $tabNewLog.Controls.Add($objLabelInterval) 

    $objLabelIntervalSec = New-Object System.Windows.Forms.Label
    $objLabelIntervalSec.Location = New-Object System.Drawing.Size(100,200) 
    $objLabelIntervalSec.Size = New-Object System.Drawing.Size(80,20) 
    $objLabelIntervalSec.Text = "Sec:"
    $tabNewLog.Controls.Add($objLabelIntervalSec) 

    $objTextBoxInterval = New-Object System.Windows.Forms.TextBox 
    $objTextBoxInterval.Location = New-Object System.Drawing.Size(100,220) 
    $objTextBoxInterval.Size = New-Object System.Drawing.Size(60,20) 
    # $objTextBoxInterval.text="0"
    $tabNewLog.Controls.Add($objTextBoxInterval) 
  
    #DropdownBox
    $objDropDownPerformanceType = New-Object System.Windows.Forms.ComboBox
    $objDropDownPerformanceType.Location = New-Object System.Drawing.Size(320,20)
    $objDropDownPerformanceType.Size = New-Object System.Drawing.Size(150,20)
    $objDropDownPerformanceType.Text = "SystemOverview"
    $tabNewLog.Controls.Add($objDropDownPerformanceType)
    $DropDownArray=Get-ChildItem "$ScriptPath\*.txt" -Exclude "read*.txt","sqlcollection.txt"| %{$_.basename}
    foreach ($Item in $DropDownArray)
    {
        $objDropDownPerformanceType.Items.add($Item) > Out-Null
    }
	
		#Credentials
		

    $objLabelCredentials = New-Object System.Windows.Forms.Label
	$objLabelCredentials.Location = New-Object System.Drawing.Size(340,100) 
    $objLabelCredentials.Size = New-Object System.Drawing.Size(150,20) 
    $objLabelCredentials.Text = "Run as $user"
    $tabNewLog.Controls.Add($objLabelCredentials) 
	
	$objCheckboxCredentials = New-Object System.Windows.Forms.CheckBox
	$objCheckboxCredentials.Location = New-Object System.Drawing.Size(320,95)
	$objCheckboxCredentials.Checked = $true
	$tabNewLog.Controls.Add($objCheckboxCredentials) 
	
	
	$objCheckboxCredentials.add_Click(
	{
	    $objLabelCredentialsUsername = New-Object System.Windows.Forms.Label
		$objLabelCredentialsUsername.Location = New-Object System.Drawing.Size(320,125) 
	    $objLabelCredentialsUsername.Size = New-Object System.Drawing.Size(80,20) 
	    $objLabelCredentialsUsername.Text = "Username"
	    $tabNewLog.Controls.Add($objLabelCredentialsUsername) 
		
		$objTextboxCredentialsUsername = New-Object System.Windows.Forms.TextBox 
	    $objTextboxCredentialsUsername.Location = New-Object System.Drawing.Size(400,125) 
	    $objTextboxCredentialsUsername.Size = New-Object System.Drawing.Size(140,20) 
	    $objTextboxCredentialsUsername.text=""
	    $tabNewLog.Controls.Add($objTextboxCredentialsUsername) 

		$objTextBoxCredentialsPassword = New-Object System.Windows.Forms.Label
		$objTextBoxCredentialsPassword.Location = New-Object System.Drawing.Size(320,150) 
	    $objTextBoxCredentialsPassword.Size = New-Object System.Drawing.Size(80,20) 
	    $objTextBoxCredentialsPassword.Text = "Password"
	    $tabNewLog.Controls.Add($objTextBoxCredentialsPassword) 

		$objTextboxCredentialsPassword = New-Object System.Windows.Forms.TextBox 
	    $objTextboxCredentialsPassword.Location = New-Object System.Drawing.Size(400,150) 
	    $objTextboxCredentialsPassword.Size = New-Object System.Drawing.Size(140,20) 
		$objTextboxCredentialsPassword.passwordchar ="*"
	    $objTextboxCredentialsPassword.text=""
	    $tabNewLog.Controls.Add($objTextboxCredentialsPassword) 
	})

	#BuildReport
	$objLabelBuildReport = New-Object System.Windows.Forms.Label
	$objLabelBuildReport.Location = New-Object System.Drawing.Size(340,180) 
     $objLabelBuildReport.Size = New-Object System.Drawing.Size(150,20) 
    $objLabelBuildReport.Text = "Build Report"
    $tabNewLog.Controls.Add($objLabelBuildReport) 
	
	$objCheckboxBuildReport = New-Object System.Windows.Forms.CheckBox
	$objCheckboxBuildReport.Location = New-Object System.Drawing.Size(320,175)
	$objCheckboxBuildReport.Checked = $true
	$tabNewLog.Controls.Add($objCheckboxBuildReport) 

	
	
	#endregion NewLog
	
# Building Settings Tab
	
	#region ExistingLog
	
	$objLabelOldLogLocation = New-Object System.Windows.Forms.Label
    $objLabelOldLogLocation.Location = New-Object System.Drawing.Size(10,20) 
    $objLabelOldLogLocation.Size = New-Object System.Drawing.Size(140,20) 
    $objLabelOldLogLocation.Text = "Existing Log Location:"
    $tabOldLog.Controls.Add($objLabelOldLogLocation) 

    $objTextBoxOldLogLocation = New-Object System.Windows.Forms.TextBox 
    $objTextBoxOldLogLocation.Location = New-Object System.Drawing.Size(150,20) 
    $objTextBoxOldLogLocation.Size = New-Object System.Drawing.Size(350,20) 
    $objTextBoxOldLogLocation.text=$OldLogPath
    $tabOldLog.Controls.Add($objTextBoxOldLogLocation) 
	
	$objLabelDisplayOldLogLocation = New-Object System.Windows.Forms.Label
    $objLabelDisplayOldLogLocation.Location = New-Object System.Drawing.Size(10,45) 
    $objLabelDisplayOldLogLocation.Size = New-Object System.Drawing.Size(140,20) 
    $objLabelDisplayOldLogLocation.Text = "Existing Logs:"
    $tabOldLog.Controls.Add($objLabelDisplayOldLogLocation) 
	
	$objDropDownDisplayOldLogLocation = New-Object System.Windows.Forms.ComboBox
    $objDropDownDisplayOldLogLocation.Location = New-Object System.Drawing.Size(150,45)
    $objDropDownDisplayOldLogLocation.Size = New-Object System.Drawing.Size(350,20)
    $objDropDownDisplayOldLogLocation.Text = "Choose log to analyze"
    $tabOldLog.Controls.Add($objDropDownDisplayOldLogLocation)
    $DropDownArray=Get-ChildItem "$OldLogPath\*.ps1" | %{$_.basename}
    foreach ($Item in $DropDownArray)
    {
        $objDropDownDisplayOldLogLocation.Items.add($Item) > Out-Null
    }
	
	$OKOldLogButton = New-Object System.Windows.Forms.Button
    $OKOldLogButton.Location = New-Object System.Drawing.Size(75,320)
    $OKOldLogButton.Size = New-Object System.Drawing.Size(75,23)
    $OKOldLogButton.Text = "Create"
    $OKOldLogButton.Add_Click({
		$OldLog = $objDropDownDisplayOldLogLocation.Text
		$objForm.Close()
		Start-Sleep 2
        invoke-Expression "$oldlogpath\$oldlog.ps1"
    })
    $tabOldLog.Controls.Add($OKOldLogButton)
	
    $CancelOldLogButton = New-Object System.Windows.Forms.Button
    $CancelOldLogButton.Location = New-Object System.Drawing.Size(150,320)
    $CancelOldLogButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelOldLogButton.Text = "Cancel"
    $CancelOldLogButton.Add_Click({$global:ExitScript=$true;$objForm.Close()})
    $tabOldLog.Controls.Add($CancelOldLogButton)

	
	#endregion ExistingLog
	
	
	#region Settings
	# Output Location
	$objLabelOutputLocation = New-Object System.Windows.Forms.Label
    $objLabelOutputLocation.Location = New-Object System.Drawing.Size(10,20) 
    $objLabelOutputLocation.Size = New-Object System.Drawing.Size(140,20) 
    $objLabelOutputLocation.Text = "Output Location:"
    $tabSettings.Controls.Add($objLabelOutputLocation) 

    $objTextBoxOutputLocation = New-Object System.Windows.Forms.TextBox 
    $objTextBoxOutputLocation.Location = New-Object System.Drawing.Size(150,20) 
    $objTextBoxOutputLocation.Size = New-Object System.Drawing.Size(350,20) 
    $objTextBoxOutputLocation.text=$OutputPath
    $tabSettings.Controls.Add($objTextBoxOutputLocation) 
	

	#endregion Settings
	# Domain + user + Password
	# 


  $objForm.Topmost = $True
  $objForm.Add_Shown({$objForm.Activate()})
  [void] $objForm.ShowDialog()


  if($computers -eq $null)
  {
    Write-Host "Abort!"
  }
  elseif ($computers -eq "")
  {
    Write-Host "No computers entered."
  }
  elseif ($interval -lt "1" )
  {
    Write-Host "Minimum interval is 1 sec"
  }
  elseif($dage  -eq "")
  {
    $dage="0"
  }
  elseif($timer -eq "")
  {
    $timer="0"
  }
  elseif($minutter -eq "")
  {
    $minutter="0"
  }

  
  elseif (($dage -eq "0" ) -and ($timer -eq "0") -and ($minutter -eq "0"))
  {
    Write-Host "No time entered"
  }
  else
  {
  	Write-Debug "Dage = $dage"
    Write-Debug "Timer = $timer"
    Write-Debug "Minutter = $minutter"
    foreach ($computer in $computers)
    {
	    $computer = $computer.trim()
        CheckServer $computer
    }
		
		
	$SDate=[datetime]::Parseexact( $startDateTime,"dd'/'MM'/'yyyy HH:mm:ss",$null)
	$SDate = $SDate.addMinutes(1)
	 
	Write-Debug "Kalder >> GetEndDate $SDate $dage $timer $minutter"
	$EDate = GetEndDate $SDate $dage $timer $minutter
	Write-Debug "EndDate = $EDate"
		 
	Write-Debug "Kalder >> MAIN $computers $dage $timer $minutter $interval  "
	if ($objTextboxCredentialsUsername.text -ne "")
	{
		#$domain = "Unknown"
		$global:cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $objTextboxCredentialsUsername.text ,(convertto-securestring $objTextboxCredentialsPassword.text -asplaintext -force)
	}
		
	$global:OutputPath = $objTextBoxOutputLocation.text
	$global:buildReport = $objCheckboxBuildReport.Checked
    MAIN $computers $interval $CounterType $SDate $EDate 
  }
}#End Function GUI

#ENDregion GUI

#Clear-Host
WriteSplashScreen
$global:ExitScript = $false
#while($ExitScript -ne $true)
#{
#  GUI
#}

GUI
break