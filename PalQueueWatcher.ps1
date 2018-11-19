
#
#	PalQueueWatcher v 1.0  by Claus Søgaard
# 
#
#	To run this script, create at task in TaskScheduler and run the task when the server starts.
# Make sure to restart the script automatically if the script fails
#
# This way it runs like a service.
#
#
##############################################################################
#	
#				FUNCTIONS
#
##############################################################################

Function Global:RunJob($command)
{
	Write-Host -fore Yellow "RunJob"
  $j = Start-Job -ScriptBlock {param($x);invoke-expression "powershell -Command {$x}"} -ArgumentList $command
}

Function Global:MoveInQueueToOutQueue
{
	Write-Host "MoveInQueueToOutQueue"
	$out = Get-Content $global:OutQueueFile
	$in = Get-Content $global:inQueueFile
	if($in -ne $null -or $in -ne "")
	{
		$out = $out + $in	
		Clear-Content $global:inQueueFile
	}
	$out | Set-Content $global:OutQueueFile
}

Function GetNextjobFromQueue
{
	Write-Host "GetjobFromQueue"
	$jobInput = get-content $global:OutQueueFile
	
  $nextJob = $jobInput | select -first 1
	$jobInput| select -skip 1 | out-file $global:OutQueueFile
	return $nextJob
}

Function Global:Main
{
	Write-Host "Main"
	MoveInQueueToOutQueue
	if((get-item $global:OutQueueFile).length -gt 5 )
	{
		for( $i = 0; $i -lt $maxConcurrentJobs; $i++ )
		{
				$job = GetNextjobFromQueue
				Write-Host "Running job [$job]"
		    RunJob $job
				while ((get-job | where{$_.State -eq "running"}) -ne $null)
				{
					Start-Sleep 5
				}
		}
	}	
	ELSE
	{
		Write-Host "No jobs found"
	}
}
##############################################################################
#	
#										MAIN
#
##############################################################################


# How many jobs we should run simultaneously.  PAL is running with 3 threads, so watch out for tweaking this parameter.
$maxConcurrentJobs = 1;
$global:inQueueFile = "\\bdfil-dc1\bd$\Bdpnet\PAL\QueueIn.txt"
$global:OutQueueFile = "\\bdfil-dc1\bd$\Bdpnet\PAL\QueueOut.txt"
while($true)
{
	Global:Main
	Start-Sleep -Seconds 30
}