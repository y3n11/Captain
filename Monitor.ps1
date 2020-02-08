
$ignoredProcesses=@("dllhost.exe","SearchProtocolHost.exe","SearchFilterHost.exe","taskhost.exe", "conhost.exe", "firefox.exe"); #these processes will never be suspended
$new_process_check_interval = New-Object System.TimeSpan(0,0,0,0,750); #public TimeSpan (int days, int hours, int minutes, int seconds, int milliseconds);


Add-Type -Name Threader -Namespace "" -Member @"
	[Flags]
	public enum ProcessAccess : uint
	{
		Terminate = 0x00000001,
		CreateThread = 0x00000002,
		VMOperation = 0x00000008,
		VMRead = 0x00000010,
		VMWrite = 0x00000020,
		DupHandle = 0x00000040,
		SetInformation = 0x00000200,
		QueryInformation = 0x00000400,
		SuspendResume = 0x00000800,
		Synchronize = 0x00100000,
		All = 0x001F0FFF
	}

	[DllImport("ntdll.dll", EntryPoint = "NtSuspendProcess", SetLastError = true)]
	public static extern uint SuspendProcess(IntPtr processHandle);

	[DllImport("ntdll.dll", EntryPoint = "NtResumeProcess", SetLastError = true)]
	public static extern uint ResumeProcess(IntPtr processHandle);

	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

	[DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool CloseHandle(IntPtr hObject);
"@



function Suspend-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to suspend process: $processID"

		$result = [Threader]::SuspendProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to suspend. SuspendProcess returned: $result"
			return $False
		}
		[Threader]::CloseHandle($pProc) | out-null;
	} else {
		Write-Error "Unable to open process. Not elevated? Process doesn't exist anymore?"
		return $False
	}
	return $True
}

function Resume-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to resume process: $processID"
		Write-Host ""
		$result = [Threader]::ResumeProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to resume. ResumeProcess returned: $result"
		}
		[Threader]::CloseHandle($pProc) | out-null
	} else {
		Write-Error "Unable to open process. Process doesn't exist anymore?"
	}
}

$culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US');
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture;
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture;

Write-Host "Monitoring newly spawned processes via WMI...";
Write-host "";

$scope = New-Object System.Management.ManagementScope("\\.\root\cimV2");
$query = New-Object System.Management.WQLEventQuery("__InstanceCreationEvent",$new_process_check_interval,"TargetInstance ISA 'Win32_Process'" );
$watcher = New-Object System.Management.ManagementEventWatcher($scope,$query);

$processSpawnCounter=1;
do
{
	$newlyArrivedEvent = $watcher.WaitForNextEvent();
	$e = $newlyArrivedEvent.TargetInstance;
	Write-Host "($processSpawnCounter) New process spawned:";

	$processName=[string]$e.Name;
	Write-host "PID:`t`t" $e.ProcessId;
	Write-host "Name:`t`t" $processName;
	Write-host "PPID:`t`t" $e.ParentProcessID; 
	
	$parent_process=''; 
	try {$proc=(Get-Process -id $e.ParentProcessID -ea stop); $parent_process=$proc.ProcessName;} catch {$parent_process='unknown';}
	Write-host "Parent name:`t" $parent_process; 
	Write-host "CommandLine:`t" $e.CommandLine;

	if (-not ($ignoredProcesses -match $processName))
	{
		if(Suspend-Process -processID $e.ProcessId){
			Write-Host "Process is suspended.";
			C:\ProgramData\Captain\Injector.exe $e.ProcessId
            Write-Host "Dll Injected !!";
            Resume-Process -processID $e.ProcessId
		}
	}else{
		Write-Host "Process ignored as per configuration.";
	}

	Write-host "";
	$processSpawnCounter += 1;
} while ($true)
