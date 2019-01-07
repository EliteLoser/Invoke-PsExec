#requires -version 3


function Invoke-PsExec {
    <#
    .SYNOPSIS
        Svendsen Tech's Invoke-PsExec for PowerShell is a function that lets you execute PowerShell
        and batch/cmd.exe code asynchronously on target Windows computers, using PsExec.exe.

        Versions of PsExec.exe after about 2015 some time (don't quote me on the date) use
        encrypted credentials when connecting to remote computers.

        Online documentation: http://www.powershelladmin.com/wiki/Invoke-PsExec_for_PowerShell

        Copyright (C) 2015-2017, Joakim Borger Svendsen
        All rights reserved.
        Svendsen Tech.
        MIT license. http://www.opensource.org/licenses/MIT

    .PARAMETER ComputerName
        IP address or computer name.
    .PARAMETER Command
        PowerShell or batch/cmd.exe code to execute.
    .PARAMETER IsPSCommand
        This indicates that the specified command string is pure PowerShell code (you will usually want single quotes around that to avoid escaping).
    .PARAMETER IsLongPSCommand
        Use this if the PowerShell code produces a base64-encoded string of a length greater than 260, so you get
        'Argument to long' [SIC] from PsExec. This uses a temporary file that's created on the remote computer.
    .PARAMETER CustomPsExecParameters
        Custom parameters for PsExec.
    .PARAMETER PSFile
        PowerShell file in the local file system to be run via PsExec on the remote computer.
    .PARAMETER Dns
        Perform a DNS lookup.
    .PARAMETER Credential
        Pass in alternate credentials. Get-Help Get-Credential.
    .PARAMETER ContinueOnPingFail
        Attempt PsExec command even if ping fails.
    .PARAMETER ThrottleLimit
        Number of concurrent threads. Default of 8. Lower it if results appear to be missing without reason.
    .PARAMETER HideProgress
        Do not display progress with Write-Progress.
    .PARAMETER Timeout
        Timeout in seconds. Causes problems if too short. 30-60 as a default seems OK.
        Increase if doing a lot of processing with PsExec.
    .PARAMETER HideSummary
        Do not display the end summary with start and end time, using Write-Host.
    #>
    [CmdletBinding()]
    param(
        # IP address or computer name.
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)][ValidateNotNullOrEmpty()][Alias('PSComputerName', 'Cn')][string[]] $ComputerName,
        # PowerShell or batch/cmd.exe code to execute.
        [string] $Command,
        # This indicates that the specified command string is pure PowerShell code (you will usually want single quotes around that to avoid escaping).
        [switch] $IsPSCommand,
        # Use this if the PowerShell code produces a base64-encoded string of a length greater than 260, so you get 'Argument to long' [SIC] from PsExec. This uses a temporary file that's created on the remote computer.
        [switch] $IsLongPSCommand,
        # Custom parameters for PsExec.
        [string] $CustomPsExecParameters = '',
        # PowerShell file in the local file system to be run via PsExec on the remote computer.
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})][string] $PSFile = '',
        # Perform a DNS lookup.
        [switch] $Dns,
        # Pass in alternate credentials. Get-Help Get-Credential.
        [System.Management.Automation.PSCredential][System.Management.Automation.Credential()] $Credential = [System.Management.Automation.PSCredential]::Empty,
        # Attempt PsExec command even if ping fails.
        [switch] $ContinueOnPingFail,
        # Number of concurrent threads.
        [int] $ThrottleLimit = 8,
        # Do not display progress with Write-Progress.
        [switch] $HideProgress,
        # Timeout in seconds. Causes problems if too short. 60 as a default seems OK. Increase if doing a lot of processing with PsExec.
        [int] $Timeout = 60,
        # Do not display the end summary with start and end time, using Write-Host.
        [switch] $HideSummary)
    # PowerShell Invoke-PsExec ("PsExec Wrapper v2").
    # Copyright (c) 2015-2017, Joakim Borger Svendsen, All rights reserved. Svendsen Tech.
    # Author: Joakim Borger Svendsen
    # MIT license - http://www.opensource.org/licenses/MIT
    # August 15, 2015. beta1
    # August 23, 2015. beta2
    # December 02, 2015, beta3, bug fixes, documentation
    # 2017-01-23 to -25: Making a module of it, v1.0, rearranging some stuff according to newly learned best practices..
    #             Setting throttle limit default to 8. The module will require PowerShell v3 due to $PSScriptRoot
    #             being used. Wish I had used K&R-style blocks now, but keeping them because it's too much work for too little gain.
    # 2017-02-14: Trying to conform to PSScriptAnalyzer warnings.
    begin
    {
        Set-StrictMode -Version Latest
        $MyEAP = 'Stop'
        $ErrorActionPreference = $MyEAP
        $StartTime = Get-Date
        if ($PsExecExecutable = Get-Item -LiteralPath (Join-Path (Get-Location) 'PsExec.exe') -ErrorAction SilentlyContinue | Select-Object -ErrorAction SilentlyContinue -ExpandProperty FullName)
        {
            Write-Verbose -Message "Found PsExec.exe in current working directory. Using this PsExec.exe executable: '$PsExecExecutable'."
        }
        # Missing $PSScriptRoot in PSv2.. Abandoning v2 support for this module.
        #Write-Verbose -Message ("MyInvocation: " + ($MyInvocation.MyCommand.Path)) # doesn't exist in my PSv4 ...
        elseif ($PsExecExecutable = Get-Item -LiteralPath "$PSScriptRoot\PsExec.exe" -ErrorAction SilentlyContinue | Select-Object -ErrorAction SilentlyContinue -ExpandProperty FullName)
        {
            Write-Verbose -Message "Found PsExec.exe in directory script was called from. Using this PsExec.exe executable: '$PsExecExecutable'."
        }
        #>
        elseif ($PsExecExecutable = Get-Command -Name psexec -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 | Select-Object -ExpandProperty Definition -ErrorAction SilentlyContinue)
        {
            Write-Verbose -Message "Found PsExec.exe in `$Env:PATH. Using this PsExec.exe executable: '$PsExecExecutable'."
        }
        else
        {
            Write-Error -Message "You need PsExec.exe from Microsoft's SysInternals suite to use this script. Either in the working dir, or somewhere in `$Env:PATH." -ErrorAction Stop
            return
        }
        $RunspaceTimers = [HashTable]::Synchronized(@{})
        $Data = [HashTable]::Synchronized(@{})
        $Runspaces = New-Object -TypeName System.Collections.ArrayList
        $RunspaceCounter = 0
        Write-Verbose -Message 'Creating initial session state.'
        $ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RunspaceTimers', $RunspaceTimers, ''))
        $ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'Data', $Data, ''))
        Write-Verbose -Message 'Creating runspace pool.'
        $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $ISS, $Host)
        $RunspacePool.ApartmentState = 'STA'
        $RunspacePool.Open()
        # This is run for every computer.
        $PsExecScriptBlock =
        {
            [CmdletBinding()]
            param(
                [int] $ID,
                [string] $ComputerName,
                [string] $Command,
                [switch] $IsPSCommand,
                [switch] $IsLongPSCommand,
                [string] $CustomPsExecParameters,
                [string] $PSFile,
                [switch] $ContinueOnPingFail,
                [switch] $Dns,
                [string] $PsExecExecutable,
                [System.Management.Automation.PSCredential][System.Management.Automation.Credential()] $Credential)
            $RunspaceTimers.$ID = Get-Date
            if (-not $Data.ContainsKey($ComputerName))
            {
                $Data[$ComputerName] = New-Object -TypeName PSObject -Property @{ ComputerName = $ComputerName }
            }
            if ($Dns)
            {
                Write-Verbose -Message "${ComputerName}: Performing DNS lookup."
                $ErrorActionPreference = 'SilentlyContinue'
                $HostEntry = [System.Net.Dns]::GetHostEntry($ComputerName)
                $Result = $?
                $ErrorActionPreference = $MyEAP
                #Write-Verbose -Message "`$Result from DNS lookup: $Result (type: $($Result.GetType().FullName))"
                # It looks like it's sometimes "successful" even when it isn't, for any practical purposes (pass in IP, get the same IP as .HostName)...
                if ($Result)
                {
                    ## This is a best-effort attempt at handling things flexibly.
                    if ($HostEntry.HostName.Split('.')[0] -ieq $ComputerName.Split('.')[0])
                    {
                        $IPDns = @($HostEntry | Select-Object -ExpandProperty AddressList | Select-Object -ExpandProperty IPAddressToString)
                    }
                    else
                    {
                        $IPDns = @(@($HostEntry.HostName) + @($HostEntry.Aliases))
                    }
                    $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name 'IP/DNS' -Value $IPDns
                }
                else
                {
                    $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name 'IP/DNS' -Value $Null
                }
            }
            Write-Verbose -Message "${ComputerName}: Pinging."
            if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet))
            {
                $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name Ping -Value $False
                if (-not $ContinueOnPingFail)
                {
                    continue
                }
            }
            else
            {
                $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name Ping -Value $True
            }
            if ($null -ne $Credential.Username)
            {
                [string] $CommandString = "-u `"$($Credential.Username)`" -p `"$($Credential.GetNetworkCredential().Password)`" /accepteula $CustomPsExecParameters \\$ComputerName"
            }
            else
            {
                [string] $CommandString = "/accepteula $CustomPsExecParameters \\$ComputerName"
            }
            if ($IsLongPSCommand -or $PSFile)
            {
                if ($IsLongPSCommand)
                {
                    $TempPSFile = [System.IO.Path]::GetTempFileName()
                    $Command | Out-File -LiteralPath $TempPSFile
                }
                elseif ($PSFile)
                {
                    $TempPSFile = $PSFile
                }
                # Try to handle multiple people running the script at the same time (race condition not handled, but it's better than nothing).
                $Destination = "\\${ComputerName}\ADMIN`$\SvendsenTechInvokePsExecTemp.ps1"
                if (Test-Path -LiteralPath $Destination)
                {
                    Write-Verbose -Message "${ComputerName}: Destination file '$Destination' already exists. Tacking on numbers until it doesn't."
                    [bool] $GotAvailableFileName = $False
                    foreach ($i in 0..10000)
                    {
                        $TempDest = $Destination -replace '\.ps1$', "$i.ps1"
                        if (-not (Test-Path -LiteralPath $TempDest))
                        {
                            $Destination = $TempDest
                            $GotAvailableFileName = $True
                            break
                        }
                    }
                    if (-not $GotAvailableFileName)
                    {
                        Write-Warning -Message "${ComputerName}: All 10,000 temp file names already present in the file system. What are you up to? Skipping this computer."
                        continue
                    }
                }
                try
                {
                    Copy-Item -LiteralPath $TempPSFile -Destination $Destination -ErrorAction Stop
                }
                catch
                {
                    Write-Warning -Message "${ComputerName}: Unable to copy (temporary) PowerShell script file to destination: '$Destination': $_"
                    if ($IsLongPSCommand)
                    {
                        Write-Verbose -Message "${ComputerName}: Deleting local temporary PS script file: '$TempPSFile'."
                        Remove-Item -LiteralPath $TempPSFile -Force -ErrorAction Continue
                    }
                    continue
                }
                if ($IsLongPSCommand)
                {
                    Write-Verbose -Message "${ComputerName}: Deleting temporary PS script file: '$TempPSFile'."
                    Remove-Item -LiteralPath $TempPSFile -Force -ErrorAction Continue
                }
                $CommandString += " cmd /c `"echo . | powershell.exe -ExecutionPolicy Bypass -File $Env:SystemRoot\$($Destination.Split('\')[-1])`""
            }
            elseif ($IsPSCommand)
            {
                $EncodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
                $CommandString += " cmd /c `"echo . | powershell.exe -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand`""
            }
            else
            {
                $CommandString += " cmd /c `"$Command`""
            }
            $TempFileNameSTDOUT = [System.IO.Path]::GetTempFileName()
            $TempFileNameSTDERR = [System.IO.Path]::GetTempFileName()
            Write-Verbose -Message "${ComputerName}: Running PsExec command."
            $Result = Start-Process -FilePath $PsExecExecutable -ArgumentList $CommandString -Wait -NoNewWindow -PassThru -RedirectStandardOutput $TempFileNameSTDOUT -RedirectStandardError $TempFileNameSTDERR -ErrorAction Continue
            $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name ExitCode -Value $Result.ExitCode
            $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name STDOUT -Value ((Get-Content -LiteralPath $TempFileNameSTDOUT) -join "`n")
            #Write-Verbose -Message ('Content of temp STDERR file: ' + ((Get-Content -LiteralPath $TempFileNameSTDERR) -join "`n"))
            $Data[$ComputerName] | Add-Member -MemberType NoteProperty -Name STDERR -Value ((Get-Content -LiteralPath $TempFileNameSTDERR) -join "`n")
            Write-Verbose -Message "${ComputerName}: Deleting local STDOUT temporary file: '$TempFileNameSTDOUT'."
            Remove-Item -LiteralPath $TempFileNameSTDOUT -Force -ErrorAction Continue
            Write-Verbose -Message "${ComputerName}: Deleting local STDERR temporary file: '$TempFileNameSTDERR'."
            Remove-Item -LiteralPath $TempFileNameSTDERR -Force -ErrorAction Continue
            if ($IsLongPSCommand -or $PSFile)
            {
                Write-Verbose -Message "${ComputerName}: Deleting remote temporary PowerShell file: '$Destination'."
                Remove-Item -LiteralPath $Destination -ErrorAction Continue
            }
        }
        function Get-Result
        {
            [CmdletBinding()]
            param(
                [switch] $Wait
            )
            do
            {
                $More = $false
                foreach ($Runspace in $Runspaces) {
                    $StartTime = $RunspaceTimers[$Runspace.ID]
                    if ($Runspace.Handle.IsCompleted)
                    {
                        #Write-Verbose -Message ('Thread done for {0}' -f $Runspace.IObject)
                        $Runspace.PowerShell.EndInvoke($Runspace.Handle)
                        $Runspace.PowerShell.Dispose()
                        $Runspace.PowerShell = $null
                        $Runspace.Handle = $null
                    }
                    elseif ($null -ne $Runspace.Handle)
                    {
                        $More = $true
                    }
                    if ($Timeout -and $StartTime)
                    {
                        if ((New-TimeSpan -Start $StartTime).TotalSeconds -ge $Timeout -and $Runspace.PowerShell) {
                            Write-Warning -Message ('Timeout {0}' -f $Runspace.IObject)
                            $Runspace.PowerShell.Dispose()
                            $Runspace.PowerShell = $null
                            $Runspace.Handle = $null
                        }
                    }
                }
                if ($More -and $PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds 100
                }
                foreach ($Thread in $Runspaces.Clone())
                {
                    if (-not $Thread.Handle) {
                        Write-Verbose -Message ('Removing {0} from runspaces' -f $Thread.IObject)
                        $Runspaces.Remove($Thread)
                    }
                }
                if (-not $HideProgress)
                {
                    $ProgressSplatting = @{
                        Activity = 'Running PsExec Commands'
                        Status = 'Processing: {0} of {1} total threads done' -f ($RunspaceCounter - $Runspaces.Count), $RunspaceCounter
                        PercentComplete = ($RunspaceCounter - $Runspaces.Count) / $RunspaceCounter * 100
                    }
                    Write-Progress @ProgressSplatting
                }
            }
            while ($More -and $PSBoundParameters['Wait'])
        } # end of Get-Result
    }

    process
    {
        foreach ($Computer in $ComputerName)
        {
            Write-Verbose -Message "Processing $Computer."
            ++$RunspaceCounter
            $psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($PsExecScriptBlock)
            [void] $psCMD.AddParameter('ID', $RunspaceCounter)
            [void] $psCMD.AddParameter('ComputerName', $Computer)
            [void] $PSCMD.AddParameter('Command', $Command)
            [void] $PSCMD.AddParameter('IsPSCommand', $IsPSCommand)
            [void] $PSCMD.AddParameter('CustomPsExecParameters', $CustomPsExecParameters)
            [void] $PSCMD.AddParameter('PSFile', $PSFile)
            [void] $PSCMD.AddParameter('IsLongPSCommand', $IsLongPSCommand)
            [void] $PSCMD.AddParameter('Dns', $Dns)
            [void] $PSCMD.AddParameter('PsExecExecutable', $PsExecExecutable)
            [void] $PSCMD.AddParameter('ContinueOnPingFail', $ContinueOnPingFail)
            [void] $PSCMD.AddParameter('Credential', $Credential)
            [void] $psCMD.AddParameter('Verbose', $VerbosePreference)
            $psCMD.RunspacePool = $RunspacePool
            [void]$Runspaces.Add(@{
                Handle = $psCMD.BeginInvoke()
                PowerShell = $psCMD
                IObject = $Computer
                ID = $RunspaceCounter
            })
            Get-Result
        }
    }
    
    end 
    {
        Get-Result -Wait
        if (-not $HideProgress)
        {
            Write-Progress -Activity 'Running PsExec Commands' -Status 'Done' -Completed
        }
        Write-Verbose -Message "Closing and disposing runspace pool."
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        [hashtable[]] $PsExecProperties = @{ Name = 'ComputerName'; Expression = { $_.Name } }
        if ($Dns)
        {
            $PsExecProperties += @{ Name = 'IP/DNS'; Expression = { $_.Value.'IP/DNS' } }
        }
        $PsExecProperties += @{ Name = 'Ping'; Expression = { $_.Value.Ping } },
                             @{ Name = 'ExitCode'; Expression = { $_.Value.ExitCode } },
                             @{ Name = 'STDOUT'; Expression = { $_.Value.STDOUT } },
                             @{ Name = 'STDERR'; Expression = { $_.Value.STDERR } }
        $Data.GetEnumerator() | Select-Object -Property $PsExecProperties
        Write-Verbose -Message '"Exporting" $Global:STPsExecData and $Global:STPsExecDataProperties'
        $Global:STPsExecData = $Data
        $Global:STPsExecDataProperties = $PsExecProperties
        if (-not $HideSummary)
        {
            Write-Host -ForegroundColor Green ('Start time: ' + $StartTime)
            Write-Host -ForegroundColor Green ('End time:   ' + (Get-Date))
        }
    }
}