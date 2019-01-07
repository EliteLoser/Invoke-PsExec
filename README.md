# Invoke-PsExec

Svendsen Tech's Invoke-PsExec for PowerShell is a function that lets you execute PowerShell and batch/cmd.exe code asynchronously on target Windows computers, using PsExec.exe.

Online blog documentation here: https://www.powershelladmin.com/wiki/Invoke-PsExec_for_PowerShell

PowerShell Gallery link: https://www.powershellgallery.com/packages/InvokePsExec/

Example of installation for your user only (elevation not required):
`Install-Module -Name InvokePsExec -Scope CurrentUser #-Force`.

# Example of a PowerShell command through PsExec.exe in PowerShell

![PowerShell Invoke-PsExec example](/Images/Invoke-PsExec-example-powershell.png)

# Example of a batch command with PsExec.exe in PowerShell

![PowerShell Invoke-PsExec example](/Images/Invoke-PsExec-example-batch.png)
