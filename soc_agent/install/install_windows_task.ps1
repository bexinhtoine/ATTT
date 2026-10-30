# Cai SOC Agent thanh Scheduled Task chay luc khoi dong (quyen SYSTEM de doc Security log).
# Chay PowerShell voi quyen Administrator:  .\install_windows_task.ps1
param(
  [string]$AgentDir = $PSScriptRoot + "\..",
  [string]$Python = "python",
  [string]$TaskName = "SOCAgent"
)
$agentPath = (Resolve-Path (Join-Path $AgentDir "agent.py")).Path
Write-Host "Cai Scheduled Task '$TaskName' chay: $Python $agentPath"

$action  = New-ScheduledTaskAction -Execute $Python -Argument "`"$agentPath`"" -WorkingDirectory (Resolve-Path $AgentDir).Path
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName $TaskName
Write-Host "Da cai va khoi chay. Xem trang thai: Get-ScheduledTask -TaskName $TaskName"
Write-Host "Go cai:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
