# Installed integration test for a disposable Windows machine. No Hello, GUI or secrets.
# Ordinary unit tests do not invoke this script. It refuses an existing installation/vault.
[CmdletBinding()]
param([switch]$AllowSystemChanges, [string]$BinaryDirectory, [string]$ResultPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$AllowSystemChanges) { throw 'This test installs/removes a SYSTEM service. Use -AllowSystemChanges on a disposable clean Windows machine.' }
if ($env:OS -ne 'Windows_NT') { throw 'Run this integration test on Windows.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (!([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated PowerShell terminal.' }
$install = 'C:\Program Files\KeyValet'; $vault = 'C:\ProgramData\KeyValet'
if ((Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $vault) -or
    (Get-Service KeyValetHelper -ErrorAction SilentlyContinue) -or
    (Get-ScheduledTask -TaskName KeyValetAgent -ErrorAction SilentlyContinue)) {
    throw 'This test requires a clean machine with no KeyValet installation, task, service or retained vault.'
}
$repo = Split-Path $PSScriptRoot -Parent
if (!$BinaryDirectory) { $BinaryDirectory = "$repo/rust/target/debug" }
$BinaryDirectory = (Resolve-Path -LiteralPath $BinaryDirectory).Path
if (!$ResultPath) { $ResultPath = "$repo/dist/windows-service-test.json" }
$version = [regex]::Match((Get-Content "$repo/rust/crates/kv-cli/Cargo.toml" -Raw), '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
$architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
$owner = $null
$testUser = $null
$testPassword = $null
$checks = [Collections.Generic.List[string]]::new()
$failure = $null
function Assert([bool]$Condition, [string]$Message) { if (!$Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert $threw $Message
}
function Wait-Service([string]$State) {
    $controller = Get-Service KeyValetHelper
    try { $controller.WaitForStatus($State, [TimeSpan]::FromSeconds(20)) } finally { $controller.Dispose() }
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class KeyValetSmokePipe {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
}
'@
function Test-ServicePipe {
    $configuration = Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'"
    Assert ($configuration.State -eq 'Running' -and $configuration.StartName -eq 'LocalSystem') 'Helper must run under SCM as SYSTEM.'
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($configuration.ProcessId)"
    Assert ($process.ExecutablePath -ieq "$install\bin\kv-helper.exe") 'Service executable path differs.'
    Assert ((Invoke-CimMethod $process -MethodName GetOwnerSid).Sid -eq 'S-1-5-18') 'Service process token must belong to SYSTEM.'
    $channel = [IO.Pipes.NamedPipeClientStream]::new('.', 'keyvalet-helper', [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        $channel.Connect(5000)
        [uint32]$pidValue = 0
        Assert ([KeyValetSmokePipe]::GetNamedPipeServerProcessId($channel.SafePipeHandle, [ref]$pidValue)) 'Cannot query kernel pipe peer.'
        Assert ($pidValue -eq $configuration.ProcessId) 'Named-pipe server is not the SCM service process.'
        $writer = [IO.StreamWriter]::new($channel, [Text.UTF8Encoding]::new($false), 1024, $true)
        $reader = [IO.StreamReader]::new($channel, [Text.UTF8Encoding]::new($false), $false, 1024, $true)
        try {
            $writer.AutoFlush = $true
            $writer.WriteLine('{"op":"control","command":"sessions"}')
            $read = $reader.ReadLineAsync()
            Assert ($read.Wait(5000)) 'Control response timed out.'
            $reply = $read.Result | ConvertFrom-Json
            Assert ($reply.sessions -eq 0) 'Public/control probes must not open credential sessions.'
        } finally { $writer.Dispose(); $reader.Dispose() }
    } finally { $channel.Dispose() }
}
function Assert-NoKeys {
    Assert (!(Test-Path "$vault/master.key")) 'No-Hello installation must not create a software master key.'
    Assert (!(Test-Path "$vault/vault.enc")) 'Public status must not initialize an encrypted vault.'
    Assert (@(Get-ChildItem $vault -Force -Filter 'device-binding*.key').Count -eq 0) 'Public status must not create binding secrets.'
}
function Test-BadPermissions([string]$Path, [Security.AccessControl.FileSystemRights]$Rights) {
    $original = Get-Acl -LiteralPath $Path
    $bad = Get-Acl -LiteralPath $Path
    $bad.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), $Rights, 'Allow'))
    $pidBefore = (Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId
    try {
        Set-Acl -LiteralPath $Path $bad
        Assert-Throws { & "$repo/scripts/install.ps1" @options } 'Installer accepted an untrusted existing file DACL.'
        Assert ((Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId -eq $pidBefore) 'Rejected upgrade must leave the running service intact.'
    } finally { Set-Acl -LiteralPath $Path $original }
}
try {
    # Exercise the actual ordinary-owner path, with no Administrators group or SeDebug
    # authority. An elevated runner alone can hide broken service/token/marker permissions.
    $testName = 'KVSmoke' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $random = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) } finally { $generator.Dispose() }
    $testPassword = ConvertTo-SecureString ('Kv9!' + [Convert]::ToBase64String($random)) -AsPlainText -Force
    $testUser = New-LocalUser -Name $testName -Password $testPassword -Description 'Disposable KeyValet integration test owner' -PasswordNeverExpires
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users.Name -Member $testUser.SID
    $owner = $testUser.SID.Value
    & "$repo/scripts/package-windows.ps1" -Tag "v$version" -Architecture $architecture -AllowUnsigned -BinaryDirectory $BinaryDirectory
    $options = @{ InstallSystem = $true; OwnerSid = $owner; OwnerProfile = "C:\Users\$testName";
        PackagePath = "$repo/dist/keyvalet-v$version-windows-$architecture.zip"; AllowUnsignedAgent = $true }
    & "$repo/scripts/install.ps1" @options
    Wait-Service 'Running'
    Test-ServicePipe
    $checks.Add('fresh install, SYSTEM identity and authenticated pipe control')
    foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook') {
        Assert ((Get-FileHash "$BinaryDirectory/$binary.exe").Hash -eq (Get-FileHash "$install/bin/$binary.exe").Hash) 'Installed executable differs from package input.'
    }
    $task = Get-ScheduledTask -TaskName KeyValetAgent
    $taskSid = if ($task.Principal.UserId -match '^S-1-') { $task.Principal.UserId }
        else { [Security.Principal.NTAccount]::new($task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value }
    Assert ($taskSid -eq $owner -and $task.Principal.RunLevel -eq 'Limited') 'Login launcher must use the installing owner without elevation.'
    $cli = "$install/bin/kv-cli.exe"
    $output = & $cli status
    Assert ($LASTEXITCODE -eq 0) 'Installed CLI cannot read public protection status.'
    $status = ($output | Out-String) | ConvertFrom-Json
    Assert ($status.provider -eq 'uninitialized') 'A clean no-Hello machine must report an uninitialized vault.'
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $cli; $start.Arguments = 'status'
    $start.WorkingDirectory = 'C:\Windows\System32'
    $start.UserName = $testName; $start.Domain = $env:COMPUTERNAME; $start.Password = $testPassword
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.LoadUserProfile = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $ordinary = [Diagnostics.Process]::Start($start)
    try {
        $readOutput = $ordinary.StandardOutput.ReadToEndAsync()
        $readError = $ordinary.StandardError.ReadToEndAsync()
        if (!$ordinary.WaitForExit(15000)) { $ordinary.Kill(); throw 'Standard-owner status probe timed out.' }
        Assert ($ordinary.ExitCode -eq 0) ("Standard-owner service identity/status probe failed: " + $readError.Result)
        $ordinaryStatus = $readOutput.Result | ConvertFrom-Json
        Assert ($ordinaryStatus.provider -eq 'uninitialized') 'Standard owner must read authenticated public status without elevation or Hello.'
    } finally { $ordinary.Dispose() }
    Test-ServicePipe
    Assert-NoKeys
    $checks.Add('real standard-owner authenticated public status without Hello; no fallback or binding keys')

    Test-BadPermissions "$vault/owner.sid" ([Security.AccessControl.FileSystemRights]::Read)
    Test-BadPermissions "$install/bin/kv-agent.exe" ([Security.AccessControl.FileSystemRights]::WriteData)
    $checks.Add('untrusted owner record and binary DACL rejection before service stop')
    $pidBefore = (Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId
    $wrongOwner = @{} + $options; $wrongOwner.OwnerSid = ($owner -replace '-\d+$', '-999999')
    Assert-Throws { & "$repo/scripts/install.ps1" @wrongOwner } 'Upgrade must not retarget a vault to another owner.'
    Assert ((Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId -eq $pidBefore) 'Wrong-owner rejection stopped the service.'
    Assert ((Get-Content "$vault/owner.sid" -Raw).Trim() -eq $owner) 'Wrong-owner upgrade changed owner.sid.'
    $checks.Add('wrong-owner upgrade rejection')
    & "$repo/scripts/install.ps1" @options
    Wait-Service 'Running'
    Test-ServicePipe
    Assert-NoKeys
    $checks.Add('same-owner upgrade')
    Stop-Service KeyValetHelper
    Wait-Service 'Stopped'
    Start-Service KeyValetHelper
    Wait-Service 'Running'
    Test-ServicePipe
    $checks.Add('SCM stop and restart')

    & "$repo/scripts/uninstall.ps1"
    Assert (!(Get-Service KeyValetHelper -ErrorAction SilentlyContinue)) 'Uninstall left its service registered.'
    Assert (!(Get-ScheduledTask -TaskName KeyValetAgent -ErrorAction SilentlyContinue)) 'Uninstall left its login task.'
    Assert (!(Test-Path $install) -and (Test-Path "$vault/owner.sid")) 'Default uninstall must retain the vault and remove executables.'
    $checks.Add('uninstall retains the vault by default')
} catch {
    $failure = $_.Exception.Message
} finally {
    # The precondition established these paths belong solely to this test. Explicitly remove
    # that test-created vault after verifying the production default preserves it.
    try {
        & "$repo/scripts/uninstall.ps1" -RemoveVault
        Assert (!(Test-Path $install) -and !(Test-Path $vault)) 'Integration cleanup left installation data.'
        $checks.Add('explicit removal and integration cleanup')
    } catch { $failure = "${failure} Cleanup failed: $($_.Exception.Message)" }
    if ($testUser) {
        try {
            Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $testUser.SID.Value -and !$_.Special } | Remove-CimInstance
            Remove-LocalUser -SID $testUser.SID
        } catch { $failure = "${failure} Test-user cleanup failed: $($_.Exception.Message)" }
    }
    if ($testPassword) { $testPassword.Dispose() }
    $report = @{ windows_build = [Environment]::OSVersion.Version.ToString(); architecture = $architecture;
        hello_tested = $false; signing = 'unsigned development'; checks = @($checks.ToArray());
        passed = !$failure; error = $failure; timestamp_utc = [DateTime]::UtcNow.ToString('o') }
    New-Item (Split-Path $ResultPath -Parent) -ItemType Directory -Force | Out-Null
    [IO.File]::WriteAllText($ResultPath, ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
if ($failure) { throw $failure }
Write-Host "Windows service integration checks passed. Report: $ResultPath"
