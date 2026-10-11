# Windows 11 24H2+, Windows Hello required. Run as the intended owner; UAC installs the
# LocalSystem service, then the original user process configures MCP clients and starts its agent.
[CmdletBinding()]
param(
    [ValidatePattern('^v\d+\.\d+\.\d+$')][string]$Tag,
    [string]$PackagePath,
    [switch]$AllowUnsignedAgent,
    [switch]$SkipSetup,
    [switch]$InstallSystem,
    [string]$OwnerSid,
    [string]$OwnerProfile
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installDir = 'C:\Program Files\KeyValet'
$vaultDir = 'C:\ProgramData\KeyValet'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($env:OS -ne 'Windows_NT' -or [Environment]::OSVersion.Version.Build -lt 26100) { throw 'KeyValet requires Windows 11 24H2+ (build 26100+) and Windows Hello.' }
if ($env:SystemDrive -ine 'C:') { throw 'This preview requires Windows on C:; the protected installation paths are fixed.' }

function Write-Utf8([string]$Path, [string]$Text) {
    $temporary = Join-Path (Split-Path $Path -Parent) ('.keyvalet-write-' + [guid]::NewGuid().ToString('N'))
    try {
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function Show-ProtectionStatus([string]$Binary) {
    & $Binary status --summary
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read KeyValet key protection status. Check that KeyValetHelper is running, then run keyvalet status --summary.' }
}
function Assert-PackageChecksum([string]$Path, [string[]]$Lines, [string]$Name) {
    $entries = @($Lines | Where-Object { $_ -match ('^[a-fA-F0-9]{64}\s+\*?' + [regex]::Escape($Name) + '$') })
    if ($entries.Count -ne 1 -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $entries[0].Substring(0, 64)) {
        throw 'Package checksum verification failed.'
    }
}
function Assert-PackageArchive([string]$Path, [string]$Architecture, [string]$ExpectedTag) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if ((Get-Item -LiteralPath $Path).Length -gt 256MB) { throw 'Package archive is too large.' }
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -eq 0 -or $archive.Entries.Count -gt 256) { throw 'Invalid package entry count.' }
        $root = $null; $seen = @{}; $parents = @{}; [long]$total = 0
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            $directory = $name.EndsWith('/')
            $relative = if ($directory) { $name.Substring(0, $name.Length - 1) } else { $name }
            if ($relative.Length -gt 160 -or $relative -match '[<>:"|?*\x00-\x1f]' -or $relative.StartsWith('/')) { throw 'Unsafe ZIP entry.' }
            $parts = @($relative.Split('/'))
            foreach ($part in $parts) {
                # Windows names are case-insensitive, and trailing dots/spaces are aliases.
                # Superscript 1/2/3 are also reserved COM/LPT device numbers.
                if (!$part -or $part -in '.', '..' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
                    $part -match '^(CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])($|\.)') { throw 'Unsafe ZIP path component.' }
            }
            if ($parts[0] -cnotmatch '^keyvalet-(v\d+\.\d+\.\d+)-windows-(x64|arm64)$') { throw 'Invalid package root.' }
            $entryTag = $Matches[1]; $entryArchitecture = $Matches[2]
            if ($entryArchitecture -ne $Architecture -or ($ExpectedTag -and $entryTag -ne $ExpectedTag)) { throw 'Package version or architecture mismatch.' }
            if ($null -eq $root) { $root = $parts[0] }
            if ($parts[0] -cne $root -or ($parts.Count -eq 1 -and !$directory)) { throw 'Package must have one root directory.' }
            $kind = ([long]$entry.ExternalAttributes -shr 16) -band 0xf000
            if (($entry.ExternalAttributes -band 0x400) -or $kind -notin 0, 0x4000, 0x8000 -or
                ($kind -eq 0x4000 -and !$directory) -or ($kind -eq 0x8000 -and $directory)) { throw 'ZIP links and special files are forbidden.' }
            if ($entry.Length -gt 128MB -or ($directory -and $entry.Length -ne 0)) { throw 'Invalid ZIP entry size.' }
            $total += $entry.Length
            if ($total -gt 512MB) { throw 'Unpacked package is too large.' }
            if ($seen.ContainsKey($relative) -or (!$directory -and $parents.ContainsKey($relative))) { throw 'Duplicate or conflicting ZIP entry.' }
            $seen[$relative] = $directory
            for ($i = 1; $i -lt $parts.Count; $i++) {
                $parent = ($parts[0..($i - 1)] -join '/')
                if ($seen.ContainsKey($parent) -and !$seen[$parent]) { throw 'ZIP file is used as a directory.' }
                $parents[$parent] = $true
            }
        }
        foreach ($file in 'bin/kv-helper.exe', 'bin/kv-agent.exe', 'bin/kv-cli.exe', 'bin/kv-mcp.exe', 'bin/kv-hook.exe', 'templates/catalog.json') {
            if (!$seen.ContainsKey("$root/$file") -or $seen["$root/$file"]) { throw "Required package file is missing: $file" }
        }
        return $root
    } finally { $archive.Dispose() }
}
function Assert-BinaryArchitecture([string]$Path, [string]$Architecture) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'Invalid DOS executable header.' }
        $stream.Position = 60; $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt ($stream.Length - 26)) { throw 'Invalid PE header offset.' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE executable signature.' }
        $machine = if ($Architecture -eq 'arm64') { 0xaa64 } else { 0x8664 }
        if ($reader.ReadUInt16() -ne $machine) { throw 'Executable architecture does not match this installation.' }
        $sections = $reader.ReadUInt16()
        if ($sections -lt 1 -or $sections -gt 96) { throw 'Invalid PE section count.' }
        $stream.Position = $offset + 20
        $optionalLength = $reader.ReadUInt16(); $characteristics = $reader.ReadUInt16()
        if ($optionalLength -lt 112 -or ($offset + 24 + $optionalLength + 40 * $sections) -gt $stream.Length -or
            !($characteristics -band 2) -or ($characteristics -band 0x2000) -or $reader.ReadUInt16() -ne 0x20b) { throw 'Invalid PE32+ executable header.' }
    } finally { $reader.Dispose() }
}
function Assert-ServiceConfiguration([string]$BinaryPath, [string]$Account) {
    if ($BinaryPath.Trim() -ine '"C:\Program Files\KeyValet\bin\kv-helper.exe" --service' -or
        $Account -notin 'LocalSystem', 'NT AUTHORITY\SYSTEM') { throw 'The existing KeyValetHelper service has an unexpected executable or account.' }
}
function Assert-PrivilegedFile([string]$Path, [bool]$UserRead) {
    if (!(Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Refusing non-file or reparse point: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    Assert-PrivilegedDescriptor ([Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)) $Path $UserRead
}
function Assert-PrivilegedDescriptor([Security.AccessControl.RawSecurityDescriptor]$Descriptor, [string]$Path, [bool]$UserRead) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if (!$Descriptor.Owner -or $Descriptor.Owner.Value -notin $trusted) { throw "Untrusted owner: $Path" }
    if ($null -eq $Descriptor.DiscretionaryAcl) { throw "Null DACL grants everyone access: $Path" }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) { continue }
        if ($ace -is [Security.AccessControl.QualifiedAce] -and $ace.AceQualifier -eq 'AccessDenied') { continue }
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.AceQualifier -ne 'AccessAllowed') { throw "Unsupported DACL entry: $Path" }
        # AccessMask is signed Int32. Reinterpret its bits so GENERIC_READ remains read-only.
        $mask = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$ace.AccessMask), 0)
        $unsafeRights = if ($UserRead) { $mask -band 0x500d0156 } else { $mask }
        if ($unsafeRights -and $ace.SecurityIdentifier.Value -notin $trusted) { throw "Untrusted DACL: $Path" }
    }
}
function Set-ProtectedDirectory([string]$Path, [bool]$UserRead) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if ($UserRead) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if (Test-Path $Path) {
        $item = Get-Item $Path -Force
        if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Refusing non-directory or reparse point: $Path" }
        $existing = Get-Acl -LiteralPath $Path
        Assert-PrivilegedDescriptor ([Security.AccessControl.RawSecurityDescriptor]::new($existing.GetSecurityDescriptorBinaryForm(), 0)) $Path $UserRead
    } else {
        # Assign security at creation, without an intermediate directory inheriting Temp or
        # ProgramData permissions. .NET Framework and modern .NET expose different APIs.
        $create = [IO.Directory].GetMethod('CreateDirectory', [type[]]@([string], [Security.AccessControl.DirectorySecurity]))
        if ($create) { [void]$create.Invoke($null, @($Path, $acl)) }
        else { [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $acl) }
        # CreateDirectory can return an existing path. Refuse a raced-in directory/link
        # instead of granting it our ownership and treating preexisting contents as trusted.
        $created = Get-Item -LiteralPath $Path -Force
        if (!$created.PSIsContainer -or ($created.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Untrusted newly created directory: $Path" }
        $createdAcl = Get-Acl -LiteralPath $Path
        Assert-PrivilegedDescriptor ([Security.AccessControl.RawSecurityDescriptor]::new($createdAcl.GetSecurityDescriptorBinaryForm(), 0)) $Path $UserRead
    }
    Set-Acl $Path $acl
}
function Assert-SignedBinary([string]$Path) {
    if ($AllowUnsignedAgent) { return }
    $signature = Get-AuthenticodeSignature $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
        $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Simvito Limited') {
        throw "Refusing unsigned or wrong-publisher binary: $Path. -AllowUnsignedAgent is for development builds only."
    }
}
function Quote-Argument([string]$Value) {
    # CommandLineToArgvW quoting for the elevation boundary, including embedded quotes and
    # trailing backslashes. This is argv data, never interpolated into a PowerShell expression.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

if (!$InstallSystem) {
    $OwnerSid = $identity.User.Value
    $OwnerProfile = $env:USERPROFILE
    $scriptPath = $PSCommandPath
    if (!$scriptPath) {
        # Also works when bootstrapped with irm ... | iex.
        $scriptPath = Join-Path ([IO.Path]::GetTempPath()) ("keyvalet-installer-" + [guid]::NewGuid().ToString('N') + '.ps1')
        Invoke-WebRequest 'https://raw.githubusercontent.com/KeyValet/KeyValet/main/scripts/install.ps1' -UseBasicParsing -OutFile $scriptPath
    }
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Quote-Argument $scriptPath), '-InstallSystem',
        '-OwnerSid', (Quote-Argument $OwnerSid), '-OwnerProfile', (Quote-Argument $OwnerProfile))
    if ($Tag) { $arguments += @('-Tag', $Tag) }
    if ($PackagePath) { $arguments += @('-PackagePath', (Quote-Argument ([IO.Path]::GetFullPath($PackagePath)))) }
    if ($AllowUnsignedAgent) { $arguments += '-AllowUnsignedAgent' }
    $powershell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process $powershell -Verb RunAs -ArgumentList $arguments -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw 'KeyValet system installation failed.' }

    function To-Map($Value) {
        if ($null -eq $Value) { return $null }
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            $map = @{}; foreach ($property in $Value.PSObject.Properties) { $map[$property.Name] = To-Map $property.Value }; return $map
        }
        if ($Value -is [array]) { return ,@($Value | ForEach-Object { To-Map $_ }) }
        return $Value
    }
    function Update-Json([string]$Path, [scriptblock]$Update) {
        $config = @{}
        if (Test-Path $Path) { $config = To-Map (Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json) }
        if ($config -isnot [hashtable]) { throw "Expected an object in $Path" }
        & $Update $config
        if (Test-Path $Path) { Copy-Item $Path "$Path.bak-keyvalet" -Force }
        $parent = Split-Path $Path -Parent
        New-Item $parent -ItemType Directory -Force | Out-Null
        Write-Utf8 $Path (($config | ConvertTo-Json -Depth 50) + "`n")
    }
    $mcp = "$installDir\bin\kv-mcp.exe"
    $hook = '"' + "$installDir\bin\kv-hook.exe" + '"'
    foreach ($path in "$OwnerProfile\.claude.json", "$OwnerProfile\.cursor\mcp.json") {
        Update-Json $path { param($config)
            if (!$config.ContainsKey('mcpServers')) { $config.mcpServers = @{} }
            if ($config.mcpServers -isnot [hashtable]) { throw 'Expected mcpServers to be an object.' }
            $config.mcpServers.keyvalet = @{ command = $mcp; args = @() }
        }
    }
    $codex = "$OwnerProfile\.codex\config.toml"
    New-Item (Split-Path $codex -Parent) -ItemType Directory -Force | Out-Null
    if (!(Test-Path $codex)) { Write-Utf8 $codex '' }
    $toml = Get-Content $codex -Raw -Encoding UTF8
    if ($toml -notmatch '(?m)^\s*\[mcp_servers\.keyvalet\]') {
        Copy-Item $codex "$codex.bak-keyvalet" -Force
        Write-Utf8 $codex ($toml + "`n[mcp_servers.keyvalet]`ncommand = '" + $mcp + "'`nargs = []`n")
    } else { Write-Host 'Existing Codex keyvalet MCP entry kept; ensure its command points to kv-mcp.exe.' }
    function Is-KeyValetHook($Entry) {
        if ($Entry -isnot [hashtable] -or !$Entry.ContainsKey('command') -or $Entry.command -isnot [string]) { return $false }
        $prefix = '"C:\Program Files\KeyValet\bin\kv-hook.exe"'
        return $Entry.command.Equals($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            $Entry.command.StartsWith($prefix + ' ', [StringComparison]::OrdinalIgnoreCase)
    }
    function Keep-OtherHooks($Entry) {
        if (Is-KeyValetHook $Entry) { return $null }
        if ($Entry -is [hashtable] -and $Entry.ContainsKey('hooks') -and $Entry.hooks -is [array]) {
            $remaining = @($Entry.hooks | Where-Object { !(Is-KeyValetHook $_) })
            if (!$remaining.Count) { return $null }
            $Entry.hooks = $remaining
        }
        return $Entry
    }
    function Add-Hooks([string]$Path, [hashtable]$Hooks, [switch]$Cursor) {
        Update-Json $Path { param($config)
            if ($Cursor) { $config.version = 1 }
            if (!$config.ContainsKey('hooks')) { $config.hooks = @{} }
            if ($config.hooks -isnot [hashtable]) { throw 'Expected hooks to be an object.' }
            foreach ($event in $Hooks.Keys) {
                if ($config.hooks.ContainsKey($event) -and $config.hooks[$event] -isnot [array]) { throw "Expected a hook array for $event." }
                $existing = @($config.hooks[$event] | Where-Object { $null -ne $_ })
                # Replace only installed commands; preserve other commands even in a shared
                # Claude/Codex hook row that also contains one of our old hooks.
                $existing = @($existing | ForEach-Object { Keep-OtherHooks $_ } | Where-Object { $null -ne $_ })
                $config.hooks[$event] = @($existing) + @($Hooks[$event])
            }
        }
    }
    Add-Hooks "$OwnerProfile\.claude\settings.json" @{
        UserPromptSubmit = @(@{ hooks = @(@{ type = 'command'; command = "$hook prompt" }) })
        PreToolUse = @(@{ matcher = 'Bash|Write|Edit|MultiEdit|mcp__.*'; hooks = @(@{ type = 'command'; command = "$hook tool" }) })
    }
    Add-Hooks "$OwnerProfile\.codex\hooks.json" @{
        PreToolUse = @(@{ matcher = 'Bash|apply_patch|mcp__.*'; hooks = @(@{ type = 'command'; command = "$hook codex-tool" }) })
    }
    Add-Hooks "$OwnerProfile\.cursor\hooks.json" -Cursor @{
        beforeShellExecution = @(@{ command = "$hook cursor-shell"; timeout = 10 })
        beforeMCPExecution = @(@{ command = "$hook cursor-mcp"; timeout = 10 })
        preToolUse = @(@{ matcher = 'Write|Edit|MultiEdit'; command = "$hook cursor-tool"; timeout = 10 })
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (@($userPath -split ';') -notcontains "$installDir\bin") {
        [Environment]::SetEnvironmentVariable('Path', (([string]$userPath).TrimEnd(';') + ";$installDir\bin").TrimStart(';'), 'User')
    }
    $env:PATH += ";$installDir\bin"
    # Start in the original interactive token; the elevated installer never creates a Hello key.
    if (!$elevated) { Start-Process "$installDir\bin\kv-agent.exe" -WindowStyle Hidden }
    else { Write-Host 'Started installation from an elevated shell. Sign out/in so the agent runs unelevated before setup-hello.' }
    if (!$SkipSetup -and !$elevated) {
        Start-Sleep -Seconds 2
        $setup = Start-Process "$installDir\bin\kv-cli.exe" -Verb RunAs -ArgumentList 'setup-hello' -PassThru -Wait
        if ($setup.ExitCode -ne 0) { throw 'Hello setup did not complete. Run kv-cli.exe setup-hello in an elevated terminal after the agent starts.' }
    }
    # Public metadata is read through the authenticated service in the original console.
    # This also reports an uninitialized vault when setup was skipped.
    Show-ProtectionStatus "$installDir\bin\kv-cli.exe"
    Write-Host 'KeyValet installed. Restart your AI clients. In Codex, trust the hooks with /hooks.'
    return
}

if (!$elevated) { throw 'The system installation phase requires UAC elevation.' }
if (!$OwnerSid -or !$OwnerProfile) { throw 'The installing user SID and profile must be supplied.' }
$owner = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
if ($OwnerSid -notmatch '^S-1-(5-21-\d+-\d+-\d+-\d+|12-1-\d+-\d+-\d+-\d+)$') { throw 'Install for an interactive Windows user, not a service/group identity.' }
$stage = Join-Path 'C:\Windows\Temp' ('KeyValet-' + [guid]::NewGuid().ToString('N'))
Set-ProtectedDirectory $stage $false
$service = $null
$serviceProcess = $null
try {
    $architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
    if (!$PackagePath) {
        if (!$Tag) {
            $release = Invoke-RestMethod 'https://api.github.com/repos/KeyValet/KeyValet/releases/latest'
            $Tag = $release.tag_name
            if ($Tag -notmatch '^v\d+\.\d+\.\d+$') { throw 'Unexpected release tag.' }
        }
        $name = "keyvalet-$Tag-windows-$architecture.zip"
        $base = "https://github.com/KeyValet/KeyValet/releases/download/$Tag"
        Invoke-WebRequest "$base/$name" -UseBasicParsing -OutFile "$stage/package.zip"
        Invoke-WebRequest "$base/SHA256SUMS" -UseBasicParsing -OutFile "$stage/SHA256SUMS"
        Assert-PackageChecksum "$stage/package.zip" @(Get-Content "$stage/SHA256SUMS") $name
    } else { Copy-Item -LiteralPath $PackagePath "$stage/package.zip" }
    $root = Assert-PackageArchive "$stage/package.zip" $architecture $Tag
    Expand-Archive "$stage/package.zip" "$stage/unpacked"
    $package = Join-Path "$stage/unpacked" $root
    foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook') {
        Assert-BinaryArchitecture "$package/bin/$binary.exe" $architecture
        Assert-SignedBinary "$package/bin/$binary.exe"
    }
    if (!(Test-Path "$package/templates/catalog.json")) { throw 'Package template catalog is missing.' }
    # Refuse to silently retarget a device-bound vault during an upgrade by another account.
    # Validate its protected directory before reading any existing owner record.
    Set-ProtectedDirectory $installDir $true
    Set-ProtectedDirectory $vaultDir $false
    Assert-PrivilegedFile "$vaultDir/owner.sid" $false
    Assert-PrivilegedFile "$vaultDir/allow-unsigned-agent" $false
    Assert-PrivilegedFile "$installDir/allow-unsigned-agent" $true
    if (Test-Path "$vaultDir/owner.sid") {
        $previousOwner = (Get-Content "$vaultDir/owner.sid" -Raw -Encoding UTF8).Trim()
        if ($previousOwner -ne $OwnerSid) { throw 'This vault belongs to another Windows account. Use that account to upgrade; recovery or removal must be explicit.' }
    }
    $service = Get-Service KeyValetHelper -ErrorAction SilentlyContinue
    if ($service) {
        $configuration = Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'"
        Assert-ServiceConfiguration $configuration.PathName $configuration.StartName
        if ($configuration.ProcessId -gt 0) {
            $serviceProcess = [Diagnostics.Process]::GetProcessById($configuration.ProcessId)
            [void]$serviceProcess.Handle # Retain the actual process before it can exit/reuse its PID.
        }
    }
    # Validate existing leaf permissions before overwriting anything or stopping the service.
    Set-ProtectedDirectory "$installDir/bin" $true
    Set-ProtectedDirectory "$installDir/templates" $true
    foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook') { Assert-PrivilegedFile "$installDir/bin/$binary.exe" $true }
    Assert-PrivilegedFile "$installDir/bin/keyvalet.ps1" $true
    Assert-PrivilegedFile "$installDir/templates/catalog.json" $true
    if ($service) {
        Stop-Service KeyValetHelper -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
        if ($serviceProcess -and !$serviceProcess.WaitForExit(20000)) { throw 'The stopped helper process has not exited; binaries were not replaced.' }
    }
    Get-CimInstance Win32_Process -Filter "Name='kv-agent.exe' OR Name='kv-mcp.exe'" | Where-Object { $_.ExecutablePath -in @("$installDir\bin\kv-agent.exe", "$installDir\bin\kv-mcp.exe") } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook') {
        Copy-Item "$package/bin/$binary.exe" "$installDir/bin/" -Force
        # Copied files inherit the protected install ACL and a privileged owner.
        & 'C:\Windows\System32\icacls.exe' "$installDir\bin\$binary.exe" /reset | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot reset binary permissions.' }
        & 'C:\Windows\System32\icacls.exe' "$installDir\bin\$binary.exe" /setowner '*S-1-5-32-544' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot set binary owner.' }
    }
    Copy-Item "$package/templates/catalog.json" "$installDir/templates/" -Force
    Write-Utf8 "$vaultDir/owner.sid" ($OwnerSid + "`n")
    & 'C:\Windows\System32\icacls.exe' "$vaultDir\owner.sid" /reset /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect owner.sid.' }
    if ($AllowUnsignedAgent) {
        Write-Utf8 "$installDir/allow-unsigned-agent" 'Explicit unsigned development installation.'
        & 'C:\Windows\System32\icacls.exe' "$installDir\allow-unsigned-agent" /reset /setowner '*S-1-5-32-544' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the development marker.' }
    }
    elseif (Test-Path "$installDir/allow-unsigned-agent") { Remove-Item "$installDir/allow-unsigned-agent" -Force }
    # Remove the preview's former private location after validating its ACL above.
    if (Test-Path "$vaultDir/allow-unsigned-agent") { Remove-Item "$vaultDir/allow-unsigned-agent" -Force }
    if (!$service) {
        New-Service -Name KeyValetHelper -DisplayName 'KeyValet Helper' -BinaryPathName ('"' + "$installDir\bin\kv-helper.exe" + '" --service') -StartupType Automatic | Out-Null
    } else {
        & 'C:\Windows\System32\sc.exe' config KeyValetHelper binPath= ('"' + "$installDir\bin\kv-helper.exe" + '" --service') start= auto obj= LocalSystem | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot configure KeyValetHelper.' }
    }
    $action = New-ScheduledTaskAction -Execute "$installDir\bin\kv-agent.exe"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $OwnerSid
    $principal = New-ScheduledTaskPrincipal -UserId $OwnerSid -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval ([TimeSpan]::FromMinutes(1)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName KeyValetAgent -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-Service KeyValetHelper
    # Management commands require elevation; public status queries run in the original console.
    # Use kv-cli.exe from an elevated terminal for piped input.
    Write-Utf8 "$installDir/bin/keyvalet.ps1" @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
$binary = 'C:\Program Files\KeyValet\bin\kv-cli.exe'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin -or ($Arguments -and $Arguments[0] -in @('status', 'protection'))) { & $binary @Arguments; exit $LASTEXITCODE }
$quoted = @($Arguments | ForEach-Object { '"' + [regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"' })
$process = Start-Process $binary -Verb RunAs -ArgumentList $quoted -Wait -PassThru
exit $process.ExitCode
'@
    & 'C:\Windows\System32\icacls.exe' "$installDir\bin\keyvalet.ps1" /reset /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the CLI wrapper.' }
} finally {
    if ($service) { $service.Dispose() }
    if ($serviceProcess) { $serviceProcess.Dispose() }
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
