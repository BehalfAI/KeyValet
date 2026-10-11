# Read-only/offline validation: never installs KeyValet, elevates, or needs an existing vault.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
$scripts = @('scripts/install.ps1', 'scripts/uninstall.ps1', 'scripts/package-windows.ps1', 'scripts/test-windows-service.ps1', 'site/static/install.ps1')
foreach ($script in $scripts) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $script), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
}
# Evaluate only configuration helpers and the public-status runner from the parsed source. Its
# top-level installer, UAC, network and service actions are never executed by this test.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile("$repo/scripts/install.ps1", [ref]$tokens, [ref]$errors)
foreach ($name in 'Write-Utf8', 'Show-ProtectionStatus', 'To-Map', 'Update-Json', 'Is-KeyValetHook', 'Keep-OtherHooks', 'Add-Hooks', 'Quote-Argument', 'Assert-PackageChecksum', 'Assert-PackageArchive', 'Assert-BinaryArchitecture', 'Assert-ServiceConfiguration', 'Assert-PrivilegedDescriptor') {
    $definition = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object Name -eq $name | Select-Object -First 1
    if (!$definition) { throw "Missing helper: $name" }
    Invoke-Expression $definition.Extent.Text
}
function Assert([bool]$Condition, [string]$Message) { if (!$Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert $threw $Message
}
function New-TestArchive([string[]]$Names, [int]$LastAttributes = 0) {
    $path = Join-Path $temp ([guid]::NewGuid().ToString('N') + '.zip')
    $archive = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Names) {
            $entry = $archive.CreateEntry($name)
            if (!$name.EndsWith('/') -and !$name.EndsWith('\')) {
                $stream = $entry.Open()
                try { $stream.WriteByte(42) } finally { $stream.Dispose() }
            }
        }
        if ($LastAttributes) { $entry.ExternalAttributes = $LastAttributes }
    } finally { $archive.Dispose() }
    return $path
}
function Set-DeclaredZipLengths([string]$Path, [uint32]$Length, [switch]$FirstOnly) {
    # Change central-directory sizes without allocating/decompressing a giant test archive.
    $bytes = [IO.File]::ReadAllBytes($Path)
    for ($i = 0; $i -lt $bytes.Length - 28; $i++) {
        if ([BitConverter]::ToUInt32($bytes, $i) -eq 0x02014b50) {
            [Array]::Copy([BitConverter]::GetBytes($Length), 0, $bytes, $i + 24, 4)
            if ($FirstOnly) { break }
        }
    }
    [IO.File]::WriteAllBytes($Path, $bytes)
}
function New-TestExecutable([string]$Path, [uint16]$Machine) {
    $bytes = [byte[]]::new(512)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x5a4d), 0, $bytes, 0, 2)
    [Array]::Copy([BitConverter]::GetBytes([int32]64), 0, $bytes, 60, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x4550), 0, $bytes, 64, 4)
    [Array]::Copy([BitConverter]::GetBytes($Machine), 0, $bytes, 68, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]1), 0, $bytes, 70, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]240), 0, $bytes, 84, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]2), 0, $bytes, 86, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x20b), 0, $bytes, 88, 2)
    [IO.File]::WriteAllBytes($Path, $bytes)
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('keyvalet-config-test-' + [guid]::NewGuid().ToString('N'))
New-Item $temp -ItemType Directory | Out-Null
try {
    # This fake CLI accepts only the public status operation and records its exact arguments.
    # The real installer, UAC, Hello setup, SYSTEM service and installed paths are never run.
    $fakeStatus = Join-Path $temp 'fake-status.ps1'
    $statusCalls = Join-Path $temp 'status-calls.txt'
    Write-Utf8 $fakeStatus @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
if ($Arguments.Count -ne 2 -or $Arguments[0] -cne 'status' -or $Arguments[1] -cne '--summary') { throw 'Unexpected non-status command.' }
[IO.File]::AppendAllText($env:KEYVALET_TEST_STATUS_CALLS, ($Arguments -join ' ') + [Environment]::NewLine)
Write-Output $env:KEYVALET_TEST_STATUS_TEXT
exit ([int]$env:KEYVALET_TEST_STATUS_EXIT)
'@
    $previousStatusEnv = @{}
    foreach ($name in 'KEYVALET_TEST_STATUS_CALLS', 'KEYVALET_TEST_STATUS_TEXT', 'KEYVALET_TEST_STATUS_EXIT') {
        $previousStatusEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    try {
        $env:KEYVALET_TEST_STATUS_CALLS = $statusCalls
        $env:KEYVALET_TEST_STATUS_EXIT = '0'
        foreach ($text in 'UNCONFIRMED (unknown)', 'SOFTWARE PROTECTION ONLY', 'NOT CONFIGURED', 'OS-reported TPM protection') {
            $env:KEYVALET_TEST_STATUS_TEXT = $text
            $shown = Show-ProtectionStatus $fakeStatus
            Assert ($shown -ceq $text) 'The installer must display the actual CLI status without replacing unknown or software protection.'
        }
        $env:KEYVALET_TEST_STATUS_EXIT = '23'
        Assert-Throws { Show-ProtectionStatus $fakeStatus } 'An unavailable protection report must abort installation before success is announced.'
        $env:KEYVALET_TEST_STATUS_EXIT = '0'
        Show-ProtectionStatus $fakeStatus | Out-Null
        Assert (@(Get-Content $statusCalls).Count -eq 6) 'Every installer status query must invoke only status --summary.'
    } finally {
        foreach ($name in $previousStatusEnv.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previousStatusEnv[$name], 'Process')
        }
    }
    $configPath = Join-Path $temp 'cursor/hooks.json'
    $hook = '"C:\Program Files\KeyValet\bin\kv-hook.exe"'
    Update-Json $configPath { param($config) $config.label = [string][char]0x4e2d + [string][char]0x6587; $config.hooks = @{ beforeShellExecution = @(@{ command = 'user-existing-hook' }) } }
    $hooks = @{ beforeShellExecution = @(@{ command = "$hook cursor-shell" }) }
    Add-Hooks $configPath $hooks -Cursor
    Add-Hooks $configPath $hooks -Cursor
    $config = To-Map (Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    Assert ($config.version -eq 1) 'Cursor requires hook schema version 1.'
    Assert ($config.label -eq ([string][char]0x4e2d + [string][char]0x6587)) 'Unicode config must survive.'
    Assert ($config.hooks.beforeShellExecution.Count -eq 2) 'Hooks must be idempotent and preserve user hooks.'
    Assert ($config.hooks.beforeShellExecution[0].command -eq 'user-existing-hook') 'Existing hook changed.'
    Assert ($config.hooks.beforeShellExecution[1].command -eq "$hook cursor-shell") 'Windows path quoting changed.'
    Assert (Test-Path "$configPath.bak-keyvalet") 'Existing config needs a backup.'
    $sharedHooks = Join-Path $temp 'claude/settings.json'
    Update-Json $sharedHooks { param($config) $config.hooks = @{
        PreToolUse = @(@{ matcher = 'Bash'; label = 'keep me'; hooks = @(
            @{ type = 'command'; command = "$hook tool" },
            @{ type = 'command'; command = 'user-script --note kv-hook.exe' }) },
            @{ matcher = 'Write'; hooks = @(@{ type = 'command'; command = '"C:\Other\kv-hook.exe" tool' }) });
        OtherEvent = @(@{ command = 'unrelated hook' }) } }
    $ourHooks = @{ PreToolUse = @(@{ matcher = 'Bash|Write'; hooks = @(@{ type = 'command'; command = "$hook tool" }) }) }
    Add-Hooks $sharedHooks $ourHooks
    Add-Hooks $sharedHooks $ourHooks
    $config = To-Map (Get-Content $sharedHooks -Raw -Encoding UTF8 | ConvertFrom-Json)
    Assert ($config.hooks.PreToolUse.Count -eq 3) 'Shared user hook rows must survive idempotent installation.'
    Assert ($config.hooks.PreToolUse[0].label -eq 'keep me' -and $config.hooks.PreToolUse[0].hooks.Count -eq 1) 'Removing our command must preserve other commands and row fields.'
    Assert ($config.hooks.PreToolUse[0].hooks[0].command -eq 'user-script --note kv-hook.exe') 'A filename in an unrelated command is not our hook.'
    Assert ($config.hooks.PreToolUse[1].hooks[0].command -eq '"C:\Other\kv-hook.exe" tool') 'An executable outside our installation must be preserved.'
    Assert ($config.hooks.OtherEvent[0].command -eq 'unrelated hook') 'Untouched hook events must survive.'
    foreach ($invalid in '{"hooks":null}', '{"hooks":[]}', '{"hooks":{"PreToolUse":"bad"}}') {
        Write-Utf8 $sharedHooks $invalid
        Assert-Throws { Add-Hooks $sharedHooks $ourHooks } 'Invalid hook schemas must be refused.'
        Assert ([IO.File]::ReadAllText($sharedHooks) -ceq $invalid) 'Invalid hook schemas must not be overwritten.'
    }
    $mcpPath = Join-Path $temp 'mcp.json'
    Update-Json $mcpPath { param($config) $config.mcpServers = @{ existing = @{ command = 'existing.exe' } } }
    $mcp = 'C:\Program Files\KeyValet\bin\kv-mcp.exe'
    Update-Json $mcpPath { param($config) $config.mcpServers.keyvalet = @{ command = $mcp; args = @() } }
    $config = To-Map (Get-Content $mcpPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    Assert ($config.mcpServers.existing.command -eq 'existing.exe') 'Other MCP servers must survive.'
    Assert ($config.mcpServers.keyvalet.command -eq $mcp) 'MCP path changed.'
    Assert ($config.mcpServers.keyvalet.args.Count -eq 0) 'Empty args must remain an array.'
    Assert ((Quote-Argument 'C:\Program Files\KeyValet\') -eq '"C:\Program Files\KeyValet\\"') 'Trailing backslash quoting is invalid.'
    Assert ((Quote-Argument 'a"b') -eq '"a\"b"') 'Embedded quote escaping is invalid.'

    $before = [IO.File]::ReadAllText($mcpPath)
    Assert-Throws { Update-Json $mcpPath { param($config) $config.mcpServers = 'broken'; throw 'synthetic update failure' } } 'Failed update must throw.'
    Assert ([IO.File]::ReadAllText($mcpPath) -ceq $before) 'Failed updates must preserve the original file.'
    Write-Utf8 $mcpPath '{invalid'
    Assert-Throws { Update-Json $mcpPath { param($config) $config.new = 1 } } 'Invalid JSON must be refused.'
    Assert ([IO.File]::ReadAllText($mcpPath) -ceq '{invalid') 'Malformed existing JSON must not be overwritten.'
    foreach ($invalid in 'null', '[]', '42', '"text"') {
        Write-Utf8 $mcpPath $invalid
        Assert-Throws { Update-Json $mcpPath { param($config) $config.new = 1 } } 'A config root must be an object.'
        Assert ([IO.File]::ReadAllText($mcpPath) -ceq $invalid) 'Invalid config roots must survive unchanged.'
    }
    Assert (@(Get-ChildItem $temp -Recurse -Force | Where-Object Name -like '.keyvalet-write-*').Count -eq 0) 'Atomic writes must not leave temporary files.'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $root = 'keyvalet-v0.2.1-windows-x64'
    $required = @('bin/kv-helper.exe', 'bin/kv-agent.exe', 'bin/kv-cli.exe', 'bin/kv-mcp.exe', 'bin/kv-hook.exe', 'templates/catalog.json')
    $names = @($required | ForEach-Object { "$root/$_" })
    $valid = New-TestArchive ($names + @("$root/", "$root/docs/", "$root/docs/windows.md"))
    Assert ((Assert-PackageArchive $valid 'x64' 'v0.2.1') -ceq $root) 'A valid release archive must be accepted.'
    Assert ((Assert-PackageArchive $valid 'x64' '') -ceq $root) 'Local packages can infer their version from the root.'
    Assert-Throws { Assert-PackageArchive $valid 'arm64' 'v0.2.1' } 'Wrong archive architecture must be refused.'
    Assert-Throws { Assert-PackageArchive $valid 'x64' 'v0.2.2' } 'Wrong archive version must be refused.'
    $validBackslashes = New-TestArchive @($names | ForEach-Object { $_.Replace('/', '\') })
    Assert ((Assert-PackageArchive $validBackslashes 'x64' 'v0.2.1') -ceq $root) 'Windows ZIP separators must be handled consistently.'
    $unsafe = @('../escape', '/absolute', '\\server\share\file', 'C:\escape',
        "$root/../escape", "$root/bin/..\escape", "$root/bin/./file", "$root//file", "$root/bin/file.", "$root/bin/file ",
        "$root/bin/file:stream", "$root/bin/NUL.txt", "$root/bin/COM1", "$root/bin/LPT9.txt",
        ($root + '/bin/COM' + [char]0xb9 + '.txt'), "$root/bin/quote`".txt", "$root/bin/question?.txt", ("$root/bin/" + [char]0 + 'nul'),
        "$root/bin/kv-cli.exe", "$root/bin/KV-CLI.EXE", "$root/bin", 'loose-root-file.txt',
        'keyvalet-v0.2.2-windows-x64/docs/file.txt', ("$root/" + ('x' * 170)))
    foreach ($name in $unsafe) {
        $archive = New-TestArchive ($names + @($name))
        Assert-Throws { Assert-PackageArchive $archive 'x64' 'v0.2.1' } "Unsafe archive entry accepted: $name"
    }
    $missing = New-TestArchive $names[0..4]
    Assert-Throws { Assert-PackageArchive $missing 'x64' 'v0.2.1' } 'Missing required files must be rejected.'
    $empty = New-TestArchive @()
    Assert-Throws { Assert-PackageArchive $empty 'x64' 'v0.2.1' } 'Empty ZIP must be rejected.'
    $tooMany = New-TestArchive @((0..256) | ForEach-Object { "$root/docs/$_" })
    Assert-Throws { Assert-PackageArchive $tooMany 'x64' 'v0.2.1' } 'Excessive ZIP entry count must be bounded.'
    foreach ($attributes in 0xa0000000, 0x10000000, 0x400, 0x40000000) {
        $archive = New-TestArchive ($names + @("$root/docs/link")) $attributes
        Assert-Throws { Assert-PackageArchive $archive 'x64' 'v0.2.1' } 'Links/special files must be refused.'
    }
    $large = New-TestArchive $names
    Set-DeclaredZipLengths $large (129MB) -FirstOnly
    Assert-Throws { Assert-PackageArchive $large 'x64' 'v0.2.1' } 'Single-file expansion must be bounded.'
    $large = New-TestArchive $names
    Set-DeclaredZipLengths $large (100MB)
    Assert-Throws { Assert-PackageArchive $large 'x64' 'v0.2.1' } 'Total expansion must be bounded.'

    $hash = (Get-FileHash $valid -Algorithm SHA256).Hash.ToLowerInvariant()
    $zipName = "$root.zip"
    Assert-PackageChecksum $valid @("$hash  $zipName") $zipName
    Assert-PackageChecksum $valid @("$hash *$zipName", ($hash + '  other.zip')) $zipName
    foreach ($lines in @(@("$hash  $zipName", "$hash  $zipName"), @('invalid checksum'), @((('0' * 64) + "  $zipName")), @("$hash  $zipName.exe"))) {
        Assert-Throws { Assert-PackageChecksum $valid $lines $zipName } 'Missing, duplicate or mismatched checksum must be rejected.'
    }

    $executable = Join-Path $temp 'test.exe'
    New-TestExecutable $executable 0x8664
    Assert-BinaryArchitecture $executable 'x64'
    Assert-Throws { Assert-BinaryArchitecture $executable 'arm64' } 'Wrong PE machine must be refused.'
    New-TestExecutable $executable 0xaa64
    Assert-BinaryArchitecture $executable 'arm64'
    foreach ($case in 'MZ', 'offset-negative', 'offset-past-eof', 'signature', 'x86', 'sections', 'optional-short', 'PE32', 'DLL', 'truncated') {
        New-TestExecutable $executable 0x8664
        $bytes = [IO.File]::ReadAllBytes($executable)
        switch ($case) {
            'MZ' { $bytes[0] = 0 }
            'offset-negative' { [Array]::Copy([BitConverter]::GetBytes([int32]-1), 0, $bytes, 60, 4) }
            'offset-past-eof' { [Array]::Copy([BitConverter]::GetBytes([int32]500), 0, $bytes, 60, 4) }
            'signature' { $bytes[64] = 0 }
            'x86' { [Array]::Copy([BitConverter]::GetBytes([uint16]0x14c), 0, $bytes, 68, 2) }
            'sections' { $bytes[70] = 0 }
            'optional-short' { $bytes[84] = 0 }
            'PE32' { [Array]::Copy([BitConverter]::GetBytes([uint16]0x10b), 0, $bytes, 88, 2) }
            'DLL' { [Array]::Copy([BitConverter]::GetBytes([uint16]0x2002), 0, $bytes, 86, 2) }
            'truncated' { $bytes = $bytes[0..87] }
        }
        [IO.File]::WriteAllBytes($executable, $bytes)
        Assert-Throws { Assert-BinaryArchitecture $executable 'x64' } "Malformed PE accepted: $case"
    }
    Assert-ServiceConfiguration '"C:\Program Files\KeyValet\bin\kv-helper.exe" --service' 'LocalSystem'
    Assert-Throws { Assert-ServiceConfiguration 'C:\other.exe' 'LocalSystem' } 'Existing service executable cannot be silently changed.'
    Assert-Throws { Assert-ServiceConfiguration '"C:\Program Files\KeyValet\bin\kv-helper.exe" --service' 'user' } 'Existing service must run as SYSTEM.'
    if ($env:OS -eq 'Windows_NT') {
        # Real Windows descriptor parsing, without root, installed paths or machine ACLs.
        $trusted = 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        Assert-PrivilegedDescriptor ([Security.AccessControl.RawSecurityDescriptor]::new($trusted)) 'synthetic' $false
        foreach ($rights in 'FR', 'GR', 'GX', '0x00120089') {
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($trusted + "(A;;$rights;;;BU)")
            Assert-PrivilegedDescriptor $descriptor 'synthetic' $true
            Assert-Throws { Assert-PrivilegedDescriptor $descriptor 'synthetic' $false } 'Private vault descriptors must forbid other-user reads.'
        }
        foreach ($rights in 'FW', 'GW', 'GA', '0x00000100', '0x00010000', '0x00040000', '0x00080000') {
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($trusted + "(A;;$rights;;;BU)")
            Assert-Throws { Assert-PrivilegedDescriptor $descriptor 'synthetic' $true } 'Write-like rights must be refused even in readable install files.'
        }
        $nullDacl = [Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:NO_ACCESS_CONTROL')
        Assert-Throws { Assert-PrivilegedDescriptor $nullDacl 'synthetic' $true } 'A null DACL must not be repaired as trusted.'
        $untrustedOwner = [Security.AccessControl.RawSecurityDescriptor]::new('O:BUG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)')
        Assert-Throws { Assert-PrivilegedDescriptor $untrustedOwner 'synthetic' $true } 'An unprivileged owner must be refused.'
        Assert-PrivilegedDescriptor ([Security.AccessControl.RawSecurityDescriptor]::new($trusted + '(D;;FW;;;BU)(A;IO;FW;;;BU)')) 'synthetic' $true
        $callback = [Security.AccessControl.RawSecurityDescriptor]::new($trusted)
        $callback.DiscretionaryAcl.InsertAce(0, [Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]::None, [Security.AccessControl.AceQualifier]::AccessAllowed, 2,
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), $true, [byte[]]::new(0)))
        Assert-Throws { Assert-PrivilegedDescriptor $callback 'synthetic' $true } 'Unevaluated callback ACEs must fail closed.'
        Write-Host 'Native Windows ACL descriptor policy tests passed.'
    }
    Write-Host 'Windows scripts parse; protection status, config, atomic writes, quoting, archive, checksum, PE and service policy tests passed.'
} finally { Remove-Item $temp -Recurse -Force }
