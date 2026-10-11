# Build a Windows x64/arm64 package. Unsigned archives are development artifacts only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^v\d+\.\d+\.\d+$')][string]$Tag,
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64',
    [string]$SigningCertificateThumbprint,
    [switch]$AllowUnsigned,
    [string]$BinaryDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
if ($env:OS -ne 'Windows_NT') { throw 'Build the Windows package on Windows with the MSVC toolchain.' }
$version = [regex]::Match((Get-Content "$repo/rust/crates/kv-cli/Cargo.toml" -Raw), '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if ($Tag -ne "v$version") { throw "Tag must be v$version." }
if (!$SigningCertificateThumbprint -and !$AllowUnsigned) { throw 'Provide -SigningCertificateThumbprint, or explicitly use -AllowUnsigned for development.' }
if ($BinaryDirectory -and (!$AllowUnsigned -or $SigningCertificateThumbprint)) { throw 'Prebuilt binaries are only supported for unsigned development/test packages.' }
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
if (!$BinaryDirectory) {
    Push-Location "$repo/rust"
    try {
        & cargo build --release --locked --target $target -p kv-helper -p kv-agent -p kv-cli -p kv-mcp -p kv-hook
        if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }
    } finally { Pop-Location }
    $BinaryDirectory = "$repo/rust/target/$target/release"
}
$BinaryDirectory = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$name = "keyvalet-$Tag-windows-$Architecture"
$stage = Join-Path "$repo/dist" $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item "$stage/bin", "$stage/templates", "$stage/scripts", "$stage/docs" -ItemType Directory -Force | Out-Null
foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook') {
    Copy-Item -LiteralPath "$BinaryDirectory/$binary.exe" "$stage/bin/"
}
if ($SigningCertificateThumbprint) {
    $certificate = Get-Item "Cert:/CurrentUser/My/$SigningCertificateThumbprint"
    if ($certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Simvito Limited') {
        throw 'The signing certificate must belong to Simvito Limited.'
    }
    $signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($signTool) { $signTool = $signTool.Source }
    else {
        $signTool = Get-ChildItem "${env:ProgramFiles(x86)}/Windows Kits/10/bin/*/x64/signtool.exe" |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (!$signTool) { throw 'Install the Windows SDK signing tools.' }
    foreach ($file in Get-ChildItem "$stage/bin/*.exe") {
        & $signTool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $file.FullName
        if ($LASTEXITCODE -ne 0) { throw "Signing failed: $($file.Name)" }
        $signature = Get-AuthenticodeSignature $file.FullName
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Simvito Limited') {
            throw "Signature verification failed: $($file.Name)"
        }
    }
} else {
    Set-Content "$stage/UNSIGNED-DEVELOPMENT-BUILD.txt" 'Unsigned development build. Install only with explicit -AllowUnsignedAgent. Not a production release.'
}
Copy-Item "$repo/templates/catalog.json" "$stage/templates/"
Copy-Item "$repo/scripts/install.ps1", "$repo/scripts/uninstall.ps1" "$stage/scripts/"
Copy-Item "$repo/LICENSE", "$repo/README.md", "$repo/SECURITY.md" $stage
Copy-Item "$repo/docs/windows.md" "$stage/docs/"
$archive = "$repo/dist/$name.zip"
if (Test-Path $archive) { Remove-Item $archive -Force }
Compress-Archive -Path $stage -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
# Separate per-architecture files avoid concurrent package jobs overwriting one another.
Set-Content "$repo/dist/SHA256SUMS-windows-$Architecture" "$hash  $name.zip" -Encoding ascii
Write-Host "Built $archive"
