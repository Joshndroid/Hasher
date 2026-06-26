$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Version = ((Select-String -Path "$Root\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value)
$Dist = "$Root\dist\windows"

Set-Location $Root
cargo build --release --bins --locked
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Force "$Dist\Hasher-portable" | Out-Null
New-Item -ItemType Directory -Force "$Dist\Hasher-offline-portable" | Out-Null

function Invoke-HasherOptionalSigning([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($env:HASHER_SIGNTOOL_COMMAND)) { return }
    if (-not $env:HASHER_SIGNTOOL_COMMAND.Contains("{file}")) {
        throw "HASHER_SIGNTOOL_COMMAND must contain the {file} placeholder."
    }
    $FullPath = (Resolve-Path $Path).Path
    $Command = $env:HASHER_SIGNTOOL_COMMAND.Replace("{file}", ('"' + $FullPath + '"'))
    & cmd.exe /d /s /c $Command
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for $FullPath" }
    $Signature = Get-AuthenticodeSignature $FullPath
    if ($Signature.Status -ne "Valid") {
        throw "Authenticode verification failed for $FullPath ($($Signature.Status))."
    }
}

Invoke-HasherOptionalSigning "target\release\hasher.exe"
Invoke-HasherOptionalSigning "target\release\hasher-cli.exe"

Copy-Item target\release\hasher.exe,target\release\hasher-cli.exe,README.md,LICENSE,assets\OFL.txt,assets\hasher-icon.ico "$Dist\Hasher-portable"
Copy-Item target\release\hasher.exe,target\release\hasher-cli.exe,README.md,LICENSE,assets\OFL.txt,assets\hasher-icon.ico "$Dist\Hasher-offline-portable"
Compress-Archive -Force "$Dist\Hasher-portable\*" "$Dist\Hasher-$Version-windows-portable.zip"
Compress-Archive -Force "$Dist\Hasher-offline-portable\*" "$Dist\Hasher-$Version-windows-offline-portable.zip"

function Resolve-Iscc {
    # 1. Already on PATH (local dev machines, some installers).
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # 2. Fixed install locations and the Chocolatey shim. The choco innosetup
    #    package does NOT reliably add ISCC.exe to PATH for the current session,
    #    which is why a bare `Get-Command ISCC.exe` keeps failing in CI.
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 5\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 5\ISCC.exe"
    )
    if ($env:ChocolateyInstall) {
        $candidates += (Join-Path $env:ChocolateyInstall "bin\ISCC.exe")
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return (Resolve-Path $candidate).Path }
    }

    # 3. The uninstall registry entry records the real install directory.
    #    Per-user installs (the common AppData case) register under HKCU.
    $registryKeys = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 5_is1",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 5_is1",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 5_is1"
    )
    foreach ($key in $registryKeys) {
        $location = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).InstallLocation
        if ($location) {
            $exe = Join-Path $location "ISCC.exe"
            if (Test-Path $exe) { return (Resolve-Path $exe).Path }
        }
    }

    # 4. Last resort: shallow scan of every root Inno could plausibly live in,
    #    including the per-user AppData install location.
    $scanRoots = @(
        "$env:LOCALAPPDATA\Programs",
        ${env:ProgramFiles(x86)},
        $env:ProgramFiles
    )
    foreach ($scanRoot in $scanRoots) {
        if (-not $scanRoot -or -not (Test-Path $scanRoot)) { continue }
        $found = Get-ChildItem -Path $scanRoot -Filter ISCC.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    return $null
}

$Iscc = Resolve-Iscc
if (-not $Iscc) {
    throw "Inno Setup compiler (ISCC.exe) not found. Install Inno Setup 6 with 'choco install innosetup -y' or from https://jrsoftware.org/isdl.php."
}
Write-Host "Using Inno Setup compiler: $Iscc"

# Compile into a local temp directory rather than straight into $Dist. Inno's
# final step calls EndUpdateResource to embed the icon/version resources into
# the setup stub, and that fails ("resource update error: EndUpdateResource
# failed") whenever another process holds a handle on the half-written file.
# Inside a synced repo the Nextcloud/OneDrive client does exactly that, and
# real-time antivirus can too. Building somewhere local then copying the
# finished installer back avoids the whole class of problem.
$IsccOut = Join-Path ([System.IO.Path]::GetTempPath()) "hasher-iscc-$Version"
if (Test-Path $IsccOut) { Remove-Item -Recurse -Force $IsccOut }
New-Item -ItemType Directory -Force $IsccOut | Out-Null
try {
    & $Iscc "/DMyAppVersion=$Version" "/O$IsccOut" "$Root\packaging\windows\Hasher.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed." }
    $SetupExe = Join-Path $IsccOut "Hasher-$Version-setup.exe"
    if (-not (Test-Path $SetupExe)) { throw "Inno Setup did not produce $SetupExe." }
    Copy-Item $SetupExe $Dist -Force
} finally {
    Remove-Item -Recurse -Force $IsccOut -ErrorAction SilentlyContinue
}
Invoke-HasherOptionalSigning "$Dist\Hasher-$Version-setup.exe"
Write-Host "Artifacts written to $Dist"
