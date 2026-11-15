[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BuildScript,

    [AllowEmptyString()]
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $PSScriptRoot 'import-local-env.ps1')
    Import-ProjectLocalEnv -ProjectRoot $projectRoot

    $vcvars64 = $null
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('VSINSTALLDIR', 'Process'))) {
        $vcvars64 = [Environment]::GetEnvironmentVariable('EU4_VCVARS64', 'Process')
        if ([string]::IsNullOrWhiteSpace($vcvars64)) {
            $vswhere = @(
                [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),
                [Environment]::GetEnvironmentVariable('ProgramFiles')
            ) | Where-Object { $_ } | ForEach-Object {
                Join-Path $_ 'Microsoft Visual Studio\Installer\vswhere.exe'
            } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if (-not $vswhere) {
                throw 'VSINSTALLDIR is not set and vswhere.exe was not found; set EU4_VCVARS64 in local.env.'
            }

            $installations = @(& $vswhere -latest -products '*' `
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                -property installationPath 2>$null)
            if ($LASTEXITCODE -ne 0 -or $installations.Count -eq 0) {
                throw 'No Visual Studio installation with the x64 C++ tools was found; set EU4_VCVARS64 in local.env.'
            }
            $vcvars64 = Join-Path $installations[0] 'VC\Auxiliary\Build\vcvars64.bat'
        } else {
            $vcvars64 = [Environment]::ExpandEnvironmentVariables($vcvars64)
            if (-not [IO.Path]::IsPathRooted($vcvars64) -and $vcvars64 -match '[\\/]') {
                $vcvars64 = Join-Path $projectRoot $vcvars64
            }
        }

        if (-not (Test-Path -LiteralPath $vcvars64 -PathType Leaf)) {
            throw "EU4_VCVARS64 does not identify an existing vcvars64.bat: $vcvars64"
        }
    }
    if (-not (Test-Path -LiteralPath $BuildScript -PathType Leaf)) {
        throw "Build script does not exist: $BuildScript"
    }

    $comSpec = [Environment]::GetEnvironmentVariable('ComSpec')
    if (-not $comSpec) { $comSpec = Join-Path $env:SystemRoot 'System32\cmd.exe' }
    $command = ''
    if ($vcvars64) {
        $command = 'call "{0}" >nul' -f $vcvars64
        $command += "`r`nif errorlevel 1 exit /b 11"
        $command += "`r`n"
    }
    $command += 'call "{0}" __codex_internal_msvc_build "{1}"' -f `
        [IO.Path]::GetFullPath($BuildScript), $OutputDirectory
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $comSpec
    $startInfo.Arguments = '/d /c ' + $command
    $startInfo.UseShellExecute = $false
    $startInfo.WorkingDirectory = (Get-Location).Path
    [Console]::Out.WriteLine('run-msvc-build child command: ' + $startInfo.Arguments)
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process.WaitForExit()
    exit $process.ExitCode
}
catch {
    [Console]::Error.WriteLine('run-msvc-build: ' + $_.Exception.Message)
    exit 11
}
