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
    $workingDirectory = (Get-Location).Path
    if ($vcvars64) {
        $environmentInfo = New-Object System.Diagnostics.ProcessStartInfo
        $environmentInfo.FileName = $comSpec
        $environmentInfo.Arguments = '/d /c call "{0}" >nul & set' -f $vcvars64
        $environmentInfo.UseShellExecute = $false
        $environmentInfo.RedirectStandardOutput = $true
        $environmentInfo.RedirectStandardError = $true
        $environmentInfo.WorkingDirectory = $workingDirectory
        $environmentProcess = [System.Diagnostics.Process]::Start($environmentInfo)
        $environmentOutput = $environmentProcess.StandardOutput.ReadToEnd()
        $environmentErrors = $environmentProcess.StandardError.ReadToEnd()
        $environmentProcess.WaitForExit()
        if ($environmentProcess.ExitCode -ne 0) {
            throw "vcvars64.bat failed with exit code $($environmentProcess.ExitCode): $environmentErrors"
        }

        $vcEnvironment = @{}
        foreach ($line in ($environmentOutput -split "`r?`n")) {
            $separator = $line.IndexOf('=')
            if ($separator -le 0) { continue }
            $name = $line.Substring(0, $separator)
            if ($name -match '^[A-Za-z_][A-Za-z0-9_]*$') {
                $vcEnvironment[$name] = $line.Substring($separator + 1)
            }
        }
        if ([string]::IsNullOrWhiteSpace($vcEnvironment['VSINSTALLDIR'])) {
            throw 'vcvars64.bat did not establish VSINSTALLDIR.'
        }
        foreach ($name in $vcEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $vcEnvironment[$name], 'Process')
        }
    }

    $command = 'call "{0}" __codex_internal_msvc_build "{1}"' -f `
        [IO.Path]::GetFullPath($BuildScript), $OutputDirectory
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $comSpec
    $startInfo.Arguments = '/d /c ' + $command
    $startInfo.UseShellExecute = $false
    $startInfo.WorkingDirectory = $workingDirectory
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process.WaitForExit()
    exit $process.ExitCode
}
catch {
    [Console]::Error.WriteLine('run-msvc-build: ' + $_.Exception.Message)
    exit 11
}
