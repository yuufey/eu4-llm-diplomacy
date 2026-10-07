param([ValidatePattern('^eu4_bridge_control_[A-Za-z0-9_]+\.dll$')][string]$OutputName='eu4_bridge_control_v3.dll')
$ErrorActionPreference = 'Stop'
$outputPath = Join-Path $PSScriptRoot $OutputName
foreach ($gameInstance in @(Get-Process eu4 -ErrorAction SilentlyContinue)) {
    if (@($gameInstance.Modules | Where-Object { $_.FileName -eq $outputPath }).Count) {
        throw 'Build output is loaded by EU4. Use a new filename or a fresh process; never hot-replace it.'
    }
}
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'import-local-env.ps1')
Import-ProjectLocalEnv -ProjectRoot $projectRoot
$arguments = @('-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
    '-shared', '-static-libgcc', '-static-libstdc++', '-Wl,--no-insert-timestamp',
    '-o', $outputPath,
    (Join-Path $PSScriptRoot 'control-probe.cpp'), (Join-Path $PSScriptRoot 'frame_stub.S'))
& (Get-ProjectLocalValue -Name 'EU4_CXX') @arguments
if ($LASTEXITCODE -ne 0) { throw 'Game control build failed.' }
Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath
