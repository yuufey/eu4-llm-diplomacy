$ErrorActionPreference = 'Stop'
$outputPath = Join-Path $PSScriptRoot 'eu4_bridge_control_recall_v5.dll'
foreach ($gameInstance in @(Get-Process eu4 -ErrorAction SilentlyContinue)) {
    if (@($gameInstance.Modules | Where-Object { $_.FileName -eq $outputPath }).Count) {
        throw 'Recall DLL is loaded; do not rebuild or replace it in the running process.'
    }
}
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'import-local-env.ps1')
Import-ProjectLocalEnv -ProjectRoot $projectRoot
$arguments = @('-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
    '-DBRIDGE_DIPLOMAT_RECALL', '-shared', '-static-libgcc', '-static-libstdc++', '-Wl,--no-insert-timestamp',
    '-o', $outputPath,
    (Join-Path $PSScriptRoot 'control-probe.cpp'), (Join-Path $PSScriptRoot 'frame_stub.S'))
& (Get-ProjectLocalValue -Name 'EU4_CXX') @arguments
if ($LASTEXITCODE -ne 0) { throw 'Diplomat recall candidate build failed.' }
Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath
