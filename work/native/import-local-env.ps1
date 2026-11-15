function Import-ProjectLocalEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot
    )

    $script:ProjectLocalRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
    $configPath = Join-Path $script:ProjectLocalRoot 'local.env'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        return
    }

    foreach ($rawLine in Get-Content -LiteralPath $configPath -Encoding UTF8) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) { throw "Invalid local.env entry: $rawLine" }
        $name = $line.Substring(0, $separator).Trim()
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            throw "Invalid local.env key: $name"
        }
        $value = $line.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($null -eq [Environment]::GetEnvironmentVariable($name, 'Process')) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

function Get-ProjectLocalValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Missing $Name in local.env. Copy local.env.example to local.env and configure it."
    }
    $value = [Environment]::ExpandEnvironmentVariables($value)
    if ($Name -match '^EU4_(GAME_ROOT|USER_DATA|PYTHON|CXX|OBJDUMP|CRASH_DUMP|DOTNET|VCVARS64)$' -and
        -not [System.IO.Path]::IsPathRooted($value) -and $value -match '[\\/]') {
        return Join-Path $script:ProjectLocalRoot $value
    }
    return $value
}
