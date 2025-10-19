$ErrorActionPreference = 'Stop'

function Convert-ToVersion {
    param([string]$v)
    if ($v -match '^\d+\.\d+\.\d+$') { $v = "$v.0" }
    return [version]$v
}

function Get-LibreOfficeInfo {
    $candidates = @(
        "$env:ProgramFiles\LibreOffice\program\version.ini",
        "$env:ProgramFiles(x86)\LibreOffice\program\version.ini"
    )

    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) {
            $raw = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
            if ($null -ne $raw -and $raw -match 'MsiProductVersion\s*=\s*([0-9.]+)') {
                $verStr = $Matches[1]
                $ver    = Convert-ToVersion $verStr
                $branch = "$($ver.Major).$($ver.Minor)"

                # versiones corregidas para CVE-2023-2255
                $fixed = $null
                switch ($branch) {
                    '7.4' { $fixed = Convert-ToVersion '7.4.7' }
                    '7.5' { $fixed = Convert-ToVersion '7.5.3' }
                    default { $fixed = $null }
                }

                $vuln = $false
                if ($fixed) {
                    if ($ver -lt $fixed) { $vuln = $true }
                }
                $fixedStr = if ($fixed) { $fixed.ToString() } else { 'n/a' }

                return [pscustomobject]@{
                    Product      = 'LibreOffice'
                    Version      = $ver.ToString()
                    Branch       = $branch
                    FixedVersion = $fixedStr
                    Vulnerable   = $vuln
                    Source       = $p
                }
            }
        }
    }
    return $null
}

# --- Ejecución ---
$lo = Get-LibreOfficeInfo
if ($lo) {
    $lo | Format-List
} else {
    Write-Host "LibreOffice no encontrado por version.ini" -ForegroundColor Yellow
}
