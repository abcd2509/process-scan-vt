<#
.SYNOPSIS
    Scans running processes for suspicious characteristics and optionally checks
    file hashes against VirusTotal.

.DESCRIPTION
    - Lists all running processes with their file path, digital signature status,
      and SHA256 hash.
    - Flags processes that are unsigned, running from suspicious locations
      (Temp, AppData, Downloads), or have common malware-mimicry name patterns.
    - Optionally submits SHA256 hashes to VirusTotal's public API (v3) to check
      known detection results (this only sends a hash, never the file itself).
    - Outputs a color-coded report to the console and a CSV log.

.NOTES
    Run as Administrator for best results (some system processes require elevation
    to read their file path).

.PARAMETER VTApiKey
    Your VirusTotal API key (free tier). Get one at https://www.virustotal.com/gui/join-us
    Free tier is rate-limited to 4 requests/minute, so this script throttles automatically.

.PARAMETER SkipVT
    Switch to skip VirusTotal checks entirely (faster, no API key needed).

.EXAMPLE
    .\Scan-Processes.ps1 -VTApiKey "your_api_key_here"

.EXAMPLE
    .\Scan-Processes.ps1 -SkipVT
#>

param(
    [string]$VTApiKey = "",
    [switch]$SkipVT
)

$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Config: paths and name patterns considered suspicious
# ---------------------------------------------------------------------------
$SuspiciousPathPatterns = @(
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\Downloads\\",
    "\\Users\\Public\\",
    "\\Windows\\Temp\\",
    "\\ProgramData\\"
)

# Common system process names that should ONLY run from System32/SysWOW64
$SystemProcessNames = @(
    "svchost.exe", "explorer.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe",
    "taskhostw.exe", "dwm.exe"
)

$LegitSystemDirs = @(
    "$env:WINDIR\System32",
    "$env:WINDIR\SysWOW64"
)

$results = @()

Write-Host "`n=== Scanning running processes ===" -ForegroundColor Cyan

$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

foreach ($proc in $processes) {

    $flags = @()
    $path = $proc.ExecutablePath
    $name = $proc.Name

    if (-not $path) {
        # No path usually means a system/protected process, or we lack permission to see it
        $flags += "NoPathVisible (run as Admin to inspect)"
    }
    else {
        # Check 1: suspicious location
        foreach ($pattern in $SuspiciousPathPatterns) {
            if ($path -match [regex]::Escape($pattern)) {
                $flags += "RunningFromSuspiciousLocation:$pattern"
                break
            }
        }

        # Check 2: system-named process running from wrong directory
        if ($SystemProcessNames -contains $name.ToLower()) {
            $inLegitDir = $false
            foreach ($dir in $LegitSystemDirs) {
                if ($path -like "$dir\*") { $inLegitDir = $true; break }
            }
            if (-not $inLegitDir) {
                $flags += "SystemNameWrongLocation"
            }
        }

        # Check 3: digital signature
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            if ($sig.Status -ne "Valid") {
                $flags += "UnsignedOrInvalidSignature:$($sig.Status)"
            }
        } catch {
            $flags += "SignatureCheckFailed"
        }

        # Check 4: name mimicry (simple Levenshtein-ish check against system names)
        foreach ($sysName in $SystemProcessNames) {
            if ($name -ne $sysName -and $name.ToLower() -like "*$($sysName.Substring(0,4).ToLower())*" -and $name -ne $sysName) {
                $flags += "PossibleNameMimicry:$sysName"
            }
        }
    }

    $hash = $null
    if ($path -and (Test-Path $path)) {
        try {
            $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {}
    }

    $results += [PSCustomObject]@{
        PID         = $proc.ProcessId
        ParentPID   = $proc.ParentProcessId
        Name        = $name
        Path        = $path
        SHA256      = $hash
        Flags       = ($flags -join "; ")
        VTDetections = $null
        VTLink      = $null
    }
}

# ---------------------------------------------------------------------------
# VirusTotal lookups (only for flagged or unsigned processes, to respect rate limits)
# ---------------------------------------------------------------------------
if (-not $SkipVT -and $VTApiKey) {
    Write-Host "`n=== Checking flagged processes against VirusTotal ===" -ForegroundColor Cyan
    Write-Host "(Free tier: ~4 requests/minute, this will pause between requests)`n" -ForegroundColor DarkGray

    $toCheck = $results | Where-Object { $_.SHA256 -and $_.Flags -ne "" }

    foreach ($item in $toCheck) {
        try {
            $headers = @{ "x-apikey" = $VTApiKey }
            $uri = "https://www.virustotal.com/api/v3/files/$($item.SHA256)"
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

            $malicious = $resp.data.attributes.last_analysis_stats.malicious
            $suspicious = $resp.data.attributes.last_analysis_stats.suspicious
            $item.VTDetections = "$malicious malicious / $suspicious suspicious (of $($resp.data.attributes.last_analysis_stats.PSObject.Properties.Value | Measure-Object -Sum | Select -Expand Sum) engines)"
            $item.VTLink = "https://www.virustotal.com/gui/file/$($item.SHA256)"

            Write-Host "$($item.Name): $($item.VTDetections)" -ForegroundColor $(if ($malicious -gt 0) { "Red" } else { "Green" })
        }
        catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                $item.VTDetections = "Not found in VT database (unknown file - could be new/rare, not necessarily bad)"
            } else {
                $item.VTDetections = "VT lookup error: $($_.Exception.Message)"
            }
        }

        Start-Sleep -Seconds 16  # throttle to stay under 4 req/min free tier limit
    }
}
elseif (-not $SkipVT -and -not $VTApiKey) {
    Write-Host "`nNo VirusTotal API key provided - skipping VT checks. Use -VTApiKey 'key' or -SkipVT to suppress this message." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Host "`n=== SUSPICIOUS PROCESSES ===" -ForegroundColor Red
$flagged = $results | Where-Object { $_.Flags -ne "" }
if ($flagged.Count -eq 0) {
    Write-Host "None found based on these heuristics. This is NOT a guarantee of safety - pair with a full antivirus scan." -ForegroundColor Green
} else {
    $flagged | Format-Table PID, Name, Path, Flags, VTDetections -AutoSize -Wrap
}

$csvPath = Join-Path $PSScriptRoot "process_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nFull results (all processes) saved to: $csvPath" -ForegroundColor Cyan
Write-Host "Total processes scanned: $($results.Count) | Flagged: $($flagged.Count)`n" -ForegroundColor Cyan
