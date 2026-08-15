#requires -version 5.1
<#
.SYNOPSIS
    IP BLOCK & NETWORK FORENSICS TOOL v5.0 (Phase 1)

.DESCRIPTION
    Defensive Windows network/IP diagnostics focused on proving whether the
    Internet-visible network identity actually changed.

    THIS IS A PHASED V5. The full "EPIC" scope (SQLite storage, DPAPI secret
    storage, a monitoring daemon, module-per-concern splitting, a parallel
    target-forensics engine, CSV export, and a full parameterized CLI) is a
    multi-session project. Phase 1 below is complete and real, not a stub;
    Phases 2-5 are an explicit, unstarted roadmap (see bottom of this header
    and the chat reply that ships with this file).

    CHANGELOG v4.0 -> v5.0 (Phase 1: consensus, provider, settings, secrets)
      - REAL consensus engine: Get-IPConsensus now does majority voting,
        quorum percentage, a HIGH/MEDIUM/LOW confidence rating, and explicit
        outlier identification per address family, instead of "first unique
        value wins". Fully unit-testable, no I/O.
      - IP intelligence is now genuinely multi-provider: Get-IPIntelAggregate
        queries every ENABLED provider concurrently (runspace pool) instead
        of stopping at the first success, then runs Get-IntelConsensus to
        surface ISP/ASN/country/VPN/proxy/datacenter conflicts across
        providers. "Unknown" (a provider that doesn't report a field) is
        never coerced into "false". The old fallback-chain function
        (Get-IPIntelSummary) is kept as a thin wrapper over the aggregate for
        menu items that only need one best answer.
      - Provider health tracking: every provider call updates in-memory
        counters (success rate, average latency, rate-limit hits, last
        success/failure/error). Menu item 3 now shows a health table.
        Health resets each run - persistence across runs is a Phase-3 item
        (would live in the same store as history).
      - Recursive settings merge (Merge-SettingsRecursive): a user overriding
        one nested provider's Enabled flag no longer wipes the sibling
        providers' settings. Settings are validated on load
        (Test-SettingsValid); an invalid settings.json is backed up next to
        itself with a timestamp and defaults are used instead of silently
        misbehaving.
      - Token handling: API tokens are read from environment variables first
        (IPBLOCK_IPAPI_TOKEN, IPBLOCK_IPINFO_TOKEN), falling back to
        settings.json only if the env var is absent, with a one-time WARN
        that plaintext storage was used. Tokens are redacted (********)
        everywhere the tool writes text: log file, TXT/HTML reports, and
        console Status lines. DPAPI/Credential-Manager storage is a Phase-1.5
        candidate, not yet implemented - see Known Limitations.
      - Pester suite expanded with mocked-data tests for the new consensus
        and aggregation logic, settings merge/validation, and secret
        redaction - no test depends on a live network call.

    CHANGELOG v3 EPIC -> v4.0 (carried forward, unchanged this phase)
      - Multi-provider IP intelligence with automatic fallback + caching
        (ipapi.is -> ipwho.is -> ip-api.com -> ipinfo.io), so one rate-limited
        provider no longer disables ASN/ISP/VPN features.
      - Public-IP consensus lookups run in parallel via a runspace pool
        (PS 5.1-compatible) instead of serially, cutting wait time.
      - Removed the blanket $ErrorActionPreference='SilentlyContinue'; calls
        now use scoped try/catch with retry + exponential backoff.
      - New: traceroute capture, DNS resolution/DoH comparison check,
        RDAP/WHOIS lookup, optional download speed test.
      - New: self-contained HTML report (single diagnostic + before/after
        comparison with a visual difference-score gauge), in addition to
        TXT/JSON.
      - New: settings.json now drives IP-intel provider order/enable flags,
        cache TTL, HTTP timeouts, and optional API tokens - no code edits
        needed to reconfigure.
      - New: -Silent / -ExportOnly parameters for unattended runs (Task
        Scheduler), and -WhatIf support on the destructive repair actions
        (DHCP renew, Winsock/IP stack reset).
      - Menu reorganized into labeled sections; long operations show
        Write-Progress instead of appearing to hang.
      - Pure logic (IP validation, consensus, diff scoring) extracted into
        standalone functions covered by a companion Pester test file.
      - Script is dot-source safe: the interactive menu only starts when the
        file is run directly, not when dot-sourced for testing.

    ROADMAP (not in this file - see chat reply for the full phase plan)
      Phase 2: first-class IPv6 diagnostics, parallel IPv4/IPv6 target
               forensics lab, expanded DNS forensics (DoH/DoT comparison).
      Phase 3: identity-confidence engine (IP-change vs identity-change
               scores with evidence lines), -Monitor mode, snapshot
               storage upgrade (SQLite w/ JSON migration) + timeline view.
      Phase 4: HTML dashboard rebuild (gauges/cards/provider-agreement
               panel), CSV export, parameterized CLI (-FullDiagnostic,
               -Target, -Snapshot, etc.) alongside the existing menu.
      Phase 5: security hardening pass, DPAPI/Credential-Manager token
               storage, module split if the file has grown too large by
               then, full edge-case test matrix, final validation report.

    IMPORTANT:
      A public Internet IP cannot be arbitrarily randomized by PowerShell.
      The ISP/router/VPN determines the public egress address. This tool does
      NOT attempt to defeat a site's security controls or automatically rotate
      addresses to evade a block. It provides controlled diagnostics so you can
      switch to a network you are authorized to use and prove what changed.

.PARAMETER Silent
    Run a full diagnostic unattended (no menu, no prompts) and exit. Intended
    for Task Scheduler / scripted use.

.PARAMETER ExportOnly
    Same as -Silent but only writes reports (skips the on-screen sections);
    use with -Silent.

.PARAMETER SettingsPath
    Override the default settings.json location.

.NOTES
    Windows 10/11, PowerShell 5.1+
    Run as Administrator for DHCP/network repair functions.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Silent,
    [switch]$ExportOnly,
    [string]$SettingsPath
)

# ==================== CONFIG ====================
$ToolName = 'IP Block & Network Forensics Tool'
$Version = '5.0-phase1'
$Root = Join-Path $env:USERPROFILE 'Desktop\IP_Block_Diagnostics'
$LogDir = Join-Path $Root 'Logs'
$ReportDir = Join-Path $Root 'Reports'
$SnapshotDir = Join-Path $Root 'Snapshots'
$HistoryFile = Join-Path $Root 'network_snapshots.json'
$SettingsFile = if ($SettingsPath) { $SettingsPath } else { Join-Path $Root 'settings.json' }
$null = New-Item -ItemType Directory -Path $Root, $LogDir, $ReportDir, $SnapshotDir -Force -ErrorAction SilentlyContinue
$LogFile = Join-Path $LogDir ('Diagnostic_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$UserAgent = "IPBlockDiagnosticTool/$Version"

function Get-DefaultSettings {
    [PSCustomObject]@{
        HttpTimeoutSec     = 8
        HttpRetryCount     = 2
        IntelCacheMinutes  = 10
        UseIPReputation    = $true
        IntelProviderOrder = @('IpapiIs', 'IpWhoIs', 'IpApiCom', 'IpInfoIo')
        IntelProviders     = [PSCustomObject]@{
            IpapiIs  = [PSCustomObject]@{ Enabled = $true; ApiToken = '' }
            IpWhoIs  = [PSCustomObject]@{ Enabled = $true }
            IpApiCom = [PSCustomObject]@{ Enabled = $true }
            IpInfoIo = [PSCustomObject]@{ Enabled = $true; ApiToken = '' }
        }
        PublicIPv4Sources  = @(
            [PSCustomObject]@{ Name = 'ipify-v4'; URL = 'https://api.ipify.org' }
            [PSCustomObject]@{ Name = 'icanhazip'; URL = 'https://icanhazip.com' }
            [PSCustomObject]@{ Name = 'ifconfig.me'; URL = 'https://ifconfig.me/ip' }
            [PSCustomObject]@{ Name = 'amazon-checkip'; URL = 'https://checkip.amazonaws.com' }
        )
        PublicIPv6Sources  = @(
            [PSCustomObject]@{ Name = 'ipify-v6'; URL = 'https://api6.ipify.org' }
            [PSCustomObject]@{ Name = 'ipify-v64'; URL = 'https://api64.ipify.org' }
            [PSCustomObject]@{ Name = 'ifconfig-v6'; URL = 'https://ifconfig.co/ip' }
        )
        DnsLeakTestHost    = 'one.one.one.one'
        DohEndpoint        = 'https://cloudflare-dns.com/dns-query'
        SpeedTestUrl       = 'https://speed.cloudflare.com/__down?bytes=25000000'
    }
}

function Merge-SettingsRecursive {
    <#
    .SYNOPSIS
        Recursively merges an override object onto a default object.
        Unlike a shallow merge, overriding one nested property (e.g.
        IntelProviders.IpapiIs.Enabled) leaves every sibling property intact
        instead of replacing the whole parent object. Pure function, no I/O
        - directly unit-testable.
    .NOTES
        Arrays are treated as leaf values (replaced wholesale, not merged
        element-by-element) since provider/source lists are ordered and a
        partial-array merge would be ambiguous.
    #>
    param($Default, $Override)

    if ($null -eq $Override) { return $Default }
    if ($Default -is [System.Collections.IEnumerable] -and $Default -isnot [string]) { return $Override }
    if ($Default.GetType().Name -ne 'PSCustomObject' -or $Override.GetType().Name -ne 'PSCustomObject') {
        return $Override
    }

    $merged = $Default.PSObject.Copy()
    foreach ($prop in $Override.PSObject.Properties) {
        $existing = $merged.PSObject.Properties.Name -contains $prop.Name
        if ($existing -and $merged.$($prop.Name) -is [PSCustomObject] -and $prop.Value -is [PSCustomObject]) {
            $merged.$($prop.Name) = Merge-SettingsRecursive -Default $merged.$($prop.Name) -Override $prop.Value
        }
        elseif ($existing) {
            $merged.$($prop.Name) = $prop.Value
        }
        else {
            $merged | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
        }
    }
    return $merged
}

function Test-SettingsValid {
    <#
    .SYNOPSIS
        Validates a loaded settings object. Pure function - returns a
        PSCustomObject with IsValid + a list of human-readable Problems;
        never throws.
    #>
    param($Settings)
    $problems = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Settings) { $problems.Add('Settings object is null.') }
    else {
        if ($Settings.PSObject.Properties.Name -contains 'HttpTimeoutSec') {
            if (-not ($Settings.HttpTimeoutSec -is [int] -or $Settings.HttpTimeoutSec -is [double]) -or $Settings.HttpTimeoutSec -le 0 -or $Settings.HttpTimeoutSec -gt 120) {
                $problems.Add("HttpTimeoutSec must be a number between 1 and 120 (got: $($Settings.HttpTimeoutSec)).")
            }
        }
        if ($Settings.PSObject.Properties.Name -contains 'HttpRetryCount') {
            if (-not ($Settings.HttpRetryCount -is [int]) -or $Settings.HttpRetryCount -lt 0 -or $Settings.HttpRetryCount -gt 10) {
                $problems.Add("HttpRetryCount must be an integer between 0 and 10 (got: $($Settings.HttpRetryCount)).")
            }
        }
        if ($Settings.PSObject.Properties.Name -contains 'IntelCacheMinutes') {
            if (-not ($Settings.IntelCacheMinutes -is [int] -or $Settings.IntelCacheMinutes -is [double]) -or $Settings.IntelCacheMinutes -lt 0) {
                $problems.Add("IntelCacheMinutes must be zero or a positive number (got: $($Settings.IntelCacheMinutes)).")
            }
        }
        foreach ($listProp in @('PublicIPv4Sources', 'PublicIPv6Sources')) {
            if ($Settings.PSObject.Properties.Name -contains $listProp) {
                foreach ($src in @($Settings.$listProp)) {
                    if (-not $src.URL -or -not ($src.URL -match '^https?://')) {
                        $problems.Add("$listProp entry '$($src.Name)' has an invalid or missing URL.")
                    }
                }
            }
        }
        if ($Settings.PSObject.Properties.Name -contains 'IntelProviderOrder') {
            $knownProviders = @('IpapiIs', 'IpWhoIs', 'IpApiCom', 'IpInfoIo')
            foreach ($p in @($Settings.IntelProviderOrder)) {
                if ($knownProviders -notcontains $p) {
                    $problems.Add("IntelProviderOrder references unknown provider '$p'.")
                }
            }
        }
    }

    [PSCustomObject]@{
        IsValid  = ($problems.Count -eq 0)
        Problems = @($problems)
    }
}

function Initialize-Settings {
    $default = Get-DefaultSettings
    if (-not (Test-Path $SettingsFile)) {
        try {
            $default | ConvertTo-Json -Depth 10 | Set-Content -Path $SettingsFile -Encoding UTF8
        }
        catch {
            Write-Host "Could not write default settings.json: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        return $default
    }

    try {
        $loaded = Get-Content -Path $SettingsFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "settings.json is malformed JSON, falling back to defaults: $($_.Exception.Message)" -ForegroundColor Yellow
        Backup-BadSettingsFile -Reason 'malformed JSON'
        return $default
    }

    $merged = Merge-SettingsRecursive -Default $default -Override $loaded
    $validation = Test-SettingsValid -Settings $merged
    if (-not $validation.IsValid) {
        Write-Host 'settings.json failed validation - falling back to defaults for this run:' -ForegroundColor Yellow
        $validation.Problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Backup-BadSettingsFile -Reason 'failed validation'
        return $default
    }
    return $merged
}

function Backup-BadSettingsFile {
    param([string]$Reason)
    if (-not (Test-Path $SettingsFile)) { return }
    try {
        $backupPath = "$SettingsFile.bad_{0}.bak" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        Copy-Item -Path $SettingsFile -Destination $backupPath -Force -ErrorAction Stop
        Write-Host "Backed up ($Reason) to: $backupPath" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Could not back up bad settings.json: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$Settings = Initialize-Settings

# ==================== SECRETS ====================
# Populated by Get-ProviderToken as tokens are resolved, so Redact-Secrets
# can strip any of them out of anything the tool writes (log/report/console).
$script:KnownSecrets = New-Object System.Collections.Generic.List[string]
$script:WarnedPlaintextTokens = New-Object System.Collections.Generic.HashSet[string]

function Get-ProviderToken {
    <#
    .SYNOPSIS
        Resolves an API token for a provider: environment variable first
        (IPBLOCK_<PROVIDERKEY>_TOKEN), settings.json ApiToken second (with a
        one-time warning that plaintext storage is being used). Every
        resolved non-empty token is registered with Redact-Secrets so it can
        never leak into logs or reports.
    .NOTES
        DPAPI / Windows Credential Manager storage is a planned Phase-1.5
        addition (see CHANGELOG "Known Limitations") - not implemented yet,
        so the only two sources today are env vars and settings.json.
    #>
    param([Parameter(Mandatory)][string]$ProviderKey)

    $envName = "IPBLOCK_$($ProviderKey.ToUpperInvariant())_TOKEN"
    $envVal = [Environment]::GetEnvironmentVariable($envName)
    if (-not [string]::IsNullOrWhiteSpace($envVal)) {
        Register-Secret -Value $envVal
        return $envVal
    }

    $settingsToken = $null
    try { $settingsToken = $Settings.IntelProviders.$ProviderKey.ApiToken } catch { }
    if (-not [string]::IsNullOrWhiteSpace($settingsToken)) {
        if (-not $script:WarnedPlaintextTokens.Contains($ProviderKey)) {
            [void]$script:WarnedPlaintextTokens.Add($ProviderKey)
            Write-Host "NOTE: $ProviderKey API token is being read from plaintext settings.json. Prefer setting the $envName environment variable instead." -ForegroundColor Yellow
        }
        Register-Secret -Value $settingsToken
        return $settingsToken
    }

    return $null
}

function Register-Secret {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    if (-not $script:KnownSecrets.Contains($Value)) { $script:KnownSecrets.Add($Value) }
}

function Redact-Secrets {
    <#
    .SYNOPSIS
        Replaces every known secret value with '********' in the given text.
        Pure string function - safe to unit test with fake secrets.
    #>
    param([string]$Text, [System.Collections.Generic.List[string]]$Secrets = $script:KnownSecrets)
    if ([string]::IsNullOrEmpty($Text) -or -not $Secrets -or $Secrets.Count -eq 0) { return $Text }
    $result = $Text
    foreach ($secret in $Secrets) {
        if ([string]::IsNullOrEmpty($secret)) { continue }
        $result = $result.Replace($secret, '********')
    }
    return $result
}

# ==================== CORE HELPERS ====================
function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    $safe = Redact-Secrets -Text $Message
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $safe
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch { }
    Write-Host $line -ForegroundColor $Color
}

function Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 86) -ForegroundColor DarkCyan
    Write-Host ('  ' + $Title) -ForegroundColor Cyan
    Write-Host ('=' * 86) -ForegroundColor DarkCyan
}

function Status {
    param(
        [ValidateSet('PASS', 'FAIL', 'WARN', 'INFO')][string]$Level,
        [string]$Message
    )
    $color = switch ($Level) {
        'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Cyan' }
    }
    $safeMessage = Redact-Secrets -Text $Message
    Write-Host ('[{0,-4}] {1}' -f $Level, $safeMessage) -ForegroundColor $color
    Write-Log "[$Level] $safeMessage" $color
}

function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}
Set-Tls12

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Runs a scriptblock with retry + exponential backoff. Returns $null on
        total failure instead of throwing, so callers can degrade gracefully.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = $Settings.HttpRetryCount + 1,
        [int]$InitialDelayMs = 400
    )
    $attempt = 0
    $delay = $InitialDelayMs
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return (& $ScriptBlock)
        }
        catch {
            if ($attempt -ge $MaxAttempts) {
                Write-Log "Retry exhausted after $attempt attempt(s): $($_.Exception.Message)" ([ConsoleColor]::DarkYellow)
                return $null
            }
            Start-Sleep -Milliseconds $delay
            $delay = $delay * 2
        }
    }
    return $null
}

function Invoke-TextUrl {
    param([string]$Url, [int]$TimeoutSec = $Settings.HttpTimeoutSec)
    Invoke-WithRetry -ScriptBlock {
        $r = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing -Headers @{ 'User-Agent' = $UserAgent } -ErrorAction Stop
        $r.Content.Trim()
    }
}

function Invoke-JsonUrl {
    param([string]$Url, [int]$TimeoutSec = $Settings.HttpTimeoutSec, [hashtable]$Headers)
    $h = @{ 'User-Agent' = $UserAgent }
    if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
    Invoke-WithRetry -ScriptBlock {
        Invoke-RestMethod -Uri $Url -TimeoutSec $TimeoutSec -Headers $h -ErrorAction Stop
    }
}

function Test-IPv4Address {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($IP, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
}

function Test-IPv6Address {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($IP, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
}

function Normalize-IP {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $null }
    try {
        $parsed = [System.Net.IPAddress]::Parse($IP.Trim())
        return $parsed.ToString()
    }
    catch { return $IP.Trim() }
}

# ==================== PARALLEL REQUEST ENGINE ====================
function Invoke-ParallelRequests {
    <#
    .SYNOPSIS
        Fires several HTTP GET requests concurrently using a runspace pool
        (PowerShell 5.1-compatible - no dependency on ForEach-Object -Parallel).
    .PARAMETER Requests
        Array of objects with Name, Url, and optional Type ('text' or 'json').
    .OUTPUTS
        PSCustomObject per request: Name, Success, Data, Error, LatencyMs.
    #>
    param(
        [Parameter(Mandatory)][array]$Requests,
        [int]$ThrottleLimit = 8,
        [int]$TimeoutSec = $Settings.HttpTimeoutSec
    )
    if (-not $Requests -or $Requests.Count -eq 0) { return @() }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $ThrottleLimit), $iss, $Host)
    $pool.Open()

    $worker = {
        param($Req, $Timeout, $UA)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            if ($Req.Type -eq 'json') {
                $data = Invoke-RestMethod -Uri $Req.Url -TimeoutSec $Timeout -Headers @{ 'User-Agent' = $UA } -ErrorAction Stop
            }
            else {
                $resp = Invoke-WebRequest -Uri $Req.Url -TimeoutSec $Timeout -UseBasicParsing -Headers @{ 'User-Agent' = $UA } -ErrorAction Stop
                $data = $resp.Content.Trim()
            }
            $sw.Stop()
            [PSCustomObject]@{ Name = $Req.Name; Success = $true; Data = $data; Error = $null; LatencyMs = $sw.ElapsedMilliseconds }
        }
        catch {
            $sw.Stop()
            [PSCustomObject]@{ Name = $Req.Name; Success = $false; Data = $null; Error = $_.Exception.Message; LatencyMs = $sw.ElapsedMilliseconds }
        }
    }

    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($req in $Requests) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker).AddArgument($req).AddArgument($TimeoutSec).AddArgument($UserAgent)
        $jobs.Add([PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() })
    }

    $results = foreach ($j in $jobs) {
        try { $j.Pipe.EndInvoke($j.Handle) }
        catch { [PSCustomObject]@{ Name = '?'; Success = $false; Data = $null; Error = $_.Exception.Message } }
        finally { $j.Pipe.Dispose() }
    }

    $pool.Close()
    $pool.Dispose()
    return @($results)
}

# ==================== PUBLIC IP CONSENSUS ====================
function Get-PublicIPMultiSource {
    $requests = @()
    foreach ($s in $Settings.PublicIPv4Sources) { $requests += [PSCustomObject]@{ Name = $s.Name; Url = $s.URL; Type = 'text'; Family = 'IPv4' } }
    foreach ($s in $Settings.PublicIPv6Sources) { $requests += [PSCustomObject]@{ Name = $s.Name; Url = $s.URL; Type = 'text'; Family = 'IPv6' } }

    Write-Progress -Activity 'Public IP consensus' -Status "Querying $($requests.Count) providers in parallel..." -PercentComplete 10
    $raw = Invoke-ParallelRequests -Requests $requests -TimeoutSec $Settings.HttpTimeoutSec
    Write-Progress -Activity 'Public IP consensus' -Completed

    $results = @()
    foreach ($r in $raw) {
        if (-not $r.Success) { continue }
        $family = ($requests | Where-Object { $_.Name -eq $r.Name } | Select-Object -First 1).Family
        $ip = Normalize-IP $r.Data
        if ($family -eq 'IPv4' -and (Test-IPv4Address $ip)) {
            $results += [PSCustomObject]@{ Source = $r.Name; IP = $ip; Family = 'IPv4'; Success = $true }
        }
        elseif ($family -eq 'IPv6' -and (Test-IPv6Address $ip)) {
            $results += [PSCustomObject]@{ Source = $r.Name; IP = $ip; Family = 'IPv6'; Success = $true }
        }
    }
    return @($results)
}

function Get-AddressConsensus {
    <#
    .SYNOPSIS
        Real majority-vote consensus for one address family: groups provider
        results by normalized value, picks the majority value, computes a
        quorum percentage and a HIGH/MEDIUM/LOW confidence rating, and lists
        the outlier providers (those that reported something other than the
        majority value). Pure function - no I/O, directly unit-testable.
    .PARAMETER Results
        Array of objects with at least Source and IP properties, already
        filtered to a single address family.
    #>
    param([array]$Results)

    $results = @($Results | Where-Object { $_.IP })
    if ($results.Count -eq 0) {
        return [PSCustomObject]@{
            Value = $null; Values = @(); ProviderCount = 0; AgreementCount = 0
            Agreement = '0/0'; Quorum = 0.0; Confidence = 'UNKNOWN'
            Consistent = $false; Conflict = $false; Outliers = @()
        }
    }

    $groups = $results | Group-Object -Property IP | Sort-Object Count -Descending
    $top = $groups[0]
    $total = $results.Count
    $quorum = [Math]::Round($top.Count / $total, 4)
    $outlierSources = @($results | Where-Object { $_.IP -ne $top.Name } | ForEach-Object { $_.Source })

    # Confidence considers both the quorum percentage AND the absolute
    # sample size - 1/1 provider agreeing is not the same strength of
    # evidence as 4/4, even though both are 100% quorum.
    $confidence =
    if ($total -eq 1) { 'LOW' }
    elseif ($quorum -ge 0.75 -and $total -ge 3) { 'HIGH' }
    elseif ($quorum -ge 0.5) { 'MEDIUM' }
    else { 'LOW' }

    [PSCustomObject]@{
        Value          = $top.Name
        Values         = @($groups | ForEach-Object { $_.Name })
        ProviderCount  = $total
        AgreementCount = $top.Count
        Agreement      = "$($top.Count)/$total"
        Quorum         = $quorum
        Confidence     = $confidence
        Consistent     = ($groups.Count -eq 1)
        Conflict       = ($groups.Count -gt 1)
        Outliers       = $outlierSources
    }
}

function Get-IPConsensus {
    <#
    .SYNOPSIS
        Real consensus engine (majority vote + quorum + confidence +
        outliers) for IPv4 and IPv6 public-IP provider results. Pure logic -
        safe to unit test directly.
    .NOTES
        Field names IPv4/IPv6/IPv4Values/IPv6Values/IPv4ProviderCount/
        IPv6ProviderCount/IPv4Consistent/IPv6Consistent/IPv4Conflict/
        IPv6Conflict are kept for backward compatibility with existing
        callers (Get-PublicIdentity, snapshots). New fields added:
        IPv4Agreement, IPv4Quorum, IPv4Confidence, IPv4Outliers (+ IPv6
        equivalents).
    #>
    param([array]$Results)

    $v4 = Get-AddressConsensus -Results (@($Results | Where-Object Family -eq 'IPv4'))
    $v6 = Get-AddressConsensus -Results (@($Results | Where-Object Family -eq 'IPv6'))

    [PSCustomObject]@{
        IPv4              = $v4.Value
        IPv6              = $v6.Value
        IPv4Values        = $v4.Values
        IPv6Values        = $v6.Values
        IPv4ProviderCount = $v4.ProviderCount
        IPv6ProviderCount = $v6.ProviderCount
        IPv4Consistent    = $v4.Consistent
        IPv6Consistent    = $v6.Consistent
        IPv4Conflict      = $v4.Conflict
        IPv6Conflict      = $v6.Conflict
        IPv4Agreement     = $v4.Agreement
        IPv6Agreement     = $v6.Agreement
        IPv4Quorum        = $v4.Quorum
        IPv6Quorum        = $v6.Quorum
        IPv4Confidence    = $v4.Confidence
        IPv6Confidence    = $v6.Confidence
        IPv4Outliers      = $v4.Outliers
        IPv6Outliers      = $v6.Outliers
    }
}

function Get-PublicIdentity {
    Section 'PUBLIC / EXTERNAL INTERNET IDENTITY'
    $results = Get-PublicIPMultiSource
    $c = Get-IPConsensus $results

    if ($results) {
        $results | Format-Table Source, Family, IP -AutoSize
    }
    else {
        Status FAIL 'No external public-IP service returned a valid address.'
    }

    if ($c.IPv4) {
        if ($c.IPv4Consistent) { Status PASS "IPv4 consensus: $($c.IPv4) | Agreement: $($c.IPv4Agreement) | Confidence: $($c.IPv4Confidence)" }
        elseif ($c.IPv4Conflict) {
            Status WARN "IPv4 providers disagree: $($c.IPv4Values -join ', ')"
            Status WARN "Majority: $($c.IPv4) | Agreement: $($c.IPv4Agreement) | Confidence: $($c.IPv4Confidence) | Outlier(s): $($c.IPv4Outliers -join ', ')"
        }
    }
    else { Status FAIL 'No public IPv4 detected.' }

    if ($c.IPv6) {
        if ($c.IPv6Consistent) { Status PASS "IPv6 consensus: $($c.IPv6) | Agreement: $($c.IPv6Agreement) | Confidence: $($c.IPv6Confidence)" }
        elseif ($c.IPv6Conflict) {
            Status WARN "IPv6 providers disagree: $($c.IPv6Values -join ', ')"
            Status WARN "Majority: $($c.IPv6) | Agreement: $($c.IPv6Agreement) | Confidence: $($c.IPv6Confidence) | Outlier(s): $($c.IPv6Outliers -join ', ')"
        }
        Status INFO 'A destination can use IPv6 instead of IPv4; both families are recorded.'
    }
    else { Status INFO 'No public IPv6 detected.' }

    [PSCustomObject]@{
        IPv4              = $c.IPv4
        IPv6              = $c.IPv6
        IPv4Values        = $c.IPv4Values
        IPv6Values        = $c.IPv6Values
        IPv4ProviderCount = $c.IPv4ProviderCount
        IPv6ProviderCount = $c.IPv6ProviderCount
        IPv4Consistent    = $c.IPv4Consistent
        IPv6Consistent    = $c.IPv6Consistent
        IPv4Agreement     = $c.IPv4Agreement
        IPv6Agreement     = $c.IPv6Agreement
        IPv4Confidence    = $c.IPv4Confidence
        IPv6Confidence    = $c.IPv6Confidence
        IPv4Outliers      = $c.IPv4Outliers
        IPv6Outliers      = $c.IPv6Outliers
        Sources           = $results
        Timestamp         = (Get-Date).ToString('o')
    }
}

# ==================== IP INTELLIGENCE (MULTI-PROVIDER + CACHE) ====================
$script:IntelCache = @{}

function ConvertTo-IntelSummary {
    param(
        [string]$IP, [string]$Provider, [string]$ISP, $ASN, [string]$ASNType,
        [string]$Country, [string]$Region, [string]$City,
        $VPN, $Proxy, $Tor, $Datacenter, $Crawler, $Abuser, $Bogon, $Mobile, $Satellite
    )
    [PSCustomObject]@{
        IP = $IP; Provider = $Provider; ISP = $ISP; ASN = $ASN; ASNType = $ASNType
        Country = $Country; Region = $Region; City = $City
        VPN = $VPN; Proxy = $Proxy; Tor = $Tor; Datacenter = $Datacenter
        Crawler = $Crawler; Abuser = $Abuser; Bogon = $Bogon; Mobile = $Mobile; Satellite = $Satellite
        Timestamp = (Get-Date).ToString('o')
    }
}

# ---- Provider contract: one URL-builder + one response-parser per provider.
# Splitting fetch (URL) from parse (response -> ConvertTo-IntelSummary) is
# what lets Get-IPIntelAggregate below fire every enabled provider through
# the SAME parallel runspace pool used for public-IP consensus, instead of
# each provider needing its own bespoke concurrency code.

function Get-IPIntelUrl-IpapiIs {
    param([string]$IP)
    if (-not $Settings.IntelProviders.IpapiIs.Enabled) { return $null }
    $uri = 'https://api.ipapi.is/?q=' + [uri]::EscapeDataString($IP)
    $token = Get-ProviderToken -ProviderKey 'IpapiIs'
    if ($token) { $uri += '&key=' + $token }
    return $uri
}
function ConvertFrom-IntelResponse-IpapiIs {
    param([string]$IP, $Data)
    if (-not $Data -or -not $Data.ip) { return $null }
    ConvertTo-IntelSummary -IP $IP -Provider 'ipapi.is' -ISP $Data.asn.org -ASN $Data.asn.asn -ASNType $Data.asn.type `
        -Country $Data.location.country -Region $Data.location.state -City $Data.location.city `
        -VPN ([bool]$Data.is_vpn) -Proxy ([bool]$Data.is_proxy) -Tor ([bool]$Data.is_tor) -Datacenter ([bool]$Data.is_datacenter) `
        -Crawler ([bool]$Data.is_crawler) -Abuser ([bool]$Data.is_abuser) -Bogon ([bool]$Data.is_bogon) `
        -Mobile ([bool]$Data.is_mobile) -Satellite ([bool]$Data.is_satellite)
}

function Get-IPIntelUrl-IpWhoIs {
    param([string]$IP)
    if (-not $Settings.IntelProviders.IpWhoIs.Enabled) { return $null }
    return "https://ipwho.is/$IP"
}
function ConvertFrom-IntelResponse-IpWhoIs {
    param([string]$IP, $Data)
    if (-not $Data -or -not $Data.success) { return $null }
    ConvertTo-IntelSummary -IP $IP -Provider 'ipwho.is' -ISP $Data.connection.isp -ASN $Data.connection.asn -ASNType $null `
        -Country $Data.country -Region $Data.region -City $Data.city `
        -VPN ([bool]$Data.security.vpn) -Proxy ([bool]$Data.security.proxy) -Tor ([bool]$Data.security.tor) `
        -Datacenter ([bool]$Data.security.hosting) -Crawler $null -Abuser $null -Bogon $null `
        -Mobile $null -Satellite $null
}

function Get-IPIntelUrl-IpApiCom {
    param([string]$IP)
    if (-not $Settings.IntelProviders.IpApiCom.Enabled) { return $null }
    # Free tier is HTTP-only (no HTTPS) - lowest-priority provider by design
    # (see settings.json IntelProviderOrder); flagged again in section 27
    # (security hardening) of the v5 roadmap as a candidate to drop once a
    # paid/HTTPS tier or a replacement free HTTPS provider is adopted.
    $fields = 'status,message,country,regionName,city,isp,org,as,mobile,proxy,hosting,query'
    return "http://ip-api.com/json/${IP}?fields=$fields"
}
function ConvertFrom-IntelResponse-IpApiCom {
    param([string]$IP, $Data)
    if (-not $Data -or $Data.status -ne 'success') { return $null }
    $asnNum = $null
    if ($Data.as -match '^(AS\d+)') { $asnNum = $Matches[1] }
    ConvertTo-IntelSummary -IP $IP -Provider 'ip-api.com' -ISP $Data.isp -ASN $asnNum -ASNType $null `
        -Country $Data.country -Region $Data.regionName -City $Data.city `
        -VPN $null -Proxy ([bool]$Data.proxy) -Tor $null -Datacenter ([bool]$Data.hosting) `
        -Crawler $null -Abuser $null -Bogon $null -Mobile ([bool]$Data.mobile) -Satellite $null
}

function Get-IPIntelUrl-IpInfoIo {
    param([string]$IP)
    if (-not $Settings.IntelProviders.IpInfoIo.Enabled) { return $null }
    $uri = "https://ipinfo.io/$IP/json"
    $token = Get-ProviderToken -ProviderKey 'IpInfoIo'
    if ($token) { $uri += "?token=$token" }
    return $uri
}
function ConvertFrom-IntelResponse-IpInfoIo {
    param([string]$IP, $Data)
    if (-not $Data -or -not $Data.ip) { return $null }
    $asnNum = $null; $orgName = $Data.org
    if ($Data.org -match '^(AS\d+)\s+(.*)$') { $asnNum = $Matches[1]; $orgName = $Matches[2] }
    # Free tier has no VPN/proxy/Tor flags - leave unknown rather than implying "clean".
    ConvertTo-IntelSummary -IP $IP -Provider 'ipinfo.io' -ISP $orgName -ASN $asnNum -ASNType $null `
        -Country $Data.country -Region $Data.region -City $Data.city `
        -VPN $null -Proxy $null -Tor $null -Datacenter $null -Crawler $null -Abuser $null -Bogon $null `
        -Mobile $null -Satellite $null
}

# ---- Provider health tracking (in-memory this run; see roadmap Phase 3 for
# persisting health across runs alongside the snapshot history store).
$script:ProviderHealth = @{}

function Update-ProviderHealth {
    param(
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][bool]$Success,
        [int]$LatencyMs = 0,
        [switch]$RateLimited,
        [string]$ErrorMessage
    )
    if (-not $script:ProviderHealth.ContainsKey($Provider)) {
        $script:ProviderHealth[$Provider] = [PSCustomObject]@{
            Provider       = $Provider
            Requests       = 0
            Successes      = 0
            Failures       = 0
            RateLimitHits  = 0
            TotalLatencyMs = 0
            LastSuccess    = $null
            LastFailure    = $null
            LastError      = $null
        }
    }
    $h = $script:ProviderHealth[$Provider]
    $h.Requests++
    $h.TotalLatencyMs += $LatencyMs
    if ($Success) { $h.Successes++; $h.LastSuccess = (Get-Date).ToString('o') }
    else {
        $h.Failures++
        $h.LastFailure = (Get-Date).ToString('o')
        $h.LastError = Redact-Secrets -Text $ErrorMessage
    }
    if ($RateLimited) { $h.RateLimitHits++ }
}

function Get-ProviderHealthSummary {
    <# Pure formatting-ready view over $script:ProviderHealth - safe to unit test by passing a fake hashtable. #>
    param($HealthTable = $script:ProviderHealth)
    $rows = foreach ($key in $HealthTable.Keys) {
        $h = $HealthTable[$key]
        $successRate = if ($h.Requests -gt 0) { [Math]::Round(($h.Successes / $h.Requests) * 100, 1) } else { 0 }
        $avgLatency = if ($h.Successes -gt 0) { [Math]::Round($h.TotalLatencyMs / $h.Successes, 0) } else { 0 }
        $status = if ($h.Requests -eq 0) { 'UNKNOWN' } elseif ($successRate -ge 95) { 'HEALTHY' } elseif ($successRate -ge 60) { 'DEGRADED' } else { 'DOWN' }
        [PSCustomObject]@{
            Provider      = $h.Provider
            Status        = $status
            SuccessRate   = "$successRate%"
            AvgLatencyMs  = $avgLatency
            RateLimitHits = $h.RateLimitHits
            LastError     = $h.LastError
        }
    }
    return @($rows | Sort-Object Provider)
}

function Show-ProviderHealth {
    Section 'PROVIDER HEALTH (this session)'
    $rows = Get-ProviderHealthSummary
    if (-not $rows -or $rows.Count -eq 0) { Status INFO 'No provider calls made yet this session.'; return }
    $rows | Format-Table Provider, Status, SuccessRate, AvgLatencyMs, RateLimitHits -AutoSize
}

function Get-IntelConsensus {
    <#
    .SYNOPSIS
        Aggregates normalized intel summaries from multiple providers into
        per-field consensus/conflict info. Categorical fields (ISP/ASN/
        Country) use majority vote; boolean security flags (VPN/Proxy/Tor/
        Datacenter) only count providers that actually reported a value -
        a provider that returns $null for a field is excluded from that
        field's vote entirely, never treated as "false". Pure function -
        directly unit-testable with fabricated summary objects.
    #>
    param([array]$Summaries)

    $summaries = @($Summaries | Where-Object { $_ })
    $fields = [ordered]@{}

    foreach ($field in @('ISP', 'ASN', 'Country')) {
        $vals = @($summaries | Where-Object { $_.$field } | Select-Object -ExpandProperty $field)
        if ($vals.Count -eq 0) {
            $fields[$field] = [PSCustomObject]@{ Value = $null; Agreement = '0/0'; Conflict = $false; AllValues = @() }
            continue
        }
        $groups = $vals | Group-Object | Sort-Object Count -Descending
        $fields[$field] = [PSCustomObject]@{
            Value     = $groups[0].Name
            Agreement = "$($groups[0].Count)/$($vals.Count)"
            Conflict  = ($groups.Count -gt 1)
            AllValues = @($groups | ForEach-Object { $_.Name })
        }
    }

    foreach ($field in @('VPN', 'Proxy', 'Tor', 'Datacenter')) {
        $reporting = @($summaries | Where-Object { $null -ne $_.$field })
        if ($reporting.Count -eq 0) {
            $fields[$field] = [PSCustomObject]@{ Value = $null; Reporters = 0; Conflict = $false }
            continue
        }
        $trueCount = @($reporting | Where-Object { $_.$field -eq $true }).Count
        $falseCount = $reporting.Count - $trueCount
        $fields[$field] = [PSCustomObject]@{
            Value     = ($trueCount -ge $falseCount)  # tie leans toward the more cautious (true/flagged) reading
            TrueCount = $trueCount
            FalseCount = $falseCount
            Reporters = $reporting.Count
            Conflict  = ($trueCount -gt 0 -and $falseCount -gt 0)
        }
    }

    [PSCustomObject]@{
        Fields        = [PSCustomObject]$fields
        ProviderCount = $summaries.Count
        Providers     = @($summaries | ForEach-Object { $_.Provider })
    }
}

function Get-IPIntelAggregate {
    <#
    .SYNOPSIS
        Queries every ENABLED provider concurrently (not fallback-only),
        updates provider health, and returns both the raw per-provider
        summaries and a cross-provider consensus (Get-IntelConsensus).
    #>
    param([string]$IP)
    if (-not $Settings.UseIPReputation -or -not $IP) { return $null }

    $providerDefs = @()
    foreach ($name in $Settings.IntelProviderOrder) {
        $urlFn = "Get-IPIntelUrl-$name"
        if (-not (Get-Command $urlFn -ErrorAction SilentlyContinue)) { continue }
        $url = & $urlFn -IP $IP
        if ($url) { $providerDefs += [PSCustomObject]@{ Name = $name; Url = $url; Type = 'json' } }
    }
    if ($providerDefs.Count -eq 0) { Status WARN 'No IP intelligence providers are enabled.'; return $null }

    Write-Progress -Activity 'IP intelligence (multi-provider)' -Status "Querying $($providerDefs.Count) provider(s) in parallel..." -PercentComplete 30
    $raw = Invoke-ParallelRequests -Requests $providerDefs -TimeoutSec 12
    Write-Progress -Activity 'IP intelligence (multi-provider)' -Completed

    $summaries = @()
    foreach ($r in $raw) {
        $rateLimited = ($r.Error -and $r.Error -match '429|Too Many Requests|rate limit')
        Update-ProviderHealth -Provider $r.Name -Success:([bool]$r.Success) -LatencyMs $r.LatencyMs -RateLimited:$rateLimited -ErrorMessage $r.Error
        if (-not $r.Success) { continue }
        $parser = "ConvertFrom-IntelResponse-$($r.Name)"
        if (-not (Get-Command $parser -ErrorAction SilentlyContinue)) { continue }
        $summary = & $parser -IP $IP -Data $r.Data
        if ($summary) { $summaries += $summary }
    }

    $consensus = Get-IntelConsensus -Summaries $summaries
    [PSCustomObject]@{
        IP         = $IP
        Summaries  = $summaries
        Consensus  = $consensus
        Timestamp  = (Get-Date).ToString('o')
    }
}

function Get-IPIntelSummary {
    <#
    .SYNOPSIS
        Fast single-answer path (fallback chain + cache) used by snapshots,
        which run frequently during a Before/After lab and should not
        multiply their API usage by every enabled provider on every capture.
        For a full multi-provider comparison, use Get-IPIntelAggregate
        (menu item 3) instead.
    #>
    param([string]$IP)
    if (-not $Settings.UseIPReputation -or -not $IP) { return $null }

    $cached = $script:IntelCache[$IP]
    if ($cached -and ((Get-Date) - $cached.Time).TotalMinutes -lt $Settings.IntelCacheMinutes) {
        return $cached.Data
    }

    foreach ($name in $Settings.IntelProviderOrder) {
        $urlFn = "Get-IPIntelUrl-$name"
        $parser = "ConvertFrom-IntelResponse-$name"
        if (-not (Get-Command $urlFn -ErrorAction SilentlyContinue) -or -not (Get-Command $parser -ErrorAction SilentlyContinue)) { continue }
        $url = & $urlFn -IP $IP
        if (-not $url) { continue }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $data = Invoke-JsonUrl -Url $url -TimeoutSec 10
        $sw.Stop()
        Update-ProviderHealth -Provider $name -Success:([bool]$data) -LatencyMs $sw.ElapsedMilliseconds
        if ($data) {
            $summary = & $parser -IP $IP -Data $data
            if ($summary) {
                $script:IntelCache[$IP] = @{ Time = (Get-Date); Data = $summary }
                return $summary
            }
        }
    }
    Status WARN "All IP intelligence providers failed or were rate-limited for $IP."
    return $null
}

function Show-IPIntelligence {
    param([string]$IP, [string]$Label = 'Public IPv4')
    Section "PUBLIC IP INTELLIGENCE - $Label"
    if (-not $IP) { Status WARN "$Label unavailable."; return $null }
    $i = Get-IPIntelSummary $IP
    if (-not $i) { return $null }
    $i | Format-List
    foreach ($name in @('VPN', 'Proxy', 'Tor', 'Datacenter', 'Crawler', 'Abuser', 'Bogon', 'Mobile', 'Satellite')) {
        $v = $i.$name
        if ($null -eq $v) { Status INFO "${name}: unknown (not reported by $($i.Provider))" }
        else { Status $(if ($v) { 'WARN' } else { 'PASS' }) ("{0}: {1}" -f $name, $v) }
    }
    return $i
}

function Show-IPIntelligenceAggregate {
    param([string]$IP, [string]$Label = 'Public IPv4')
    Section "MULTI-PROVIDER IP INTELLIGENCE - $Label"
    if (-not $IP) { Status WARN "$Label unavailable."; return $null }
    $agg = Get-IPIntelAggregate -IP $IP
    if (-not $agg -or $agg.Summaries.Count -eq 0) { Status WARN 'No provider returned usable data.'; return $null }

    Status INFO "$($agg.Summaries.Count) of $($Settings.IntelProviderOrder.Count) configured provider(s) responded."
    $agg.Summaries | Select-Object Provider, ISP, ASN, Country, VPN, Proxy, Tor, Datacenter | Format-Table -AutoSize

    $c = $agg.Consensus.Fields
    Write-Host "`nConsensus:"
    foreach ($field in @('ISP', 'ASN', 'Country')) {
        $f = $c.$field
        if (-not $f.Value) { Status INFO "$field`: no provider reported this."; continue }
        if ($f.Conflict) { Status WARN "$field`: CONFLICT - $($f.AllValues -join ' vs ') (majority: $($f.Value), $($f.Agreement))" }
        else { Status PASS "$field`: $($f.Value) ($($f.Agreement) agree)" }
    }
    foreach ($field in @('VPN', 'Proxy', 'Tor', 'Datacenter')) {
        $f = $c.$field
        if ($f.Reporters -eq 0) { Status INFO "$field`: unknown (no provider reports this flag)"; continue }
        if ($f.Conflict) { Status WARN "$field`: PROVIDERS DISAGREE - $($f.TrueCount) say yes, $($f.FalseCount) say no" }
        else { Status $(if ($f.Value) { 'WARN' } else { 'PASS' }) "$field`: $($f.Value) (unanimous among $($f.Reporters) reporting provider(s))" }
    }
    Show-ProviderHealth
    return $agg
}

# ==================== LOCAL NETWORK STATE ====================
function Get-PrimaryInterface {
    try {
        return Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
            Sort-Object @{Expression = { $_.IPv4DefaultGateway.RouteMetric }; Ascending = $true } |
            Select-Object -First 1
    }
    catch { return $null }
}

function Get-NetworkStateObject {
    $primary = Get-PrimaryInterface
    $adapter = $null
    if ($primary) { $adapter = Get-NetAdapter -InterfaceIndex $primary.InterfaceIndex -ErrorAction SilentlyContinue }

    $dns = @()
    $networkCategory = $null
    $ipv4Connectivity = $null
    $ipv6Connectivity = $null
    if ($primary) {
        try {
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $primary.InterfaceIndex -ErrorAction Stop |
                    Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses })
        }
        catch { }
        try {
            $profile = Get-NetConnectionProfile -InterfaceIndex $primary.InterfaceIndex -ErrorAction Stop
            $networkCategory = $profile.NetworkCategory
            $ipv4Connectivity = $profile.IPv4Connectivity
            $ipv6Connectivity = $profile.IPv6Connectivity
        }
        catch { }
    }

    [PSCustomObject]@{
        Computer             = $env:COMPUTERNAME
        InterfaceAlias       = $(if ($primary) { $primary.InterfaceAlias } else { $null })
        InterfaceIndex       = $(if ($primary) { $primary.InterfaceIndex } else { $null })
        InterfaceDescription = $(if ($adapter) { $adapter.InterfaceDescription } else { $null })
        InterfaceStatus      = $(if ($adapter) { $adapter.Status } else { $null })
        LinkSpeed            = $(if ($adapter) { $adapter.LinkSpeed } else { $null })
        MAC                  = $(if ($adapter) { $adapter.MacAddress } else { $null })
        IPv4Local            = $(if ($primary) { @($primary.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', ' } else { $null })
        IPv6Local            = $(if ($primary) { @($primary.IPv6Address | ForEach-Object { $_.IPAddress }) -join ', ' } else { $null })
        Gateway              = $(if ($primary) { @($primary.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', ' } else { $null })
        DNS                  = ($dns -join ', ')
        NetworkCategory      = $networkCategory
        IPv4Connectivity     = $ipv4Connectivity
        IPv6Connectivity     = $ipv6Connectivity
    }
}

function Show-NetworkState {
    Section 'NETWORK ADAPTERS / CONNECTION'
    Get-NetAdapter -IncludeHidden |
        Sort-Object Status, Name |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, ifIndex, Virtual |
        Format-Table -AutoSize

    Write-Host "`nConnection profiles:"
    try { Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity | Format-Table -AutoSize } catch { }

    Write-Host "`nIP configuration:"
    Get-NetIPConfiguration -All |
        Select-Object InterfaceAlias, InterfaceIndex,
        @{N = 'IPv4'; E = { ($_.IPv4Address.IPAddress -join ', ') } },
        @{N = 'IPv6'; E = { ($_.IPv6Address.IPAddress -join ', ') } },
        @{N = 'Gateway'; E = { ($_.IPv4DefaultGateway.NextHop -join ', ') } },
        @{N = 'DNS'; E = { ($_.DNSServer.ServerAddresses -join ', ') } } |
        Format-Table -AutoSize
}

function Get-RoutingState {
    Section 'ROUTING / MTU'
    Write-Host 'Default IPv4 route:'
    Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Select-Object ifIndex, InterfaceAlias, NextHop, RouteMetric, State | Format-Table -AutoSize
    Write-Host "`nDefault IPv6 route:"
    Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Select-Object ifIndex, InterfaceAlias, NextHop, RouteMetric, State | Format-Table -AutoSize
    Write-Host "`nInterface MTU:"
    netsh interface ipv4 show subinterfaces
}

# ==================== DNS / PROXY / VPN / SECURITY SOFTWARE ====================
function Test-DNS {
    Section 'DNS DIAGNOSTICS'
    $names = @('www.microsoft.com', 'www.cloudflare.com', 'www.google.com', 'www.ticketmaster.com')
    $fail = 0
    foreach ($name in $names) {
        try {
            $r = Resolve-DnsName -Name $name -ErrorAction Stop
            $ips = @($r | Where-Object { $_.Type -in 'A', 'AAAA' } | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue)
            if ($ips) { Status PASS "$name -> $($ips -join ', ')" } else { Status WARN "$name resolved but returned no A/AAAA result." }
        }
        catch { $fail++; Status FAIL "$name DNS resolution failed." }
    }
    Write-Host "`nConfigured DNS servers:"
    Get-DnsClientServerAddress -AddressFamily IPv4, IPv6 |
        Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, AddressFamily, @{N = 'Servers'; E = { $_.ServerAddresses -join ', ' } } | Format-Table -AutoSize
    if ($fail -eq 0) { Status PASS 'DNS resolution tests passed.' } else { Status WARN "$fail DNS test(s) failed." }
    Write-Host "`nNRPT / DNS policy:"
    try { Get-DnsClientNrptPolicy -ErrorAction Stop | Format-Table -AutoSize } catch { Write-Host 'No NRPT policy information available.' }

    Test-DnsLeak
}

function Test-DnsLeak {
    <#
    .SYNOPSIS
        Compares resolution of a domain with a fixed, well-known answer
        (one.one.one.one -> 1.1.1.1/1.0.0.1) via the system resolver vs. a
        DNS-over-HTTPS resolver. A mismatch suggests interception/hijacking
        or a misconfigured resolver - it is not a full DNS-leak test (that
        requires a unique per-session subdomain and a controlled server),
        but it is a useful, low-false-positive sanity check.
    #>
    Section 'DNS RESOLUTION / DoH COMPARISON CHECK'
    $target = $Settings.DnsLeakTestHost

    $systemIPs = @()
    try {
        $systemIPs = @(Resolve-DnsName -Name $target -Type A -ErrorAction Stop |
                Where-Object { $_.Type -eq 'A' } | Select-Object -ExpandProperty IPAddress)
    }
    catch {
        Status WARN "System resolver could not resolve $target."
    }

    $dohIPs = @()
    $dohUrl = "$($Settings.DohEndpoint)?name=$target&type=A"
    $doh = Invoke-JsonUrl -Url $dohUrl -TimeoutSec 8 -Headers @{ 'Accept' = 'application/dns-json' }
    if ($doh -and $doh.Answer) {
        $dohIPs = @($doh.Answer | Where-Object { $_.type -eq 1 } | Select-Object -ExpandProperty data)
    }
    else {
        Status WARN 'DNS-over-HTTPS (Cloudflare) lookup failed or was unreachable.'
    }

    if ($systemIPs) { Status INFO "System resolver: $target -> $($systemIPs -join ', ')" }
    if ($dohIPs) { Status INFO "DoH resolver:    $target -> $($dohIPs -join ', ')" }

    if ($systemIPs -and $dohIPs) {
        $overlap = @($systemIPs | Where-Object { $dohIPs -contains $_ })
        if ($overlap.Count -gt 0) {
            Status PASS 'System DNS and DoH agree on the well-known test host.'
        }
        else {
            Status WARN 'System DNS and DoH DISAGREE on a fixed-answer test host - possible DNS interception/hijack. Investigate.'
        }
    }
}

function Show-ProxyState {
    Section 'PROXY / WINHTTP / ENVIRONMENT'
    Write-Host 'WinHTTP proxy:'; netsh winhttp show proxy
    Write-Host "`nInternet Settings proxy:"
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if (Test-Path $reg) { Get-ItemProperty $reg | Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect | Format-List }
    Write-Host "`nEnvironment proxy variables:"
    Get-ChildItem Env: | Where-Object { $_.Name -match 'proxy' } | Select-Object Name, Value | Format-Table -AutoSize
}

function Show-VPNState {
    Section 'VPN / VIRTUAL NETWORK DETECTION'
    $patterns = 'VPN|TAP|TUN|WireGuard|Wintun|OpenVPN|Nord|ExpressVPN|Surfshark|Mullvad|Proton|Cloudflare|WARP|Cisco AnyConnect|GlobalProtect|Fortinet|Hamachi|ZeroTier|Tailscale|Avast SecureLine|SecureLine|Hyper-V|VMware|VirtualBox|WSL|Docker'
    $adapters = Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -match $patterns -or $_.InterfaceDescription -match $patterns } |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed, ifIndex, Virtual
    if ($adapters) { Status WARN 'Potential VPN/virtual adapters detected:'; $adapters | Format-Table -AutoSize } else { Status PASS 'No obvious VPN/virtual adapter was detected.' }
    Write-Host "`nWindows VPN profiles:"
    try {
        $profiles = Get-VpnConnection -AllUserConnection -ErrorAction Stop
        if ($profiles) { $profiles | Select-Object Name, ServerAddress, ConnectionStatus, TunnelType, AuthenticationMethod | Format-Table -AutoSize }
        else { Write-Host 'No Windows VPN profiles found.' }
    }
    catch { Write-Host 'VPN profile query unavailable.' }
    Write-Host "`nVPN-related processes:"
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'wireguard|openvpn|nord|expressvpn|surfshark|mullvad|proton|warp|secureline|avast' } | Select-Object ProcessName, Id, Path
    if ($procs) { $procs | Format-Table -AutoSize } else { Write-Host 'No obvious VPN processes found.' }
}

function Show-AvastState {
    Section 'AVAST / SECURITY SOFTWARE'
    $paths = @("$env:ProgramFiles\Avast Software", "${env:ProgramFiles(x86)}\Avast Software", "$env:ProgramData\Avast Software") | Where-Object { $_ -and (Test-Path $_) }
    if ($paths) { Status INFO 'Avast installation/data paths detected:'; $paths | ForEach-Object { Write-Host "  $_" } } else { Status INFO 'No standard Avast path detected.' }
    $proc = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'avast|secureline|wsc_proxy' } | Select-Object ProcessName, Id, Path
    if ($proc) { Write-Host "`nAvast processes:"; $proc | Format-Table -AutoSize }
    $svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'avast|secureline' -or $_.DisplayName -match 'Avast|SecureLine' } | Select-Object Name, DisplayName, State, StartMode
    if ($svc) { Write-Host "`nAvast services:"; $svc | Format-Table -AutoSize }
    Status INFO 'This tool NEVER disables Avast automatically.'
}

# ==================== CONNECTIVITY ====================
function Test-TCP443 {
    param([string[]]$Hosts = @('1.1.1.1', '8.8.8.8', 'www.microsoft.com', 'www.cloudflare.com'))
    Section 'TCP / 443 CONNECTIVITY'
    foreach ($h in $Hosts) {
        try {
            $r = Test-NetConnection -ComputerName $h -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue
            if ($r.TcpTestSucceeded) { Status PASS "$h`:443 reachable | Source=$($r.SourceAddress) | Interface=$($r.InterfaceAlias)" }
            else { Status FAIL "$h`:443 failed | Ping=$($r.PingSucceeded)" }
        }
        catch { Status FAIL "$h`:443 test errored." }
    }
}

function Test-NCSI {
    Section 'WINDOWS INTERNET / CAPTIVE PORTAL TESTS'
    foreach ($url in @('http://www.msftconnecttest.com/connecttest.txt', 'http://www.msftncsi.com/ncsi.txt')) {
        try {
            $r = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -Headers @{ 'User-Agent' = 'Microsoft NCSI' } -ErrorAction Stop
            Status PASS "$url -> HTTP $($r.StatusCode)"
        }
        catch { Status WARN "$url failed." }
    }
}

function Test-IPv4IPv6 {
    Section 'FORCED IPv4 vs IPv6 EGRESS'
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { Status WARN 'curl.exe unavailable.'; return }
    $rows = @()
    foreach ($mode in @('-4', '-6')) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $out = & curl.exe $mode '-sS' '--max-time' '12' 'https://api.ipify.org' 2>&1
        $exit = $LASTEXITCODE; $sw.Stop(); $ip = Normalize-IP ($out -join '')
        $family = if ($mode -eq '-4') { 'IPv4' } else { 'IPv6' }
        $ok = if ($family -eq 'IPv4') { Test-IPv4Address $ip } else { Test-IPv6Address $ip }
        $rows += [PSCustomObject]@{ Family = $family; Address = $ip; Working = $ok; Milliseconds = $sw.ElapsedMilliseconds; ExitCode = $exit }
        if ($ok) { Status PASS "$family egress = $ip ($($sw.ElapsedMilliseconds) ms)" } else { Status WARN "$family egress unavailable or failed." }
    }
    return $rows
}

function Test-RouteDiagnostics {
    Section 'ROUTE DIAGNOSTICS'
    foreach ($t in @('www.cloudflare.com', 'www.microsoft.com')) {
        Write-Host "`nRoute to $t"
        try {
            $r = Test-NetConnection -ComputerName $t -DiagnoseRouting -InformationLevel Detailed -WarningAction SilentlyContinue
            $r | Select-Object ComputerName, RemoteAddress, SelectedSourceAddress, OutgoingInterfaceIndex, SelectedNetRoute, RouteDiagnosticsSucceeded | Format-List
        }
        catch { Status WARN "Route diagnostics unavailable for $t." }
    }
}

# ==================== NEW: TRACEROUTE ====================
function Get-TraceRoute {
    param([string]$TargetHost = '1.1.1.1', [int]$MaxHops = 12, [int]$TimeoutMs = 1500)
    if (-not (Get-Command tracert.exe -ErrorAction SilentlyContinue)) { return @() }
    $lines = & tracert.exe '-h' $MaxHops '-w' $TimeoutMs '-d' $TargetHost 2>&1
    return @($lines)
}

function Show-TraceRoute {
    param([string]$TargetHost)
    if ([string]::IsNullOrWhiteSpace($TargetHost)) { $TargetHost = Read-Host 'Target host/IP for traceroute (default 1.1.1.1)' }
    if ([string]::IsNullOrWhiteSpace($TargetHost)) { $TargetHost = '1.1.1.1' }
    Section "TRACEROUTE - $TargetHost"
    Write-Host 'This can take up to ~20-30 seconds if hops are unresponsive...' -ForegroundColor Yellow
    $lines = Get-TraceRoute -TargetHost $TargetHost
    if ($lines) { $lines | ForEach-Object { Write-Host $_ } } else { Status WARN 'tracert.exe unavailable or produced no output.' }
    return $lines
}

# ==================== NEW: RDAP / WHOIS ====================
function Get-RdapInfo {
    param([string]$IP)
    if (-not $IP) { return $null }
    $d = Invoke-JsonUrl -Url "https://rdap.org/ip/$IP" -TimeoutSec 10
    if (-not $d) { return $null }
    [PSCustomObject]@{
        IP        = $IP
        Handle    = $d.handle
        Name      = $d.name
        Country   = $d.country
        StartAddr = $d.startAddress
        EndAddr   = $d.endAddress
        Entities  = @($d.entities | ForEach-Object { $_.handle } | Where-Object { $_ })
    }
}

function Show-RdapInfo {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { $IP = Read-Host 'IP address to look up (RDAP/WHOIS)' }
    if ([string]::IsNullOrWhiteSpace($IP)) { return $null }
    Section "RDAP / WHOIS - $IP"
    $r = Get-RdapInfo -IP $IP
    if ($r) { $r | Format-List } else { Status WARN 'RDAP lookup failed or is unavailable for this address.' }
    return $r
}

# ==================== NEW: OPTIONAL SPEED TEST ====================
function Test-DownloadSpeed {
    Section 'DOWNLOAD SPEED TEST (OPTIONAL)'
    Write-Host "Downloading a test payload from Cloudflare's speed-test endpoint..."
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-WebRequest -Uri $Settings.SpeedTestUrl -TimeoutSec 20 -UseBasicParsing -ErrorAction Stop
        $sw.Stop()
        $bytes = $resp.RawContentLength
        if (-not $bytes) { $bytes = $resp.Content.Length }
        $seconds = [Math]::Max(0.05, $sw.Elapsed.TotalSeconds)
        $mbps = [Math]::Round((($bytes * 8) / $seconds) / 1MB, 2)
        Status PASS "Downloaded $([Math]::Round($bytes/1MB,1)) MB in $([Math]::Round($seconds,2))s -> ~$mbps Mbps"
        return [PSCustomObject]@{ Bytes = $bytes; Seconds = $seconds; Mbps = $mbps }
    }
    catch {
        $sw.Stop()
        Status INFO "Speed test skipped/unavailable: $($_.Exception.Message)"
        return $null
    }
}

# ==================== TARGET WEBSITE ====================
function Test-TargetSite {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { $Url = Read-Host 'Enter URL (example: https://www.example.com)' }
    if ([string]::IsNullOrWhiteSpace($Url)) { return }
    if ($Url -notmatch '^https?://') { $Url = 'https://' + $Url }
    try { $uri = [Uri]$Url } catch { Status FAIL 'Invalid URL.'; return }
    $hostName = $uri.Host
    Section "TARGET WEBSITE FORENSICS - $hostName"
    Write-Host "URL: $Url"
    Write-Host "`nDNS:"
    try { Resolve-DnsName $hostName -ErrorAction Stop | Where-Object { $_.Type -in 'A', 'AAAA' } | Select-Object Name, Type, IPAddress, TTL | Format-Table -AutoSize } catch { Status FAIL 'Target DNS resolution failed.' }

    Write-Host "`nTCP 443:"
    try {
        $tcp = Test-NetConnection -ComputerName $hostName -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue
        $tcp | Select-Object ComputerName, RemoteAddress, InterfaceAlias, SourceAddress, PingSucceeded, TcpTestSucceeded | Format-List
    }
    catch { }

    Write-Host "`nPowerShell HTTP:"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $http = $null
    try {
        $http = Invoke-WebRequest -Uri $Url -TimeoutSec 20 -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
        $sw.Stop()
        Status PASS "HTTP $($http.StatusCode) in $($sw.ElapsedMilliseconds) ms"
        Write-Host "Final URL: $($http.BaseResponse.ResponseUri)"
        Write-Host "Server:    $($http.Headers['Server'])"
        Write-Host "CF-Ray:    $($http.Headers['CF-Ray'])"
        Write-Host "Location:  $($http.Headers['Location'])"
    }
    catch {
        $sw.Stop()
        Status WARN "HTTP request failed after $($sw.ElapsedMilliseconds) ms: $($_.Exception.Message)"
    }

    $curlRows = @()
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        foreach ($mode in @('-4', '-6')) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $headers = & curl.exe $mode '-sS' '-I' '-L' '--max-time' '20' '--connect-timeout' '8' $Url 2>&1
            $exit = $LASTEXITCODE; $sw.Stop(); $joined = ($headers -join "`n")
            $statusCode = $null
            if ($joined -match '(?m)^HTTP/[^ ]+\s+(\d{3})') { $statusCode = $Matches[1] }
            $curlRows += [PSCustomObject]@{ Family = $(if ($mode -eq '-4') { 'IPv4' } else { 'IPv6' }); Status = $statusCode; ExitCode = $exit; Milliseconds = $sw.ElapsedMilliseconds }
            if ($exit -eq 0) { Status PASS "curl $mode target test completed | HTTP=$statusCode | $($sw.ElapsedMilliseconds) ms" } else { Status WARN "curl $mode target test failed/unavailable." }
            if ($joined) { $joined -split "`n" | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" } }
        }
    }
    return [PSCustomObject]@{ Url = $Url; Host = $hostName; PowerShellStatus = $(if ($http) { $http.StatusCode } else { $null }); Curl = $curlRows }
}

# ==================== SNAPSHOTS ====================
function New-NetworkSnapshot {
    param([string]$Label = 'Manual Snapshot', [switch]$Show, [switch]$IncludeTraceRoute)
    Section "CAPTURE NETWORK IDENTITY - $Label"
    Write-Progress -Activity "Snapshot: $Label" -Status 'Gathering public identity...' -PercentComplete 10
    $public = Get-PublicIdentity
    Write-Progress -Activity "Snapshot: $Label" -Status 'Gathering local network state...' -PercentComplete 40
    $local = Get-NetworkStateObject
    Write-Progress -Activity "Snapshot: $Label" -Status 'Testing forced IPv4/IPv6 egress...' -PercentComplete 55
    $egress = Test-IPv4IPv6
    Write-Progress -Activity "Snapshot: $Label" -Status 'IP intelligence lookups...' -PercentComplete 70
    $intel4 = if ($public.IPv4) { Get-IPIntelSummary $public.IPv4 } else { $null }
    $intel6 = if ($public.IPv6) { Get-IPIntelSummary $public.IPv6 } else { $null }
    $trace = @()
    if ($IncludeTraceRoute) {
        Write-Progress -Activity "Snapshot: $Label" -Status 'Tracing route...' -PercentComplete 85
        $trace = Get-TraceRoute -TargetHost '1.1.1.1' -MaxHops 10
    }
    Write-Progress -Activity "Snapshot: $Label" -Completed

    $snapshot = [PSCustomObject]@{
        SnapshotId       = [guid]::NewGuid().ToString()
        Label            = $Label
        Timestamp        = (Get-Date).ToString('o')
        Computer         = $env:COMPUTERNAME
        User             = $env:USERNAME
        PowerShell       = $PSVersionTable.PSVersion.ToString()
        ToolVersion      = $Version
        PublicIP         = $public
        IPv4Intelligence = $intel4
        IPv6Intelligence = $intel6
        LocalNetwork     = $local
        ForcedEgress     = $egress
        TraceRoute       = $trace
        DefaultIPv4Route = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object ifIndex, InterfaceAlias, NextHop, RouteMetric, State)
        DefaultIPv6Route = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object ifIndex, InterfaceAlias, NextHop, RouteMetric, State)
        Proxy            = @(netsh winhttp show proxy | Out-String)
    }

    $safeLabel = ($Label -replace '[^a-zA-Z0-9_-]', '_')
    $file = Join-Path $SnapshotDir ('{0}_{1}_{2}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $safeLabel, $snapshot.SnapshotId.Substring(0, 8))
    try { $snapshot | ConvertTo-Json -Depth 12 | Set-Content -Path $file -Encoding UTF8 }
    catch { Status WARN "Could not write snapshot file: $($_.Exception.Message)" }

    $history = @()
    if (Test-Path $HistoryFile) {
        try { $history = @(Get-Content $HistoryFile -Raw | ConvertFrom-Json) } catch { $history = @() }
    }
    $history += $snapshot
    if ($history.Count -gt 200) { $history = @($history | Select-Object -Last 200) }
    try { $history | ConvertTo-Json -Depth 12 | Set-Content -Path $HistoryFile -Encoding UTF8 }
    catch { Status WARN "Could not update snapshot history: $($_.Exception.Message)" }

    Status PASS "Snapshot saved: $file"
    if ($Show) { Show-Snapshot $snapshot }
    return $snapshot
}

function Get-AllSnapshots {
    if (-not (Test-Path $HistoryFile)) { return @() }
    try { return @(Get-Content $HistoryFile -Raw | ConvertFrom-Json) } catch { return @() }
}

function Show-Snapshot {
    param($Snapshot)
    if (-not $Snapshot) { return }
    Section "SNAPSHOT - $($Snapshot.Label)"
    Write-Host "ID:        $($Snapshot.SnapshotId)"
    Write-Host "Timestamp: $($Snapshot.Timestamp)"
    Write-Host "IPv4:      $($Snapshot.PublicIP.IPv4)"
    Write-Host "IPv6:      $($Snapshot.PublicIP.IPv6)"
    if ($Snapshot.IPv4Intelligence) {
        Write-Host "ISP:       $($Snapshot.IPv4Intelligence.ISP)  (source: $($Snapshot.IPv4Intelligence.Provider))"
        Write-Host "ASN:       $($Snapshot.IPv4Intelligence.ASN)"
        Write-Host "Type:      $($Snapshot.IPv4Intelligence.ASNType)"
    }
    Write-Host "Interface: $($Snapshot.LocalNetwork.InterfaceAlias)"
    Write-Host "Gateway:   $($Snapshot.LocalNetwork.Gateway)"
    Write-Host "DNS:       $($Snapshot.LocalNetwork.DNS)"
}

# ==================== DIFF SCORING (pure logic - testable) ====================
function Get-NetworkDiffScore {
    <#
    .SYNOPSIS
        Pure comparison function: takes two snapshot-shaped objects and
        returns which fields changed plus a 0-100 confidence score. Contains
        no I/O, so it is directly unit-testable with fake objects.
    #>
    param($Before, $After)

    $ipv4Changed = ($Before.PublicIP.IPv4 -ne $After.PublicIP.IPv4 -and $Before.PublicIP.IPv4 -and $After.PublicIP.IPv4)
    $ipv6Changed = ($Before.PublicIP.IPv6 -ne $After.PublicIP.IPv6)
    $ispChanged = ($Before.IPv4Intelligence.ISP -ne $After.IPv4Intelligence.ISP -and $Before.IPv4Intelligence.ISP -and $After.IPv4Intelligence.ISP)
    $asnChanged = ($Before.IPv4Intelligence.ASN -ne $After.IPv4Intelligence.ASN -and $Before.IPv4Intelligence.ASN -and $After.IPv4Intelligence.ASN)
    $dnsChanged = ($Before.LocalNetwork.DNS -ne $After.LocalNetwork.DNS)
    $ifaceChanged = ($Before.LocalNetwork.InterfaceAlias -ne $After.LocalNetwork.InterfaceAlias)

    $score = 0
    if ($ipv4Changed) { $score += 40 }
    if ($ipv6Changed) { $score += 20 }
    if ($ispChanged) { $score += 15 }
    if ($asnChanged) { $score += 15 }
    if ($dnsChanged) { $score += 5 }
    if ($ifaceChanged) { $score += 5 }

    [PSCustomObject]@{
        IPv4Changed       = $ipv4Changed
        IPv6Changed       = $ipv6Changed
        ISPChanged        = $ispChanged
        ASNChanged        = $asnChanged
        DNSChanged        = $dnsChanged
        InterfaceChanged  = $ifaceChanged
        Score             = $score
    }
}

function Compare-NetworkSnapshots {
    param($Before, $After)
    if (-not $Before -or -not $After) { Status WARN 'Two snapshots are required.'; return }
    Section 'NETWORK IDENTITY COMPARISON'
    $rows = @(
        [PSCustomObject]@{ Field = 'IPv4'; Before = $Before.PublicIP.IPv4; After = $After.PublicIP.IPv4 }
        [PSCustomObject]@{ Field = 'IPv6'; Before = $Before.PublicIP.IPv6; After = $After.PublicIP.IPv6 }
        [PSCustomObject]@{ Field = 'ISP'; Before = $Before.IPv4Intelligence.ISP; After = $After.IPv4Intelligence.ISP }
        [PSCustomObject]@{ Field = 'ASN'; Before = $Before.IPv4Intelligence.ASN; After = $After.IPv4Intelligence.ASN }
        [PSCustomObject]@{ Field = 'ASN Type'; Before = $Before.IPv4Intelligence.ASNType; After = $After.IPv4Intelligence.ASNType }
        [PSCustomObject]@{ Field = 'VPN'; Before = $Before.IPv4Intelligence.VPN; After = $After.IPv4Intelligence.VPN }
        [PSCustomObject]@{ Field = 'Proxy'; Before = $Before.IPv4Intelligence.Proxy; After = $After.IPv4Intelligence.Proxy }
        [PSCustomObject]@{ Field = 'Datacenter'; Before = $Before.IPv4Intelligence.Datacenter; After = $After.IPv4Intelligence.Datacenter }
        [PSCustomObject]@{ Field = 'Interface'; Before = $Before.LocalNetwork.InterfaceAlias; After = $After.LocalNetwork.InterfaceAlias }
        [PSCustomObject]@{ Field = 'Gateway'; Before = $Before.LocalNetwork.Gateway; After = $After.LocalNetwork.Gateway }
        [PSCustomObject]@{ Field = 'DNS'; Before = $Before.LocalNetwork.DNS; After = $After.LocalNetwork.DNS }
    )
    $rows | Format-Table Field, Before, After -AutoSize

    $diff = Get-NetworkDiffScore -Before $Before -After $After

    if ($diff.IPv4Changed) { Status PASS "PUBLIC IPv4 CHANGED: $($Before.PublicIP.IPv4) -> $($After.PublicIP.IPv4)" } else { Status WARN 'Public IPv4 did not change or could not be compared.' }
    if ($diff.IPv6Changed) { Status PASS "PUBLIC IPv6 CHANGED: $($Before.PublicIP.IPv6) -> $($After.PublicIP.IPv6)" } else { Status INFO 'Public IPv6 did not change (or remained unavailable).' }
    if ($diff.ISPChanged) { Status PASS "ISP changed: $($Before.IPv4Intelligence.ISP) -> $($After.IPv4Intelligence.ISP)" }
    if ($diff.ASNChanged) { Status PASS "ASN changed: $($Before.IPv4Intelligence.ASN) -> $($After.IPv4Intelligence.ASN)" }
    if ($diff.DNSChanged) { Status INFO 'DNS configuration changed.' }
    if ($diff.InterfaceChanged) { Status INFO 'Active interface changed.' }

    Write-Host "`nNETWORK DIFFERENCE SCORE: $($diff.Score) / 100" -ForegroundColor Cyan
    if ($diff.Score -ge 75) { Status PASS 'Strong evidence that Internet/network identity changed.' }
    elseif ($diff.Score -ge 40) { Status WARN 'Some network identity characteristics changed; inspect the comparison.' }
    else { Status WARN 'Little evidence of a meaningful public-network identity change.' }

    $compare = [PSCustomObject]@{
        Timestamp        = (Get-Date).ToString('o')
        Before           = $Before
        After            = $After
        IPv4Changed      = $diff.IPv4Changed
        IPv6Changed      = $diff.IPv6Changed
        ISPChanged       = $diff.ISPChanged
        ASNChanged       = $diff.ASNChanged
        DNSChanged       = $diff.DNSChanged
        InterfaceChanged = $diff.InterfaceChanged
        Score            = $diff.Score
    }
    $file = Join-Path $ReportDir ('NETWORK_COMPARE_{0}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try { $compare | ConvertTo-Json -Depth 15 | Set-Content -Path $file -Encoding UTF8 } catch { }
    Status INFO "Comparison saved: $file"

    $htmlFile = Join-Path $ReportDir ('NETWORK_COMPARE_{0}.html' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try { New-HtmlComparisonReport -Rows $rows -Diff $diff -Before $Before -After $After -Path $htmlFile; Status INFO "HTML comparison report: $htmlFile" } catch { }

    return $compare
}

function Select-Snapshot {
    param([string]$Prompt = 'Select snapshot')
    $all = Get-AllSnapshots
    if (-not $all) { Status WARN 'No snapshots exist.'; return $null }
    $items = @($all | Sort-Object Timestamp -Descending | Select-Object -First 50)
    Write-Host ''
    for ($i = 0; $i -lt $items.Count; $i++) {
        $x = $items[$i]
        Write-Host ("{0,2}. {1} | {2} | IPv4={3} | IPv6={4}" -f ($i + 1), $x.Label, $x.Timestamp, $x.PublicIP.IPv4, $x.PublicIP.IPv6)
    }
    $n = Read-Host $Prompt
    $idx = 0
    if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $items.Count) { return $items[$idx - 1] }
    Status WARN 'Invalid snapshot selection.'
    return $null
}

function Show-SnapshotHistory {
    Section 'NETWORK IDENTITY HISTORY'
    $all = Get-AllSnapshots
    if (-not $all) { Status INFO 'No snapshots have been saved.'; return }
    $all | Sort-Object Timestamp -Descending | Select-Object -First 40 |
        ForEach-Object { [PSCustomObject]@{ Label = $_.Label; Timestamp = $_.Timestamp; IPv4 = $_.PublicIP.IPv4; IPv6 = $_.PublicIP.IPv6; ISP = $_.IPv4Intelligence.ISP; ASN = $_.IPv4Intelligence.ASN; Interface = $_.LocalNetwork.InterfaceAlias } } |
        Format-Table -AutoSize
}

# ==================== NETWORK CHANGE WORKFLOW ====================
function Network-IdentityChangeTest {
    Section 'NETWORK IDENTITY CHANGE / VERIFICATION LAB'
    Write-Host 'This test does not magically randomize an ISP-assigned public IP.' -ForegroundColor Yellow
    Write-Host 'It records the current identity, lets you switch to a network you control,'
    Write-Host 'then captures the new identity and proves what actually changed.'
    Write-Host ''
    Write-Host 'Good test options:'
    Write-Host '  - Ethernet -> Wi-Fi'
    Write-Host '  - Home Wi-Fi -> phone hotspot'
    Write-Host '  - Network A -> Network B'
    Write-Host '  - Enable a VPN you are authorized to use'
    Write-Host ''
    $label = Read-Host 'Baseline label (example: Home Ethernet)'
    if ([string]::IsNullOrWhiteSpace($label)) { $label = 'Before Network Switch' }
    $before = New-NetworkSnapshot -Label $label -IncludeTraceRoute
    Write-Host ''
    Write-Host 'NOW SWITCH THE NETWORK.' -ForegroundColor Yellow
    Read-Host 'Press ENTER after the new connection is active' | Out-Null
    Start-Sleep -Seconds 3
    $afterLabel = Read-Host 'New network label (example: Phone Hotspot)'
    if ([string]::IsNullOrWhiteSpace($afterLabel)) { $afterLabel = 'After Network Switch' }
    $after = New-NetworkSnapshot -Label $afterLabel -IncludeTraceRoute
    Compare-NetworkSnapshots $before $after | Out-Null
    Pause-Tool
}

# ==================== HTML REPORTS ====================
function Get-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text.ToString())
}

$script:HtmlStyle = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#111827;color:#e5e7eb;margin:0;padding:24px}
h1{color:#38bdf8;margin-top:0}
h2{color:#38bdf8;border-bottom:1px solid #374151;padding-bottom:6px;margin-top:32px}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #374151}
th{color:#9ca3af;font-weight:600}
.pass{color:#34d399}.warn{color:#fbbf24}.fail{color:#f87171}.info{color:#60a5fa}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.badge-pass{background:#064e3b;color:#34d399}.badge-warn{background:#78350f;color:#fbbf24}
.badge-fail{background:#7f1d1d;color:#f87171}.badge-info{background:#1e3a8a;color:#93c5fd}
.gauge-wrap{background:#1f2937;border-radius:8px;height:28px;width:100%;overflow:hidden;margin:8px 0}
.gauge-fill{height:100%;text-align:right;color:#0b1220;font-weight:700;padding-right:8px;line-height:28px;box-sizing:border-box}
.meta{color:#9ca3af;font-size:13px}
pre{background:#0b1220;color:#d1d5db;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px}
</style>
'@

function New-HtmlReport {
    param($Snapshot, [string]$Path)
    $rows = @()
    if ($Snapshot.IPv4Intelligence) {
        foreach ($k in @('ISP', 'ASN', 'ASNType', 'Country', 'Region', 'City', 'VPN', 'Proxy', 'Tor', 'Datacenter', 'Provider')) {
            $rows += "<tr><td>$k</td><td>$(Get-HtmlEscaped $Snapshot.IPv4Intelligence.$k)</td></tr>"
        }
    }
    $traceHtml = if ($Snapshot.TraceRoute) { (($Snapshot.TraceRoute | ForEach-Object { Get-HtmlEscaped $_ }) -join "`n") } else { '(not captured)' }

    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Network Forensics Report</title>$($script:HtmlStyle)</head>
<body>
<h1>IP Block &amp; Network Forensics Report</h1>
<p class="meta">Generated $(Get-Date) &middot; Tool v$Version &middot; Computer $(Get-HtmlEscaped $env:COMPUTERNAME) &middot; Label: $(Get-HtmlEscaped $Snapshot.Label)</p>

<h2>Public Identity</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Public IPv4</td><td>$(Get-HtmlEscaped $Snapshot.PublicIP.IPv4)</td></tr>
<tr><td>Public IPv6</td><td>$(Get-HtmlEscaped $Snapshot.PublicIP.IPv6)</td></tr>
<tr><td>IPv4 provider consensus</td><td>$($Snapshot.PublicIP.IPv4Consistent)</td></tr>
</table>

<h2>IP Intelligence</h2>
<table><tr><th>Field</th><th>Value</th></tr>$($rows -join "`n")</table>

<h2>Local Network</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Interface</td><td>$(Get-HtmlEscaped $Snapshot.LocalNetwork.InterfaceAlias)</td></tr>
<tr><td>Gateway</td><td>$(Get-HtmlEscaped $Snapshot.LocalNetwork.Gateway)</td></tr>
<tr><td>DNS</td><td>$(Get-HtmlEscaped $Snapshot.LocalNetwork.DNS)</td></tr>
<tr><td>Network Category</td><td>$(Get-HtmlEscaped $Snapshot.LocalNetwork.NetworkCategory)</td></tr>
</table>

<h2>Traceroute</h2>
<pre>$traceHtml</pre>

</body></html>
"@
    (Redact-Secrets -Text $html) | Set-Content -Path $Path -Encoding UTF8
}

function New-HtmlComparisonReport {
    param([array]$Rows, $Diff, $Before, $After, [string]$Path)
    $tableRows = foreach ($r in $Rows) {
        "<tr><td>$(Get-HtmlEscaped $r.Field)</td><td>$(Get-HtmlEscaped $r.Before)</td><td>$(Get-HtmlEscaped $r.After)</td></tr>"
    }
    $gaugeColor = if ($Diff.Score -ge 75) { '#34d399' } elseif ($Diff.Score -ge 40) { '#fbbf24' } else { '#f87171' }
    $verdict = if ($Diff.Score -ge 75) { 'Strong evidence the network identity changed.' }
    elseif ($Diff.Score -ge 40) { 'Some identity characteristics changed - inspect the table below.' }
    else { 'Little evidence of a meaningful identity change.' }

    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Network Identity Comparison</title>$($script:HtmlStyle)</head>
<body>
<h1>Network Identity Comparison</h1>
<p class="meta">Generated $(Get-Date) &middot; Tool v$Version &middot; Before: $(Get-HtmlEscaped $Before.Label) &middot; After: $(Get-HtmlEscaped $After.Label)</p>

<h2>Difference Score</h2>
<div class="gauge-wrap"><div class="gauge-fill" style="width:$($Diff.Score)%;background:$gaugeColor">$($Diff.Score) / 100</div></div>
<p>$(Get-HtmlEscaped $verdict)</p>

<h2>Before / After</h2>
<table><tr><th>Field</th><th>Before</th><th>After</th></tr>$($tableRows -join "`n")</table>

</body></html>
"@
    (Redact-Secrets -Text $html) | Set-Content -Path $Path -Encoding UTF8
}

# ==================== DHCP / REPAIR (ShouldProcess-aware) ====================
function Flush-DNS {
    Section 'SAFE REPAIR - FLUSH DNS'
    ipconfig /flushdns | Out-Host
    Status PASS 'DNS cache flush command completed.'
}

function Renew-DHCP {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Section 'NETWORK REPAIR - DHCP RELEASE / RENEW + PUBLIC IP VERIFICATION'
    if (-not (Is-Admin)) { Status WARN 'Administrator privileges are required.'; return }
    if (-not $PSCmdlet.ShouldProcess('Network adapter', 'Release and renew DHCP lease (temporary disconnect)')) { return }
    $before = New-NetworkSnapshot -Label 'Before DHCP Renew'
    Write-Host ''
    Write-Host 'This temporarily disconnects the network.' -ForegroundColor Yellow
    $ok = Read-Host 'Type RENEW to continue'
    if ($ok -ne 'RENEW') { Write-Host 'Cancelled.'; return }
    ipconfig /release | Out-Host
    Start-Sleep 3
    ipconfig /renew | Out-Host
    Start-Sleep 5
    $after = New-NetworkSnapshot -Label 'After DHCP Renew'
    Compare-NetworkSnapshots $before $after | Out-Null
    Pause-Tool
}

function Reset-NetworkStack {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Section 'DEEP NETWORK RESET'
    if (-not (Is-Admin)) { Status WARN 'Administrator privileges are required.'; return }
    if (-not $PSCmdlet.ShouldProcess('Windows network stack', 'Reset Winsock and IP stack (requires reboot)')) { return }
    Write-Host 'This performs Winsock/IP stack resets and normally requires a reboot.' -ForegroundColor Yellow
    Write-Host 'It does NOT guarantee a new public IP.'
    $confirm = Read-Host 'Type RESET NETWORK to continue'
    if ($confirm -ne 'RESET NETWORK') { Write-Host 'Cancelled.'; return }
    $backup = Join-Path $ReportDir ('Network_Backup_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    @('=== ipconfig /all ===', (ipconfig /all | Out-String), '=== route print ===', (route print | Out-String), '=== netsh interface ipv4 show config ===', (netsh interface ipv4 show config | Out-String)) | Set-Content $backup -Encoding UTF8
    netsh winsock reset | Out-Host
    netsh int ip reset | Out-Host
    ipconfig /flushdns | Out-Host
    Status PASS 'Network stack reset commands completed. Reboot Windows before retesting.'
    Status INFO "Backup saved to $backup"
}

# ==================== FULL FORENSIC REPORT ====================
function Full-Diagnostic {
    $start = Get-Date
    Section "$ToolName v$Version - FULL FORENSIC REPORT"
    Write-Host "Started: $start"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Admin:    $(Is-Admin)"
    $snapshot = New-NetworkSnapshot -Label 'Full Diagnostic' -IncludeTraceRoute
    if (-not $Silent) {
        Show-NetworkState
        Get-RoutingState
        Show-ProxyState
        Show-VPNState
        Show-AvastState
        Test-DNS
        Test-TCP443
        Test-NCSI
        Test-RouteDiagnostics
    }

    $report = Join-Path $ReportDir ('FULL_REPORT_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $snapshotJson = $snapshot | ConvertTo-Json -Depth 15
    $content = @()
    $content += 'IP BLOCK / NETWORK FORENSICS TOOL v4'
    $content += '====================================='
    $content += "Date: $(Get-Date)"
    $content += "Computer: $env:COMPUTERNAME"
    $content += "PowerShell: $($PSVersionTable.PSVersion)"
    $content += "Admin: $(Is-Admin)"
    $content += ''
    $content += '=== NETWORK IDENTITY SNAPSHOT ==='
    $content += $snapshotJson
    $content += ''
    $content += '=== ADAPTERS ==='
    $content += (Get-NetAdapter -IncludeHidden | Format-Table -AutoSize | Out-String)
    $content += '=== IP CONFIG ==='
    $content += (Get-NetIPConfiguration -All | Out-String)
    $content += '=== ROUTES ==='
    $content += (Get-NetRoute | Out-String)
    $content += '=== DNS ==='
    $content += (Get-DnsClientServerAddress | Out-String)
    $content += '=== FIREWALL ==='
    $content += (Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String)
    $content += '=== MTU ==='
    $content += (netsh interface ipv4 show subinterfaces | Out-String)
    try { (Redact-Secrets -Text ($content -join "`n")) | Set-Content -Path $report -Encoding UTF8 } catch { Status WARN "Could not write TXT report: $($_.Exception.Message)" }

    $htmlReport = Join-Path $ReportDir ('FULL_REPORT_{0}.html' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try { New-HtmlReport -Snapshot $snapshot -Path $htmlReport } catch { Status WARN "Could not write HTML report: $($_.Exception.Message)" }

    $elapsed = ((Get-Date) - $start).TotalSeconds
    Section 'DIAGNOSTIC SUMMARY'
    if ($snapshot.PublicIP.IPv4) { Status PASS "External IPv4: $($snapshot.PublicIP.IPv4)" } else { Status FAIL 'External IPv4 unavailable.' }
    if ($snapshot.PublicIP.IPv6) { Status INFO "External IPv6: $($snapshot.PublicIP.IPv6)" } else { Status INFO 'External IPv6 unavailable.' }
    if ($snapshot.IPv4Intelligence) { Status INFO "ISP/ASN: $($snapshot.IPv4Intelligence.ISP) / $($snapshot.IPv4Intelligence.ASN) (source: $($snapshot.IPv4Intelligence.Provider))" }
    Status INFO "JSON snapshot: $SnapshotDir"
    Status INFO "Detailed report: $report"
    Status INFO "HTML report: $htmlReport"
    Status INFO "Elapsed: $([math]::Round($elapsed,1)) seconds"
    return $snapshot
}

function Invoke-SilentRun {
    Write-Log "Unattended run started (-Silent)."
    Full-Diagnostic | Out-Null
    Write-Log "Unattended run complete."
}

# ==================== UI ====================
function Pause-Tool { Read-Host "`nPress ENTER to continue" | Out-Null }
function Open-Folder { Start-Process explorer.exe $Root }

function Edit-SettingsFile {
    Section 'SETTINGS'
    Status INFO "Settings file: $SettingsFile"
    Write-Host 'Edit this JSON file to change IP-intel provider order, enable/disable'
    Write-Host 'providers, set API tokens (ipapi.is / ipinfo.io), cache TTL, and timeouts.'
    Write-Host 'Changes take effect the next time the tool is started.'
    try { Start-Process notepad.exe $SettingsFile } catch { Status WARN 'Could not open Notepad automatically.' }
}

function Show-Banner {
    Clear-Host
    Write-Host '+--------------------------------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host "|              IP BLOCK & NETWORK FORENSICS TOOL v$Version                                    |" -ForegroundColor Cyan
    Write-Host '|              IPv4 - IPv6 - ASN - ISP - DNS - VPN - Proxy - History                     |' -ForegroundColor Cyan
    Write-Host '+--------------------------------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "Computer : $env:COMPUTERNAME"
    Write-Host "Admin    : $(if (Is-Admin) { 'YES' } else { 'NO' })"
    Write-Host "Data     : $Root"
    Write-Host ''
}

function Start-DiagnosticMenu {
    do {
        Show-Banner
        Write-Host '-- IDENTITY --------------------------------------------------------------------'
        Write-Host ' 1  FULL FORENSIC DIAGNOSTIC (TXT + JSON + HTML)'
        Write-Host ' 2  SHOW EXTERNAL IPv4 / IPv6 + CONSENSUS'
        Write-Host ' 3  IP / ASN / ISP REPUTATION INTELLIGENCE (multi-provider)'
        Write-Host ' 4  RDAP / WHOIS LOOKUP'
        Write-Host ''
        Write-Host '-- CHANGE DETECTION --------------------------------------------------------------'
        Write-Host ' 5  NETWORK IDENTITY CHANGE LAB  (BEFORE / AFTER)'
        Write-Host ' 6  SAVE CURRENT NETWORK SNAPSHOT'
        Write-Host ' 7  COMPARE TWO SAVED SNAPSHOTS'
        Write-Host ' 8  SHOW NETWORK IDENTITY HISTORY'
        Write-Host ' 9  SHOW LAST SNAPSHOT'
        Write-Host ''
        Write-Host '-- LOCAL DIAGNOSTICS -------------------------------------------------------------'
        Write-Host '10  DNS DIAGNOSTICS + LEAK/DoH CHECK'
        Write-Host '11  TCP/443 + INTERNET CONNECTIVITY (NCSI)'
        Write-Host '12  VPN / VIRTUAL ADAPTER DETECTION'
        Write-Host '13  PROXY DETECTION'
        Write-Host '14  ROUTE + MTU DIAGNOSTICS'
        Write-Host '15  TRACEROUTE TO TARGET'
        Write-Host '16  AVAST DETECTION'
        Write-Host '17  FORCED IPv4 vs IPv6 EGRESS'
        Write-Host '18  TEST TARGET WEBSITE'
        Write-Host '19  DOWNLOAD SPEED TEST (optional)'
        Write-Host ''
        Write-Host '-- REPAIR (DESTRUCTIVE) ------------------------------------------------------------'
        Write-Host '20  FLUSH DNS'
        Write-Host '21  DHCP RELEASE/RENEW + VERIFY IDENTITY CHANGE'
        Write-Host '22  DEEP NETWORK RESET (REQUIRES REBOOT)'
        Write-Host ''
        Write-Host '-- DATA -----------------------------------------------------------------------'
        Write-Host '23  OPEN REPORT / SNAPSHOT FOLDER'
        Write-Host '24  EDIT SETTINGS (providers, cache TTL, API tokens)'
        Write-Host '25  SHOW PROVIDER HEALTH (this session)'
        Write-Host ' 0  EXIT'
        Write-Host ''
        $choice = Read-Host 'Select'
        switch ($choice) {
            '1' { Full-Diagnostic | Out-Null; Pause-Tool }
            '2' { $p = Get-PublicIdentity; Pause-Tool }
            '3' { $p = Get-PublicIdentity; if ($p.IPv4) { Show-IPIntelligenceAggregate $p.IPv4 } ; if ($p.IPv6) { Show-IPIntelligenceAggregate $p.IPv6 'Public IPv6' }; Pause-Tool }
            '4' { $ip = Read-Host 'IP to look up (blank = current public IPv4)'; if ([string]::IsNullOrWhiteSpace($ip)) { $p = Get-PublicIdentity; $ip = $p.IPv4 }; Show-RdapInfo -IP $ip | Out-Null; Pause-Tool }
            '5' { Network-IdentityChangeTest }
            '6' { $label = Read-Host 'Snapshot label'; if ([string]::IsNullOrWhiteSpace($label)) { $label = 'Manual Snapshot' }; New-NetworkSnapshot -Label $label -Show | Out-Null; Pause-Tool }
            '7' { $b = Select-Snapshot 'Select BEFORE snapshot number'; if ($b) { $a = Select-Snapshot 'Select AFTER snapshot number'; if ($a) { Compare-NetworkSnapshots $b $a | Out-Null } }; Pause-Tool }
            '8' { Show-SnapshotHistory; Pause-Tool }
            '9' { $s = Select-Snapshot 'Select snapshot number'; if ($s) { Show-Snapshot $s }; Pause-Tool }
            '10' { Test-DNS; Pause-Tool }
            '11' { Test-TCP443; Test-NCSI; Pause-Tool }
            '12' { Show-VPNState; Pause-Tool }
            '13' { Show-ProxyState; Pause-Tool }
            '14' { Get-RoutingState; Test-RouteDiagnostics; Pause-Tool }
            '15' { Show-TraceRoute | Out-Null; Pause-Tool }
            '16' { Show-AvastState; Pause-Tool }
            '17' { Test-IPv4IPv6 | Out-Null; Pause-Tool }
            '18' { Test-TargetSite | Out-Null; Pause-Tool }
            '19' { Test-DownloadSpeed | Out-Null; Pause-Tool }
            '20' { Flush-DNS; Pause-Tool }
            '21' { Renew-DHCP }
            '22' { Reset-NetworkStack; Pause-Tool }
            '23' { Open-Folder; Pause-Tool }
            '24' { Edit-SettingsFile; Pause-Tool }
            '25' { Show-ProviderHealth; Pause-Tool }
            '0' { Write-Host "`nExiting." -ForegroundColor Cyan }
            default { Write-Host 'Invalid selection.' -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice -ne '0')
}

# ==================== ENTRY POINT ====================
# Dot-source safe: the interactive menu (and any side effects) only start
# when this file is executed directly - not when dot-sourced (e.g. by Pester
# to import functions for unit testing).
if ($MyInvocation.InvocationName -ne '.') {
    if ($Silent -or $ExportOnly) {
        Invoke-SilentRun
    }
    else {
        Start-DiagnosticMenu
    }
}
