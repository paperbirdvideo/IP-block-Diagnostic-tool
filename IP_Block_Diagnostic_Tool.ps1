#requires -version 5.1
<#
.SYNOPSIS
    Public IP / VPN / Avast / Network Diagnostic & Repair Tool

.DESCRIPTION
    Windows PowerShell utility for diagnosing websites that report an IP block.
    It checks:
      - Public IPv4 / IPv6
      - Local/private IP addresses
      - Default gateway
      - DNS servers and proxy settings
      - Network adapters and VPN-related adapters
      - Windows VPN profiles where available
      - Avast products/processes/services
      - Public Internet connectivity
      - A user-supplied website
      - Whether the public IP changes after DHCP release/renew
    It can also safely flush DNS and renew DHCP.

    It DOES NOT automatically disable antivirus/security software or bypass
    website security controls.

.NOTES
    Run as Administrator for the repair functions.
#>

$ErrorActionPreference = 'SilentlyContinue'
$Script:LogDir = Join-Path $env:USERPROFILE "Desktop\IP_Block_Diagnostics"
$null = New-Item -ItemType Directory -Path $Script:LogDir -Force
$Script:LogFile = Join-Path $Script:LogDir ("IP_Diagnostic_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $Script:LogFile -Value $line
    Write-Host $line -ForegroundColor $Color
}

function Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PublicIP {
    $result = [ordered]@{
        IPv4 = $null
        IPv6 = $null
        Source = $null
    }

    try {
        $result.IPv4 = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10 -UseBasicParsing).ToString().Trim()
        $result.Source = "ipify"
    } catch {}

    try {
        $result.IPv6 = (Invoke-RestMethod -Uri "https://api6.ipify.org" -TimeoutSec 10 -UseBasicParsing).ToString().Trim()
    } catch {}

    # Fallback for IPv4
    if (-not $result.IPv4) {
        try {
            $result.IPv4 = (Invoke-RestMethod -Uri "https://ipv4.icanhazip.com" -TimeoutSec 10 -UseBasicParsing).ToString().Trim()
            $result.Source = "icanhazip"
        } catch {}
    }

    [PSCustomObject]$result
}

function Get-NetworkSnapshot {
    $public = Get-PublicIP
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, ifIndex

    $configs = Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq "Up"} |
        Select-Object InterfaceAlias, InterfaceIndex,
            @{N="IPv4";E={($_.IPv4Address.IPAddress -join ", ")}},
            @{N="IPv6";E={($_.IPv6Address.IPAddress -join ", ")}},
            @{N="Gateway";E={($_.IPv4DefaultGateway.NextHop -join ", ")}},
            @{N="DNS";E={($_.DNSServer.ServerAddresses -join ", ")}}

    [PSCustomObject]@{
        Timestamp = Get-Date
        PublicIPv4 = $public.IPv4
        PublicIPv6 = $public.IPv6
        PublicIPSource = $public.Source
        LocalIPv4 = ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {$_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*"} |
            Select-Object -ExpandProperty IPAddress) -join ", ")
        LocalIPv6 = ((Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
            Where-Object {$_.IPAddress -notlike "::1" -and $_.IPAddress -notlike "fe80::*"} |
            Select-Object -ExpandProperty IPAddress) -join ", ")
        Adapters = $adapters
        Configurations = $configs
    }
}

function Show-PublicIP {
    Section "PUBLIC INTERNET IP"
    $p = Get-PublicIP

    if ($p.IPv4) {
        Write-Host "Public IPv4: " -NoNewline
        Write-Host $p.IPv4 -ForegroundColor Green
    } else {
        Write-Host "Public IPv4: NOT DETECTED" -ForegroundColor Yellow
    }

    if ($p.IPv6) {
        Write-Host "Public IPv6: " -NoNewline
        Write-Host $p.IPv6 -ForegroundColor Green
    } else {
        Write-Host "Public IPv6: none detected" -ForegroundColor DarkGray
    }

    Write-Host "Source: $($p.Source)"
    return $p
}

function Show-LocalNetwork {
    Section "LOCAL NETWORK / ROUTING / DNS"

    Write-Host "`nActive adapters:"
    Get-NetAdapter | Where-Object Status -eq "Up" |
        Format-Table Name, InterfaceDescription, LinkSpeed, MacAddress -AutoSize

    Write-Host "`nIP configuration:"
    Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq "Up"} |
        Format-Table InterfaceAlias,
            @{N="IPv4";E={($_.IPv4Address.IPAddress -join ",")}},
            @{N="Gateway";E={($_.IPv4DefaultGateway.NextHop -join ",")}},
            @{N="DNS";E={($_.DNSServer.ServerAddresses -join ",")}} -AutoSize

    Write-Host "`nDefault route:"
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Format-Table ifIndex, NextHop, RouteMetric, InterfaceAlias -AutoSize

    Write-Host "`nWindows proxy:"
    netsh winhttp show proxy
}

function Show-VPN {
    Section "VPN / TUNNEL / VIRTUAL ADAPTER DETECTION"

    $patterns = 'VPN|TAP|TUN|WireGuard|Wintun|OpenVPN|Nord|ExpressVPN|Surfshark|Mullvad|Proton|Cloudflare|WARP|Cisco AnyConnect|GlobalProtect|Fortinet|Hamachi|ZeroTier|Tailscale|Avast SecureLine|SecureLine'

    $adapters = Get-NetAdapter -IncludeHidden |
        Where-Object {
            $_.Name -match $patterns -or $_.InterfaceDescription -match $patterns
        } |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, ifIndex

    if ($adapters) {
        $adapters | Format-Table -AutoSize
    } else {
        Write-Host "No obvious VPN/virtual adapter detected." -ForegroundColor Green
    }

    try {
        $vpn = Get-VpnConnection -AllUserConnection -ErrorAction Stop
        if ($vpn) {
            Write-Host "`nWindows VPN profiles:"
            $vpn | Select-Object Name, ServerAddress, ConnectionStatus, TunnelType, AuthenticationMethod |
                Format-Table -AutoSize
        } else {
            Write-Host "`nNo Windows VPN profiles found."
        }
    } catch {
        Write-Host "`nWindows VPN profile query unavailable or requires elevated permissions." -ForegroundColor Yellow
    }
}

function Show-Avast {
    Section "AVAST DETECTION"

    $avastPaths = @(
        "$env:ProgramFiles\Avast Software",
        "${env:ProgramFiles(x86)}\Avast Software",
        "$env:ProgramData\Avast Software"
    ) | Where-Object {$_ -and (Test-Path $_)}

    if ($avastPaths) {
        Write-Host "Avast installation/data detected:"
        $avastPaths | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
    } else {
        Write-Host "No standard Avast installation path detected." -ForegroundColor DarkGray
    }

    $avastProcesses = Get-Process -ErrorAction SilentlyContinue |
        Where-Object {$_.ProcessName -match 'avast|secureline|wsc_proxy'} |
        Select-Object ProcessName, Id, Path

    if ($avastProcesses) {
        Write-Host "`nAvast-related processes:"
        $avastProcesses | Format-Table -AutoSize
    } else {
        Write-Host "`nNo obvious Avast processes detected."
    }

    $avastServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {$_.Name -match 'avast|secureline' -or $_.DisplayName -match 'Avast|SecureLine'} |
        Select-Object Name, DisplayName, State, StartMode

    if ($avastServices) {
        Write-Host "`nAvast-related services:"
        $avastServices | Format-Table -AutoSize
    }

    Write-Host ""
    Write-Host "IMPORTANT: This tool does not disable Avast automatically." -ForegroundColor Yellow
    Write-Host "If a controlled Avast test is needed, temporarily disable Web Shield/Web Guard"
    Write-Host "from Avast's own interface, test the site once, then re-enable protection."
}

function Test-Internet {
    Section "INTERNET CONNECTIVITY"

    $targets = @(
        @{Name="Cloudflare"; Host="1.1.1.1"},
        @{Name="Google DNS"; Host="8.8.8.8"},
        @{Name="Cloudflare Website"; Host="https://www.cloudflare.com"},
        @{Name="Google Website"; Host="https://www.google.com"}
    )

    foreach ($t in $targets) {
        $ok = $false
        $detail = ""

        if ($t.Host -like "http*") {
            try {
                $r = Invoke-WebRequest -Uri $t.Host -TimeoutSec 10 -UseBasicParsing
                $ok = ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500)
                $detail = "HTTP $($r.StatusCode)"
            } catch {
                $detail = $_.Exception.Message
            }
        } else {
            $ok = Test-Connection -ComputerName $t.Host -Count 1 -Quiet -ErrorAction SilentlyContinue
            $detail = if ($ok) {"Ping OK"} else {"Ping failed"}
        }

        if ($ok) {
            Write-Host ("{0,-24} OK    {1}" -f $t.Name, $detail) -ForegroundColor Green
        } else {
            Write-Host ("{0,-24} FAIL  {1}" -f $t.Name, $detail) -ForegroundColor Yellow
        }
    }
}

function Test-Website {
    Section "WEBSITE TEST"

    $url = Read-Host "Enter the website URL to test (example: https://example.com)"
    if ([string]::IsNullOrWhiteSpace($url)) {
        Write-Host "No URL supplied." -ForegroundColor Yellow
        return
    }

    if ($url -notmatch '^https?://') {
        $url = "https://" + $url
    }

    Write-Host "Testing: $url"

    try {
        $r = Invoke-WebRequest -Uri $url -TimeoutSec 20 -UseBasicParsing
        Write-Host "HTTP status: $($r.StatusCode)" -ForegroundColor Green
        Write-Host "Status description: $($r.StatusDescription)"
        Write-Host "Final URL: $($r.BaseResponse.ResponseUri)"
        Write-Host "Server: $($r.Headers['Server'])"
    } catch {
        Write-Host "Request failed:" -ForegroundColor Yellow
        Write-Host $_.Exception.Message
    }

    Write-Host "`nNOTE: A successful HTTP request does not prove that ticket/login/purchase"
    Write-Host "functionality is allowed. A site can block specific actions after page load."
}

function Flush-DNS {
    Section "FLUSH DNS CACHE"
    try {
        ipconfig /flushdns | ForEach-Object {Write-Host $_}
        Write-Log "DNS cache flushed." Green
    } catch {
        Write-Log "DNS flush failed: $($_.Exception.Message)" Yellow
    }
}

function Renew-DHCP {
    Section "DHCP RELEASE / RENEW"
    if (-not (Test-Admin)) {
        Write-Host "Administrator privileges are required for DHCP release/renew." -ForegroundColor Yellow
        Write-Host "Restart this script as Administrator and try again."
        return
    }

    Write-Host "This may temporarily disconnect the PC from the network." -ForegroundColor Yellow
    $confirm = Read-Host "Type RENEW to continue"
    if ($confirm -ne "RENEW") {
        Write-Host "Cancelled."
        return
    }

    $before = Get-PublicIP
    Write-Host "Public IPv4 before: $($before.IPv4)"

    ipconfig /release | ForEach-Object {Write-Host $_}
    Start-Sleep -Seconds 3
    ipconfig /renew | ForEach-Object {Write-Host $_}
    Start-Sleep -Seconds 5

    $after = Get-PublicIP
    Write-Host "`nPublic IPv4 after:  $($after.IPv4)"

    if ($before.IPv4 -and $after.IPv4 -and $before.IPv4 -ne $after.IPv4) {
        Write-Host "SUCCESS: Public IPv4 changed." -ForegroundColor Green
    } elseif ($before.IPv4 -eq $after.IPv4) {
        Write-Host "Public IPv4 did not change." -ForegroundColor Yellow
        Write-Host "Your ISP/router may be keeping the same public address."
    } else {
        Write-Host "Could not reliably compare public IPs." -ForegroundColor Yellow
    }
}

function Full-Diagnostic {
    Section "FULL DIAGNOSTIC"
    Write-Host "This report is being saved to:"
    Write-Host $Script:LogFile -ForegroundColor Green

    $snap = Get-NetworkSnapshot

    Write-Host "`nPublic IPv4: $($snap.PublicIPv4)" -ForegroundColor Green
    Write-Host "Public IPv6: $($snap.PublicIPv6)"
    Write-Host "Local IPv4:  $($snap.LocalIPv4)"
    Write-Host "Local IPv6:  $($snap.LocalIPv6)"

    Show-LocalNetwork
    Show-VPN
    Show-Avast
    Test-Internet

    Write-Host "`nPotential diagnosis:" -ForegroundColor Cyan

    if ($snap.PublicIPv4) {
        Write-Host "1. The website will normally see your public IPv4: $($snap.PublicIPv4)"
    }

    if ($snap.LocalIPv4 -match '192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.') {
        Write-Host "2. Your local/private IP is separate from the public IP. Changing it normally will NOT remove an Internet IP block."
    }

    $vpnAdapters = Get-NetAdapter -IncludeHidden |
        Where-Object {$_.Name -match $patterns -or $_.InterfaceDescription -match $patterns}
    if ($vpnAdapters) {
        Write-Host "3. A VPN/virtual adapter appears to be present. Verify whether a VPN is active."
    } else {
        Write-Host "3. No obvious VPN adapter was detected."
    }

    Write-Host "4. If the website works on a phone hotspot but not home Wi-Fi, that strongly points toward the home public IP/network."
    Write-Host "5. If the website fails even on a different network, the block may be account/device/browser related rather than your home IP."

    # Save structured report
    $report = Join-Path $Script:LogDir ("Network_Report_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    @"
IP BLOCK DIAGNOSTIC REPORT
==========================
Date: $(Get-Date)

PUBLIC IPv4: $($snap.PublicIPv4)
PUBLIC IPv6: $($snap.PublicIPv6)
LOCAL IPv4:  $($snap.LocalIPv4)
LOCAL IPv6:  $($snap.LocalIPv6)
IP SOURCE:   $($snap.PublicIPSource)

ACTIVE ADAPTERS
---------------
$($snap.Adapters | Out-String)

IP CONFIGURATION
----------------
$($snap.Configurations | Out-String)

WINDOWS PROXY
-------------
$(netsh winhttp show proxy | Out-String)
"@ | Set-Content -Path $report -Encoding UTF8

    Write-Host "`nReport saved to:" -ForegroundColor Green
    Write-Host $report
}

function Compare-IP {
    Section "PUBLIC IP COMPARISON"

    $p = Get-PublicIP
    Write-Host "Current public IPv4: $($p.IPv4)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Now you can switch networks (for example, connect to a phone hotspot)."
    Write-Host "Press ENTER when the PC is connected to the other network."
    Read-Host

    Start-Sleep -Seconds 2
    $q = Get-PublicIP

    Write-Host "New public IPv4:     $($q.IPv4)" -ForegroundColor Green

    if ($p.IPv4 -and $q.IPv4 -and $p.IPv4 -ne $q.IPv4) {
        Write-Host "`nRESULT: The public IP changed." -ForegroundColor Green
        Write-Host "This is exactly the kind of change that can bypass an IP-specific block."
    } elseif ($p.IPv4 -eq $q.IPv4) {
        Write-Host "`nRESULT: The public IP did not change." -ForegroundColor Yellow
    } else {
        Write-Host "`nRESULT: Unable to compare the addresses." -ForegroundColor Yellow
    }
}

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "     WINDOWS IP BLOCK / VPN / AVAST DIAGNOSTIC TOOL" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Log folder: $Script:LogDir"
    if (Test-Admin) {
        Write-Host "Administrator: YES" -ForegroundColor Green
    } else {
        Write-Host "Administrator: NO (diagnostics work; repair functions may need Admin)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "1. Full diagnostic + report"
    Write-Host "2. Show public IP"
    Write-Host "3. Compare IP after switching networks"
    Write-Host "4. Test a specific website"
    Write-Host "5. Detect VPN / virtual adapters"
    Write-Host "6. Detect Avast"
    Write-Host "7. Test Internet connectivity"
    Write-Host "8. Flush DNS cache"
    Write-Host "9. DHCP release/renew + check whether public IP changed"
    Write-Host "10. Open diagnostic folder"
    Write-Host "0. Exit"
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1" { Full-Diagnostic; Pause }
        "2" { Show-PublicIP; Pause }
        "3" { Compare-IP; Pause }
        "4" { Test-Website; Pause }
        "5" { Show-VPN; Pause }
        "6" { Show-Avast; Pause }
        "7" { Test-Internet; Pause }
        "8" { Flush-DNS; Pause }
        "9" { Renew-DHCP; Pause }
        "10" {
            Start-Process explorer.exe $Script:LogDir
            Pause
        }
        "0" { Write-Host "Done." }
        default { Write-Host "Invalid choice." -ForegroundColor Yellow; Start-Sleep 1 }
    }
} while ($choice -ne "0")
