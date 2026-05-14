# End-to-end test + diagnostic for Burnwall.
#
# Builds the release binary, spawns a mock Anthropic upstream and the proxy
# pointed at it (sandboxed under $env:TEMP\burnwall-e2e-<random>), then runs:
#
#   1. Forwarding           - proxy logs a successful request and cost
#   2. Security blocking    - `cat ~/.ssh/id_rsa` returns 403 + audit row
#   3. Budget enforcement   - exceeded budget returns 429
#   4. Claude Code routing  - does `claude -p` actually go through the proxy?
#
# Exit code 0 if everything passes, 1 otherwise.

[CmdletBinding()]
param(
    [int]$ProxyPort = 4100,
    [int]$MockPort  = 9999,
    [switch]$SkipClaude,
    [switch]$SkipBuild,
    [switch]$KeepSandbox
)

$ErrorActionPreference = "Stop"

# ---------------------------------- helpers ----------------------------------

$script:Failures = 0

function Section($msg) { Write-Host ""; Write-Host "== $msg ==" -ForegroundColor Yellow }
function Pass($msg)    { Write-Host "  PASS  $msg" -ForegroundColor Green }
function Fail($msg)    { Write-Host "  FAIL  $msg" -ForegroundColor Red; $script:Failures++ }
function Info($msg)    { Write-Host "  ..    $msg" -ForegroundColor DarkGray }
function Note($msg)    { Write-Host "  NOTE  $msg" -ForegroundColor Cyan }

function Wait-ForPort {
    param([int]$Port, [int]$TimeoutSec = 15, [string]$Label = "port")
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect("127.0.0.1", $Port)
            $c.Close()
            return
        }
        catch {
            Start-Sleep -Milliseconds 150
        }
    }
    throw ("timed out waiting for {0} on :{1}" -f $Label, $Port)
}

function Invoke-Proxy {
    param(
        [string]$Path,
        [string]$Body = "",
        [hashtable]$Headers = @{},
        [string]$Method = "POST"
    )
    $url = "http://127.0.0.1:$ProxyPort$Path"
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $Method
    $req.ContentType = "application/json"
    foreach ($k in $Headers.Keys) { $req.Headers[$k] = $Headers[$k] }
    if ($Body) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    try {
        $resp = $req.GetResponse()
        $status = [int]$resp.StatusCode
    }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $status = [int]$resp.StatusCode
    }
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $text = $reader.ReadToEnd()
    $reader.Close()
    $resp.Close()
    return @{ Status = $status; Body = $text }
}

function Get-Status {
    $json = & $script:Bin status --json 2>$null | Out-String
    return ($json | ConvertFrom-Json)
}

function Reset-Sandbox {
    if (Test-Path $script:DataDir) {
        Remove-Item -Recurse -Force $script:DataDir -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $script:DataDir | Out-Null
}

# ---------------------------------- setup ----------------------------------

$repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
$script:DataDir = Join-Path $env:TEMP "burnwall-e2e-$(Get-Random)"
$script:Bin = Join-Path $repoRoot "target\release\burnwall.exe"
$env:BURNWALL_DATA_DIR = $script:DataDir

Section "Setup"
Info "Repo:    $repoRoot"
Info "Sandbox: $script:DataDir"

if (-not $SkipBuild) {
    Info "Building release binary (multi-minute the first time)..."
    Push-Location $repoRoot
    try {
        & cargo build --release --quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "cargo build --release"; exit 1 }
        Pass "cargo build --release"
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path $script:Bin)) {
    Fail "binary not found at $script:Bin (run without -SkipBuild)"
    exit 1
}
Pass "binary present: $script:Bin"

Reset-Sandbox
Pass "fresh sandbox at $script:DataDir"

# ---------------------------- spawn mock + proxy ----------------------------

$mockScript     = Join-Path $PSScriptRoot "mock-anthropic.ps1"
$mockOutLog     = Join-Path $script:DataDir "mock.out.log"
$mockErrLog     = Join-Path $script:DataDir "mock.err.log"
$burnwallOutLog = Join-Path $script:DataDir "burnwall.out.log"
$burnwallErrLog = Join-Path $script:DataDir "burnwall.err.log"

function Start-BurnwallProxy {
    $script:burnwallProc = Start-Process $script:Bin `
        -ArgumentList "start", `
            "--port", "$ProxyPort", `
            "--upstream-anthropic", "http://127.0.0.1:$MockPort", `
            "--upstream-openai",    "http://127.0.0.1:$MockPort" `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $burnwallOutLog -RedirectStandardError $burnwallErrLog
    Wait-ForPort -Port $ProxyPort -Label "burnwall"
}

function Stop-BurnwallProxy {
    if ($script:burnwallProc -and -not $script:burnwallProc.HasExited) {
        Stop-Process -Id $script:burnwallProc.Id -Force -ErrorAction SilentlyContinue
        # Give the OS a moment to release the listening port and the SQLite handle.
        Start-Sleep -Milliseconds 600
    }
}

Section "Starting mock upstream on :$MockPort"
$mockProc = Start-Process powershell `
    -ArgumentList "-NoLogo", "-NoProfile", "-File", $mockScript, "-Port", "$MockPort" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $mockOutLog -RedirectStandardError $mockErrLog
Wait-ForPort -Port $MockPort -Label "mock"
Pass "mock listening"

Section "Starting Burnwall proxy on :$ProxyPort"
Start-BurnwallProxy
Pass "burnwall listening"

# ---------------------------------- tests ----------------------------------

try {
    Section "Test 1: safe request is forwarded, parsed, cached pricing applied, savings reported"
    $body = '{"model":"claude-haiku-4-5","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}'
    $r = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $body -Headers @{ "x-api-key" = "fake" }
    if ($r.Status -eq 200) { Pass "200 OK" } else { Fail ("expected 200, got {0}" -f $r.Status) }
    Start-Sleep -Milliseconds 300
    $status = Get-Status
    if ($status.total_requests -eq 1) {
        Pass "1 request recorded"
    } else {
        Fail ("total_requests={0}, expected 1" -f $status.total_requests)
    }
    $row = $status.breakdown[0]
    if ($status.breakdown.Count -ge 1 -and $row.model -eq "claude-haiku-4-5") {
        Pass "model recorded as claude-haiku-4-5"
    } else {
        Fail ("breakdown missing claude-haiku-4-5: {0}" -f ($status.breakdown | ConvertTo-Json -Compress))
    }

    # Mock returns: input=1000 (non-cached), cache_creation=200, cache_read=5000, output=100.
    # Verify each token bucket lands in storage as-is:
    if ($row.input_tokens -eq 1000) { Pass "input_tokens stored as 1000" } else { Fail ("input_tokens={0}" -f $row.input_tokens) }
    if ($row.cache_creation_tokens -eq 200) { Pass "cache_creation_tokens stored as 200" } else { Fail ("cache_creation_tokens={0}" -f $row.cache_creation_tokens) }
    if ($row.cache_read_tokens -eq 5000) { Pass "cache_read_tokens stored as 5000" } else { Fail ("cache_read_tokens={0}" -f $row.cache_read_tokens) }
    if ($row.output_tokens -eq 100) { Pass "output_tokens stored as 100" } else { Fail ("output_tokens={0}" -f $row.output_tokens) }

    # haiku rates per SPEC: input 1.00, cache_write 1.25, cache_read 0.10, output 5.00 (USD/MTok)
    #   input        1000 * 1.00  / 1e6 = 0.001000
    #   cache_write   200 * 1.25  / 1e6 = 0.000250
    #   cache_read   5000 * 0.10  / 1e6 = 0.000500
    #   output        100 * 5.00  / 1e6 = 0.000500
    #   total                            = 0.002250
    $expectedCost = 0.00225
    if ([Math]::Abs($status.total_cost_usd - $expectedCost) -lt 1e-7) {
        Pass ("cost = {0:N6} USD (expected {1:N6} -- haiku rates with cache)" -f $status.total_cost_usd, $expectedCost)
    } else {
        Fail ("cost = {0} USD, expected {1}" -f $status.total_cost_usd, $expectedCost)
    }

    # Cache hit rate: 5000 / (1000 + 200 + 5000) = 0.806...
    $expectedHit = 5000.0 / 6200.0
    if ([Math]::Abs($row.cache_hit_rate - $expectedHit) -lt 1e-6) {
        Pass ("cache_hit_rate = {0:P1} (expected {1:P1})" -f $row.cache_hit_rate, $expectedHit)
    } else {
        Fail ("cache_hit_rate = {0}, expected {1}" -f $row.cache_hit_rate, $expectedHit)
    }

    # Without caching, all 6200 prompt tokens would have been billed at the
    # input rate: 6200 * 1.00 / 1e6 + 100 * 5.00 / 1e6 = 0.0067.
    # Savings = 0.0067 - 0.00225 = 0.00445.
    $expectedNoCache = 0.0067
    $expectedSavings = $expectedNoCache - $expectedCost
    if ([Math]::Abs($status.cost_without_cache_usd - $expectedNoCache) -lt 1e-6) {
        Pass ("cost_without_cache = {0:N6} USD (expected {1:N6})" -f $status.cost_without_cache_usd, $expectedNoCache)
    } else {
        Fail ("cost_without_cache = {0}, expected {1}" -f $status.cost_without_cache_usd, $expectedNoCache)
    }
    if ([Math]::Abs($status.cache_savings_usd - $expectedSavings) -lt 1e-6) {
        Pass ("cache_savings = {0:N6} USD (expected {1:N6})" -f $status.cache_savings_usd, $expectedSavings)
    } else {
        Fail ("cache_savings = {0}, expected {1}" -f $status.cache_savings_usd, $expectedSavings)
    }

    Reset-Sandbox
    Section "Test 2: security violation returns 403 and writes audit rows"
    $blockedBody = '{"model":"claude-haiku-4-5","messages":[{"role":"assistant","content":[{"type":"tool_use","name":"bash","input":{"command":"cat ~/.ssh/id_rsa"}}]}]}'
    $r = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $blockedBody
    if ($r.Status -eq 403) { Pass "403 Forbidden" } else { Fail ("expected 403, got {0}" -f $r.Status) }
    if ($r.Body -like '*security_blocked*') {
        Pass "body has security_blocked error type"
    } else {
        Fail ("body missing security_blocked: {0}" -f $r.Body)
    }
    if ($r.Body -like '*~/.ssh*') {
        Pass "body mentions the matched rule"
    } else {
        Fail "body missing rule detail"
    }
    Start-Sleep -Milliseconds 300
    $status = Get-Status
    if ($status.security_events -eq 1) {
        Pass "1 security event written"
    } else {
        Fail ("security_events={0}" -f $status.security_events)
    }
    if ($status.blocked_requests -eq 1) {
        Pass "1 blocked request row written"
    } else {
        Fail ("blocked_requests={0}" -f $status.blocked_requests)
    }

    Section "Test 3: budget enforcement returns 429"
    Info "stopping burnwall, dropping budget to 0.0001 USD, restarting"
    Stop-BurnwallProxy
    Reset-Sandbox
    & $script:Bin config set budget.daily 0.0001 | Out-Null
    Start-BurnwallProxy

    Info "first request - should succeed and push us over the limit"
    $r1 = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $body -Headers @{ "x-api-key" = "fake" }
    if ($r1.Status -eq 200) { Pass "first request 200 OK" } else { Fail ("first request: {0}" -f $r1.Status) }

    Info "second request - budget should now block"
    Start-Sleep -Milliseconds 400
    $r2 = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $body -Headers @{ "x-api-key" = "fake" }
    if ($r2.Status -eq 429) { Pass "429 Too Many Requests" } else { Fail ("expected 429, got {0}" -f $r2.Status) }
    if ($r2.Body -like '*budget_exceeded*') {
        Pass "body has budget_exceeded error type"
    } else {
        Fail "body missing budget_exceeded"
    }

    Section "Test 4: loop detection blocks repeated identical requests"
    Info "stopping burnwall, configuring loop_detection.max_identical_requests=3, restarting"
    Stop-BurnwallProxy
    Reset-Sandbox
    # Tighten the loop threshold and disable cost-spiral so this test is deterministic.
    & $script:Bin config set loop_detection.max_identical_requests 3 | Out-Null
    & $script:Bin config set loop_detection.window_seconds 60 | Out-Null
    & $script:Bin config set loop_detection.max_cost_per_window 0.0 | Out-Null
    & $script:Bin config set budget.daily 50.0 | Out-Null
    Start-BurnwallProxy

    # Send the SAME body 3 times. First 2 should pass, 3rd should be loop-blocked.
    Info "sending 2 identical requests (should pass)"
    $loopBody = '{"model":"claude-haiku-4-5","max_tokens":50,"messages":[{"role":"user","content":"identical"}]}'
    for ($i = 1; $i -le 2; $i++) {
        $resp = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $loopBody -Headers @{ "x-api-key" = "fake" }
        if ($resp.Status -eq 200) {
            Pass ("identical request {0}/2 passed" -f $i)
        } else {
            Fail ("identical request {0}/2 returned {1}" -f $i, $resp.Status)
        }
    }

    Info "sending 3rd identical request (should be loop-blocked)"
    $loopResp = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $loopBody -Headers @{ "x-api-key" = "fake" }
    if ($loopResp.Status -eq 429) {
        Pass "3rd identical request returned 429"
    } else {
        Fail ("expected 429, got {0}" -f $loopResp.Status)
    }
    if ($loopResp.Body -like '*loop_detected*') {
        Pass "body has loop_detected error type"
    } else {
        Fail ("body missing loop_detected: {0}" -f $loopResp.Body)
    }
    if ($loopResp.Body -like '*identical*') {
        Pass "body explains the loop count"
    } else {
        Fail "body missing loop count detail"
    }

    # Distinct body should still pass even within the same window.
    Info "sending a DIFFERENT body (should pass)"
    $distinctBody = '{"model":"claude-haiku-4-5","max_tokens":50,"messages":[{"role":"user","content":"distinct"}]}'
    $distinctResp = Invoke-Proxy -Path "/anthropic/v1/messages" -Body $distinctBody -Headers @{ "x-api-key" = "fake" }
    if ($distinctResp.Status -eq 200) {
        Pass "distinct body passed (loop counter is per-hash)"
    } else {
        Fail ("distinct body returned {0}, expected 200" -f $distinctResp.Status)
    }

    # -------------- Claude Code diagnostic --------------
    # Bring budget back up + relax loop detection so the diagnostic isn't immediately blocked.
    Stop-BurnwallProxy
    Reset-Sandbox
    & $script:Bin config set budget.daily 50.0 | Out-Null
    & $script:Bin config set loop_detection.max_identical_requests 5 | Out-Null
    Start-BurnwallProxy

    Section "Diagnostic: does Claude Code route through Burnwall?"
    $haveClaude = $null -ne (Get-Command claude -ErrorAction SilentlyContinue)
    if ($SkipClaude) {
        Note "skipping (-SkipClaude)"
    }
    elseif (-not $haveClaude) {
        Note "no 'claude' on PATH - skipping diagnostic"
    }
    else {
        function Probe-ClaudeRouting {
            param([hashtable]$EnvVars)
            $before = (Get-Status).total_requests
            $envBackup = @{}
            foreach ($k in $EnvVars.Keys) {
                $envBackup[$k] = [Environment]::GetEnvironmentVariable($k, "Process")
                [Environment]::SetEnvironmentVariable($k, $EnvVars[$k], "Process")
            }
            try {
                $job = Start-Job -ScriptBlock {
                    try { & claude -p "say hi" 2>&1 } catch { "ERROR: $_" }
                }
                $done = Wait-Job $job -Timeout 30
                if (-not $done) {
                    Stop-Job $job -ErrorAction SilentlyContinue
                    Note "claude command did not finish within 30s (fine for routing diagnosis)"
                }
                Receive-Job $job -ErrorAction SilentlyContinue | Out-Null
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            }
            finally {
                foreach ($k in $envBackup.Keys) {
                    if ($null -eq $envBackup[$k]) {
                        [Environment]::SetEnvironmentVariable($k, $null, "Process")
                    } else {
                        [Environment]::SetEnvironmentVariable($k, $envBackup[$k], "Process")
                    }
                }
            }
            Start-Sleep -Milliseconds 400
            $after = (Get-Status).total_requests
            return $after -gt $before
        }

        Info "attempt 1: setting ANTHROPIC_BASE_URL"
        $routed = Probe-ClaudeRouting -EnvVars @{
            "ANTHROPIC_BASE_URL" = "http://127.0.0.1:$ProxyPort/anthropic"
        }
        if ($routed) {
            Pass "Claude Code honors ANTHROPIC_BASE_URL"
        }
        else {
            Note "Claude Code did not route via ANTHROPIC_BASE_URL"
            Info "attempt 2: also setting ANTHROPIC_API_URL"
            Reset-Sandbox
            $routed = Probe-ClaudeRouting -EnvVars @{
                "ANTHROPIC_BASE_URL" = "http://127.0.0.1:$ProxyPort/anthropic"
                "ANTHROPIC_API_URL"  = "http://127.0.0.1:$ProxyPort/anthropic"
            }
            if ($routed) {
                Pass "Claude Code honors ANTHROPIC_API_URL"
                Note "use ANTHROPIC_API_URL=... when starting Claude Code in your shell"
            }
            else {
                Fail "Claude Code did not route via either env var"
                Note "your Claude Code build/auth mode is bypassing the env vars"
                Note "likely cause: OAuth/login session - see README workaround (set ANTHROPIC_API_KEY)"
                Note "Burnwall itself is working - tests 1-3 above prove it"
            }
        }
    }
}
finally {
    Section "Cleanup"
    if ($script:burnwallProc -and -not $script:burnwallProc.HasExited) {
        Stop-Process -Id $script:burnwallProc.Id -Force -ErrorAction SilentlyContinue
        Info ("stopped burnwall (pid {0})" -f $script:burnwallProc.Id)
    }
    if ($mockProc -and -not $mockProc.HasExited) {
        Stop-Process -Id $mockProc.Id -Force -ErrorAction SilentlyContinue
        Info ("stopped mock (pid {0})" -f $mockProc.Id)
    }
    if ($KeepSandbox) {
        Note ("sandbox kept at {0}" -f $script:DataDir)
        Note ("burnwall stdout: {0}" -f $burnwallOutLog)
        Note ("burnwall stderr: {0}" -f $burnwallErrLog)
        Note ("mock stdout:     {0}" -f $mockOutLog)
        Note ("mock stderr:     {0}" -f $mockErrLog)
    }
    else {
        Remove-Item -Recurse -Force $script:DataDir -ErrorAction SilentlyContinue
        Info "removed sandbox"
    }
    Remove-Item Env:\BURNWALL_DATA_DIR -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host ("{0} check(s) failed." -f $script:Failures) -ForegroundColor Red
    exit 1
}
