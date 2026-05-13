# Mock Anthropic Messages API endpoint for Burnwall e2e testing.
#
# Listens on the requested port (default 9999) and answers every POST with
# a structurally-valid Anthropic Messages response so the proxy's response
# parser can extract `model`/`usage` and the cost calculator can price it.

[CmdletBinding()]
param(
    [int]$Port = 9999
)

$ErrorActionPreference = "Stop"

# Realistic numbers that exercise the caching code paths:
#   - input_tokens 1000  (non-cached prompt)
#   - cache_creation_input_tokens 200  (cache write — Anthropic 1.25x rate)
#   - cache_read_input_tokens 5000  (cache hit — Anthropic 0.10x rate)
#   - output_tokens 100
$response = @{
    id          = "msg_mock_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    type        = "message"
    role        = "assistant"
    content     = @(@{ type = "text"; text = "ok" })
    model       = "claude-haiku-4-5"
    stop_reason = "end_turn"
    usage       = @{
        input_tokens                 = 1000
        cache_creation_input_tokens  = 200
        cache_read_input_tokens      = 5000
        output_tokens                = 100
    }
} | ConvertTo-Json -Compress

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()

Write-Host "[mock] listening on http://127.0.0.1:$Port/"

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        try {
            # Drain the request body (avoids Anthropic-SDK clients hanging).
            $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream)
            [void]$reader.ReadToEnd()

            $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            $ctx.Response.StatusCode = 200
            $ctx.Response.ContentType = "application/json"
            $ctx.Response.ContentLength64 = $buffer.Length
            $ctx.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        catch {
            $ctx.Response.StatusCode = 500
        }
        finally {
            $ctx.Response.Close()
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
