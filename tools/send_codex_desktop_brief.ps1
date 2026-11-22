#requires -Version 7.4
param([Parameter(Mandatory)][guid]$ThreadId, [switch]$ActiveOnly, [switch]$DiscoverOnly)

$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$message = [Console]::In.ReadToEnd()
if (!$DiscoverOnly -and ([string]::IsNullOrWhiteSpace($message) -or $message.Length -gt 20000)) {
    throw 'Expected a briefing of 1 to 20000 characters on stdin.'
}

$thread = $ThreadId.ToString()
$client = 'initializing-client'
$pipe = [IO.Pipes.NamedPipeClientStream]::new(
    '.', 'codex-ipc', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)

function Send-Frame($value, [Threading.CancellationToken]$token) {
    $json = ConvertTo-Json -InputObject $value -Depth 20 -Compress
    $payload = [Text.Encoding]::UTF8.GetBytes($json)
    $length = [BitConverter]::GetBytes([uint32]$payload.Length)
    [void]$pipe.WriteAsync($length, 0, $length.Length, $token).GetAwaiter().GetResult()
    [void]$pipe.WriteAsync($payload, 0, $payload.Length, $token).GetAwaiter().GetResult()
    [void]$pipe.FlushAsync($token).GetAwaiter().GetResult()
}

function Read-Frame([Threading.CancellationToken]$token) {
    $length = [byte[]]::new(4)
    [void]$pipe.ReadExactlyAsync([Memory[byte]]::new($length), $token).GetAwaiter().GetResult()
    $size = [BitConverter]::ToUInt32($length, 0)
    if ($size -eq 0 -or $size -gt 4MB) { throw 'Invalid Codex IPC frame length.' }
    $payload = [byte[]]::new($size)
    [void]$pipe.ReadExactlyAsync([Memory[byte]]::new($payload), $token).GetAwaiter().GetResult()
    [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json -AsHashtable
}

function Invoke-OwnerRequest($method, $parameters, $owner, [int]$version = 1, [int]$timeout = 8000) {
    $deadline = [Threading.CancellationTokenSource]::new($timeout + 2500)
    try {
        $id = [guid]::NewGuid().ToString()
        $request = @{
            type = 'request'; requestId = $id; sourceClientId = $client
            method = $method; version = $version; params = $parameters; timeoutMs = $timeout
        }
        if ($owner) { $request.targetClientId = $owner }
        Send-Frame $request $deadline.Token
        while ($true) {
            $frame = Read-Frame $deadline.Token
            switch ($frame.type) {
                'client-discovery-request' {
                    Send-Frame @{type='client-discovery-response'; requestId=$frame.requestId
                        response=@{canHandle=$false}} $deadline.Token
                }
                'request' {
                    Send-Frame @{type='response'; requestId=$frame.requestId
                        resultType='error'; error='no-handler-for-request'} $deadline.Token
                }
                'response' { if ($frame.requestId -eq $id) { return $frame } }
            }
        }
    } finally { $deadline.Dispose() }
}

try {
    try { $pipe.Connect(3000) } catch {
        throw 'The current Codex desktop instance is not listening on the local codex-ipc pipe.'
    }
    $hello = Invoke-OwnerRequest 'initialize' @{clientType='eu4-brief-dispatch'}
    if ($hello.resultType -ne 'success' -or !$hello.result.clientId) {
        throw 'Codex desktop could not initialize the briefing connection.'
    }
    $client = $hello.result.clientId
    $lookup = Invoke-OwnerRequest 'thread-owner-discovery' @{hostId='local'; conversationId=$thread}
    $owner = $lookup.handledByClientId
    if ($lookup.resultType -ne 'success' -or !$owner) {
        throw "Codex desktop has no local owner for $thread. Open that conversation in the app."
    }
    if ($DiscoverOnly) {
        @{thread_id=$thread; method='discover'} | ConvertTo-Json -Compress
        return
    }

    $messageId = [guid]::NewGuid().ToString()
    $items = @(@{type='text'; text=$message; text_elements=@()})
    $restore = @{id=$messageId; text=$message; context=@{
        prompt=$message; workspaceRoots=@(); imageAttachments=@(); fileAttachments=@()
        addedFiles=@(); commentAttachments=@(); responseTextAnnotations=@(); attachmentOrder=@()
    }}
    $mode = 'steer'
    $delivery = Invoke-OwnerRequest 'thread-follower-steer-turn' @{
        conversationId=$thread; input=$items; clientUserMessageId=$messageId
        restoreMessage=$restore; additionalContext=@{}
    } $owner
    if (!$ActiveOnly -and $delivery.resultType -eq 'error' -and [string]$delivery.error -match
        'no active turn to steer|active turn already ended|^Cannot steer conversation \S+ because it is not active\.?$') {
        $mode = 'start'
        $delivery = Invoke-OwnerRequest 'thread-follower-start-turn' @{
            conversationId=$thread
            turnStart=@{request=@{threadId=$thread; input=$items; clientUserMessageId=$messageId}
                context=@{restoreMessage=$restore; inheritThreadSettings=$true}}
        } $owner 2 45000
    }
    if ($delivery.resultType -ne 'success') { throw "Codex desktop rejected ${mode}: $($delivery.error)" }
    @{thread_id=$thread; message_id=$messageId; method=$mode} | ConvertTo-Json -Compress
} finally { $pipe.Dispose() }
