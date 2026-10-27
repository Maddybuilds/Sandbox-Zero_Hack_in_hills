# Judges: double-click START_JUDGES.cmd for browser auto-connection and the access key.
# Optional Ollama/Qwen setup and the recorded-result caution are in JUDGE_GUIDE.md.
param([switch]$Containers,[switch]$Check,[int]$Port=8000)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if ($Check) { python doctor.py; exit $LASTEXITCODE }
if ($Containers) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install Docker Desktop with WSL 2 before using -Containers. Local mode needs only Python.' }
    $szExisting = if (Test-Path -LiteralPath '.env') { Get-Content -LiteralPath '.env' -Raw } else { '' }
    $szSecrets = @(foreach ($szName in @('SZ_ACCESS_CODE','SZ_RED_TOKEN','SZ_BLUE_TOKEN','SZ_TARGET_TOKEN')) {
        if ($szExisting -notmatch ('(?m)^\s*' + $szName + '\s*=')) {
            $szBytes = New-Object byte[] 32
            $szRng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $szRng.GetBytes($szBytes) } finally { $szRng.Dispose() }
            $szName + '=' + [Convert]::ToBase64String($szBytes)
        }
    })
    if ($szSecrets.Count -gt 0) { Add-Content -LiteralPath '.env' -Value ("`n" + ($szSecrets -join "`n")) -Encoding ascii }
    Write-Output 'Local container credentials are in .env. Keep that file private. Open localhost:8000 after services become healthy.'
    docker compose up --build
    exit $LASTEXITCODE
}
$szPreviousModel = $env:SZ_MODEL
$szPreviousMode = $env:SZ_MODE
try {
    $env:SZ_MODEL = ''
    $env:SZ_MODE = 'local'
    python server.py --no-env --port $Port
} finally {
    $env:SZ_MODEL = $szPreviousModel
    $env:SZ_MODE = $szPreviousMode
}
