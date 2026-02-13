# Deploy Silverline-API per rsync/scp
# Auf Windows: Nutzt WSL oder Git Bash falls vorhanden

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Silverline Deploy"

$sshUser = "y12er_it-pin"
$sshHost = "y12er.ftp.infomaniak.com"
$remoteDir = "/home/clients/cd018176a9efb9d6ecf8a0ae8be5e651/sites/mysilverline.it-pin.ch/wp-content/plugins/silverline-api"

$localDir = $PSScriptRoot + "\"
$dryRun = $args -contains "--dry"

Write-Host "Deploy: $localDir -> ${sshUser}@${sshHost}:${remoteDir}" -ForegroundColor Cyan
if ($dryRun) { Write-Host "(Dry-Run)" -ForegroundColor Yellow }
Write-Host ""

# 1. Versuch: WSL + rsync
$wsl = Get-Command wsl -ErrorAction SilentlyContinue
if ($wsl) {
    Write-Host "Starte via WSL..." -ForegroundColor Gray
    # deploy.sh zu LF konvertieren (CRLF verursacht Bash-Fehler)
    $shPath = Join-Path $localDir "deploy.sh"
    if (Test-Path $shPath) {
        $content = [System.IO.File]::ReadAllText($shPath) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText($shPath, $content, [System.Text.UTF8Encoding]::new($false))
    }
    # Windows C:\Users\... zu WSL /mnt/c/Users/...
    $drive = $localDir.Substring(0, 1).ToLower()
    $rest = $localDir.Substring(2).Replace('\', '/')
    $wslPath = "/mnt/$drive$rest"
    
    Push-Location $localDir
    try {
        wsl bash -c "cd '$wslPath' && bash deploy.sh $(if ($dryRun) { '--dry' })"
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nDeploy fertig." -ForegroundColor Green
        exit 0
    }
}

# 2. Versuch: Git Bash
$gitBash = "C:\Program Files\Git\bin\bash.exe"
if (Test-Path $gitBash) {
    Write-Host "Starte via Git Bash..." -ForegroundColor Gray
    $bashArgs = @("-c", "cd '$($localDir.Replace('\', '/'))' && ./deploy.sh $(if ($dryRun) { '--dry' })")
    & $gitBash $bashArgs
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nDeploy fertig." -ForegroundColor Green
        exit 0
    }
}

# 3. Fallback: scp (ohne rsync - kopiert alles)
$scp = Get-Command scp -ErrorAction SilentlyContinue
if ($scp) {
    Write-Host "rsync nicht gefunden. Nutze scp (kopiert alle Dateien)..." -ForegroundColor Yellow
    Write-Host "Wichtig: .git, debug.log etc. werden mitkopiert." -ForegroundColor Yellow
    $files = @(
        "silverline-api.php",
        "silverline-auth.php",
        "readme.txt",
        "OPS.md",
        "deploy.sh",
        "deploy.ps1"
    )
    foreach ($f in $files) {
        $fp = Join-Path $localDir $f
        if (Test-Path $fp) {
            Write-Host "  Kopiere $f..." -ForegroundColor Gray
            if (-not $dryRun) {
                scp $fp "${sshUser}@${sshHost}:${remoteDir}/"
            }
        }
    }
    Write-Host "`nDeploy fertig (scp)." -ForegroundColor Green
    exit 0
}

Write-Host "Fehler: Weder WSL noch Git Bash noch scp gefunden." -ForegroundColor Red
Write-Host ""
Write-Host "Optionen:" -ForegroundColor Yellow
Write-Host "  1. WSL installieren: wsl --install (empfohlen)" 
Write-Host "  2. Git für Windows: https://git-scm.com"
Write-Host "  3. OpenSSH aktivieren: Einstellungen > Apps > Optionale Features > OpenSSH"
exit 1
