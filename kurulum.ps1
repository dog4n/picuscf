<#
Picus x Cloudflare WAF Platformu - Windows kurulum betigi.
Kullanim (yonetici PowerShell, kurulum dosyalarinin oldugu klasorde):
  powershell -ExecutionPolicy Bypass -File .\kurulum.ps1
  powershell -ExecutionPolicy Bypass -File .\kurulum.ps1 -Hedef "D:\PicusCF" -Port 9999 -Nssm "C:\Araclar\nssm.exe"
Parametreler:
  -Hedef     Kurulum klasoru (varsayilan C:\PicusCF). Betik dosyalari buraya kopyalar; veri (data) ve .env korunur.
  -Port      Dinlenecek port (varsayilan 9999)
  -Python    python.exe yolu (bos: PATH'te / py launcher ile bulunur, 3.10+ gerekir)
  -Nssm      nssm.exe yolu (bos: PATH'te ya da hedef klasorde aranir). Yoksa servis kurulmaz, elle calistirma anlatilir.
  -Name      Windows servis adi (varsayilan PicusCF)
  -Proxy     Kurumsal proxy (ornek http://proxy.local:8080) - pip ve uygulama icin
  -Disaridan Uygulamayi sunucu disindan erisime acar (HOST=0.0.0.0 + guvenlik duvari kurali). Varsayilan: sadece localhost.
#>
param(
  [string]$Hedef = "C:\PicusCF",
  [int]$Port = 9999,
  [string]$Python = "",
  [string]$Nssm = "",
  [string]$Name = "PicusCF",
  [string]$Proxy = "",
  [switch]$Disaridan
)
$ErrorActionPreference = "Stop"
function Adim($n, $m) { Write-Host "`n[$n] $m" -ForegroundColor Cyan }
function Bilgi($m) { Write-Host "    $m" }
function Uyari($m) { Write-Host "    UYARI: $m" -ForegroundColor Yellow }

$Kaynak = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in "app.py", "run.py", "requirements.txt", "templates", "static") {
  if (-not (Test-Path (Join-Path $Kaynak $f))) { throw "Kurulum dosyalari eksik ($f). Zip'i tamamen acip betigi o klasorden calistirin." }
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Betigi yonetici olarak calistirin (servis ve guvenlik duvari icin gerekli)." }

Adim 1 "Dosyalar kopyalaniyor: $Kaynak -> $Hedef"
New-Item -ItemType Directory -Force -Path $Hedef | Out-Null
if ((Resolve-Path $Kaynak).Path.TrimEnd('\') -ne (Resolve-Path $Hedef).Path.TrimEnd('\')) {
  robocopy $Kaynak $Hedef /E /NFL /NDL /NJH /NJS /NP /XD data __pycache__ .venv /XF .env *.pyc | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "Kopyalama hatasi (robocopy $LASTEXITCODE)." }
}
Bilgi "Tamam."

Adim 2 "Python bulunuyor"
if (-not $Python) {
  $cands = @()
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) { try { $cands += (& py -3 -c "import sys;print(sys.executable)") } catch {} }
  $p = Get-Command python -ErrorAction SilentlyContinue
  if ($p) { $cands += $p.Source }
  foreach ($c in $cands) {
    if ($c -and (Test-Path $c) -and ($c -notlike "*WindowsApps*")) { $Python = $c; break }
  }
}
if (-not $Python -or -not (Test-Path $Python)) { throw "Python 3.10+ bulunamadi. python.org'dan kurun ya da -Python ile yol verin." }
$ver = & $Python -c "import sys;print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]"3.10") { throw "Python $ver bulundu; 3.10 ya da ustu gerekli." }
Bilgi "Python $ver : $Python"

Adim 3 "Sanal ortam ve paketler"
$venv = Join-Path $Hedef ".venv"
$vpy = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $vpy)) { try { & $Python -m venv $venv 2>$null | Out-Null } catch {} }
if (-not (Test-Path $vpy)) {
  Uyari "Sanal ortam olusturulamadi (gomulu/embeddable Python olabilir); paketler dogrudan bu Python'a kurulacak."
  $vpy = $Python
}
$pipArgs = @("-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", (Join-Path $Hedef "requirements.txt"))
if ($Proxy) { $pipArgs += @("--proxy", $Proxy) }
& $vpy @pipArgs
if ($LASTEXITCODE -ne 0) { throw "pip install basarisiz. Internet/proxy erisimini kontrol edin (-Proxy)." }
Bilgi "Paketler kuruldu."

Adim 4 "Ayar dosyasi (.env)"
$envf = Join-Path $Hedef ".env"
if (-not (Test-Path $envf)) { Copy-Item (Join-Path $Hedef ".env.example") $envf }
function Set-EnvVal($k, $v) {
  $lines = @(Get-Content $envf -Encoding UTF8 | Where-Object { $_ -notmatch "^\s*#?\s*$k\s*=" })
  $lines += "$k=$v"
  Set-Content -Path $envf -Value $lines -Encoding UTF8
}
function Get-EnvVal($k) {
  $l = Get-Content $envf -Encoding UTF8 | Where-Object { $_ -match "^\s*$k\s*=" } | Select-Object -Last 1
  if ($l) { return ($l -split "=", 2)[1].Trim() } else { return "" }
}
Set-EnvVal "PORT" $Port
Set-EnvVal "HOST" ($(if ($Disaridan) { "0.0.0.0" } else { "127.0.0.1" }))
if ($Proxy) { Set-EnvVal "HTTPS_PROXY" $Proxy }
if (-not (Get-EnvVal "CF_API_TOKEN")) {
  Uyari "CF_API_TOKEN bos. .env Not Defteri'nde aciliyor: token'lari '=' isaretinden sonra yapistirin, kaydedip kapatin."
  Start-Process notepad.exe $envf -Wait
}
# .env sadece SYSTEM ve Administrators tarafindan okunabilsin
icacls $envf /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
Bilgi ".env hazir (erisim: SYSTEM + Administrators)."

Adim 5 "Port kontrolu ($Port)"
$busy = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($busy -and -not $svc) { throw "Port $Port kullanimda. Baska port secin (-Port)." }
Bilgi "Uygun."

Adim 6 "Windows servisi"
if (-not $Nssm) {
  $n = Get-Command nssm -ErrorAction SilentlyContinue
  if ($n) { $Nssm = $n.Source } elseif (Test-Path (Join-Path $Hedef "nssm.exe")) { $Nssm = Join-Path $Hedef "nssm.exe" }
}
if ($Nssm -and (Test-Path $Nssm)) {
  if ($svc) { & $Nssm stop $Name | Out-Null } else { & $Nssm install $Name $vpy "run.py" | Out-Null }
  & $Nssm set $Name Application $vpy | Out-Null
  & $Nssm set $Name AppParameters "run.py" | Out-Null
  & $Nssm set $Name AppDirectory $Hedef | Out-Null
  & $Nssm set $Name DisplayName "Picus x Cloudflare WAF Platformu" | Out-Null
  & $Nssm set $Name Start SERVICE_AUTO_START | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $Hedef "data\logs") | Out-Null
  & $Nssm set $Name AppStdout (Join-Path $Hedef "data\logs\servis.log") | Out-Null
  & $Nssm set $Name AppStderr (Join-Path $Hedef "data\logs\servis.log") | Out-Null
  & $Nssm set $Name AppRotateFiles 1 | Out-Null
  & $Nssm set $Name AppRotateBytes 10485760 | Out-Null
  & $Nssm start $Name | Out-Null
  Bilgi "Servis '$Name' calisiyor."
} else {
  Uyari "nssm.exe bulunamadi; servis kurulmadi. nssm.cc'den indirip -Nssm ile tekrar calistirin."
  Uyari "Simdilik elle calistirmak icin: cd $Hedef ; .\.venv\Scripts\python.exe run.py"
}

Adim 7 "Guvenlik duvari"
Get-NetFirewallRule -DisplayName "$Name *" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Disaridan) {
  New-NetFirewallRule -DisplayName "$Name $Port" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
  Bilgi "Port $Port disaridan erisime acildi."
} else {
  Bilgi "Sadece localhost: uygulama yalnizca bu sunucunun icinden acilir."
}

Adim 8 "Saglik kontrolu"
Start-Sleep -Seconds 4
try {
  $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/saglik" -TimeoutSec 15
  Bilgi "Uygulama cevap veriyor ($($r.StatusCode))."
} catch { Uyari "Uygulama henuz cevap vermedi. Log: $Hedef\data\logs\servis.log" }
Push-Location $Hedef
try { & $vpy manage.py baglanti-test } finally { Pop-Location }

Write-Host "`nKurulum tamam. Adres: http://localhost:$Port  (ilk acilista yonetici hesabi olusturulur)" -ForegroundColor Green
