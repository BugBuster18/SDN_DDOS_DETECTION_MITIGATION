# Render report/v2/Results_Report_v2.html to PDF with headless Chrome (Windows).
param([string]$Out = "Results_Report_v2.pdf")
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$tmp = Join-Path $env:TEMP "ddos_report_render"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item -Recurse -Force (Join-Path $src "Results_Report_v2.html") $tmp
Copy-Item -Recurse -Force (Join-Path $src "figures") $tmp
$url = "file:///" + (($tmp -replace '\\', '/') + "/Results_Report_v2.html")
$p = Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -ArgumentList @(
    "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--user-data-dir=$tmp\prof",
    "--print-to-pdf=$tmp\out.pdf", $url) -Wait -PassThru -WindowStyle Hidden
Copy-Item -Force "$tmp\out.pdf" (Join-Path $src $Out)
"exit $($p.ExitCode) -> $(Join-Path $src $Out)"
