# Print paper/revisions/out/*.html to PDF with headless Chrome (Windows).
$out = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "out"
$tmp = Join-Path $env:TEMP "ddos_revrep"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $tmp | Out-Null
foreach ($f in Get-ChildItem $out -Filter *.html) {
    Copy-Item $f.FullName $tmp -Force
    $src = Join-Path $tmp $f.Name
    $pdf = Join-Path $tmp ($f.BaseName + ".pdf")
    $url = "file:///" + ($src -replace '\\', '/')
    Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -ArgumentList @(
        "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--user-data-dir=$tmp\prof",
        "--print-to-pdf=$pdf", $url) -Wait -WindowStyle Hidden
    Copy-Item $pdf (Join-Path $out ($f.BaseName + ".pdf")) -Force
    "$($f.BaseName).pdf"
}
