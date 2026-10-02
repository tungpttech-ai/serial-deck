# Authenticode-sign one file. The certificate path and password come from the
# environment of a release-only CI step (SIGN_CERT_PATH, SIGN_CERT_PASSWORD),
# so neither appears in a command line or log.
param([Parameter(Mandatory = $true)][string]$File)
$ErrorActionPreference = "Stop"
if (-not $env:SIGN_CERT_PATH -or -not $env:SIGN_CERT_PASSWORD) { throw "signing credentials are not set" }
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found" }
& $signtool.FullName sign /f $env:SIGN_CERT_PATH /p $env:SIGN_CERT_PASSWORD /fd sha256 `
    /tr http://timestamp.digicert.com /td sha256 $File
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $signtool.FullName verify /pa $File
exit $LASTEXITCODE
