param([string]$Python = "python")
$ErrorActionPreference = "Stop"

function Invoke-Python {
    & $Python @args
    if ($LASTEXITCODE -ne 0) { throw "Python command failed with exit code $LASTEXITCODE" }
}

Push-Location $PSScriptRoot
try {
    Invoke-Python -m pip install -r requirements-build.txt
    Invoke-Python -m pip check
    Invoke-Python -m unittest discover -s tests -v
    Invoke-Python launcher.py --smoke-test
    Invoke-Python -m PyInstaller --noconfirm --clean --onefile --windowed --name HuaweiNetworkDoctor launcher.py
    $process = Start-Process -FilePath (Resolve-Path "dist\HuaweiNetworkDoctor.exe") -ArgumentList "--smoke-test" -PassThru
    if (-not $process.WaitForExit(120000)) {
        Stop-Process -Id $process.Id -Force
        throw "Packaged smoke test timed out."
    }
    if ($process.ExitCode -ne 0) { throw "Packaged smoke test failed: $($process.ExitCode)" }
} finally {
    Pop-Location
}
