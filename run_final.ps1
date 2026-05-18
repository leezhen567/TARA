function global:trae-sandbox {
    param([string]$cmd)
    Invoke-Expression $cmd
}

$pythonPaths = @(
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe",
    "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe",
    "python",
    "py"
)

$pythonExe = $null
foreach ($p in $pythonPaths) {
    try {
        if ($p -eq "python" -or $p -eq "py") {
            $result = & $p --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $pythonExe = $p
                break
            }
        } elseif (Test-Path $p) {
            $pythonExe = $p
            break
        }
    } catch {}
}

if ($pythonExe) {
    Write-Host "Using Python: $pythonExe"
    & $pythonExe "D:\Jupyter profile\汽车信息安全风险评估\notebooks\add_topo_interface.py"
} else {
    Write-Host "Python not found"
}