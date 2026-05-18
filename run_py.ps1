$ErrorActionPreference = "Stop"
$pythonExe = "python"
try {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
} catch {}

if (-not $pythonExe) {
    $paths = @(
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe",
        "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $pythonExe = $p
            break
        }
    }
}

& $pythonExe "D:\Jupyter profile\汽车信息安全风险评估\notebooks\add_topo_interface.py"