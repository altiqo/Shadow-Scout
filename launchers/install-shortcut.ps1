# Создаёт ярлык «Shadow Scout» на рабочем столе Windows, запускающий ShadowScout.bat.
# Запуск: правый клик → «Выполнить с помощью PowerShell» (или: powershell -ExecutionPolicy Bypass -File install-shortcut.ps1)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$bat = Join-Path $root "launchers\ShadowScout.bat"
$desktop = [Environment]::GetFolderPath("Desktop")
$lnk = Join-Path $desktop "Shadow Scout.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnk)
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/c `"$bat`""
$shortcut.WorkingDirectory = $root
$shortcut.WindowStyle = 1
$shortcut.IconLocation = "%SystemRoot%\System32\shell32.dll,44"
$shortcut.Description = "Shadow Scout — поиск VPS под VPN вне радара РКН"
$shortcut.Save()
Write-Host "Ярлык создан: $lnk"
Write-Host "Совет: в свойствах ярлыка выберите шрифт Cascadia Mono / Consolas и включите «Использовать устаревшую консоль = выкл.» для корректных символов."
